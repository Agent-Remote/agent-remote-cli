mod api;
mod auth;
mod bridge_release;
mod broker_credentials;
mod cli;
mod config;
mod dependencies;
mod device;
mod doctor;
mod ego_browser;
mod identifiers;
mod local_state;
mod managed_releases;
mod mutagen;
mod node_install_state;
mod node_release;
mod platform;
mod port_forward;
mod secrets;
mod ssh;
mod terminal;
mod wireguard;
mod workspace;

use std::ffi::OsStr;
use std::fs::File;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use clap::Parser;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command as AsyncCommand;
use tokio::time::sleep;

use crate::api::{
    ApiClient, AuthToken, BindingStatusData, CreateDeveloperCredentialProfileRequest,
    CreateSyncSessionRequest, CreateToolAccountRequest, CreateWorkspaceRequest,
    DeveloperCredentialGitHubCli, DeveloperCredentialGitIdentity, DeveloperCredentialProfileData,
    DeveloperCredentialSsh, GitSyncPolicy, NodeData, NodeJoinCodeRevokeState,
    RegisterDeviceRequest, SyncSessionData, ToolAccountConfigImportFile,
    ToolAccountConfigImportRequest, ToolAccountData, WorkspaceData,
};
use crate::auth::{
    clear_device_token_refresh, has_device_token, load_device_token, store_device_token,
};
use crate::broker_credentials::delete_broker_credential_if_matches;
use crate::cli::{
    AccountCommand, AccountDefaultCommand, Cli, Command, CredentialsCommand, DepsCommand,
    DeviceCommand, DeviceRevokeArgs, DeviceRotateTokenArgs, DeviceUninstallArgs, LoginMethod,
    NodeCommand, NodeInstallArgs, SshCommand, SyncCommand, WireGuardCommand, VERSION,
};
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManager;
use crate::doctor::Doctor;
use crate::local_state::{LocalDevice, LocalState, LocalSyncSession, LocalWorkspace};
use crate::node_install_state::{NodeInstallExchangeState, NodeInstallStage};
use crate::node_release::MANAGED_NODE_VERSION;
use crate::secrets::{device_token_key, user_token_key, wireguard_private_key_key, SecretStore};
use crate::terminal::{Details, Table};
use agent_remote_cli::identifiers::{resolve_id, short_id};

const CONFIG_IMPORT_MAX_FILE_BYTES: u64 = 1024 * 1024;
const CONFIG_IMPORT_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
const CONFIG_IMPORT_WAIT_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    terminal::configure(cli.color);
    let json = cli.json;
    if let Err(error) = run(cli).await {
        if json {
            print_json_error(&error);
        } else {
            eprintln!("{} {error:#}", terminal::failure("ERROR"));
        }
        std::process::exit(1);
    }
}

fn print_json_error(error: &anyhow::Error) {
    println!("{}", json_error_value(error));
}

fn json_error_value(error: &anyhow::Error) -> serde_json::Value {
    let rendered = format!("{error:#}");
    let error_code = field_token(&rendered, "error_code").unwrap_or("control_plane_error");
    let phase = field_token(&rendered, "state").unwrap_or("unknown");
    let admission = field_token(&rendered, "admission").unwrap_or("unknown");
    let next_action = field_token(&rendered, "next_action").unwrap_or("repair");
    let next_command = field_between(&rendered, "next_command=", " stale=")
        .map(|value| value.split_once(" (").map_or(value, |(command, _)| command))
        .filter(|value| value.starts_with("agent-remote ") && value.is_ascii());
    let stale =
        field_token(&rendered, "stale").is_some_and(|value| value.eq_ignore_ascii_case("true"));
    // An error proves only explicit facts; all unobserved local state remains unknown.
    let definitely_uninstalled = matches!(phase, "uninstalled" | "absent");
    let execution_closed = matches!(admission, "closed" | "server_execution_closed");
    let installed = definitely_uninstalled.then_some(false);
    let enabled = definitely_uninstalled.then_some(false);
    let registered: Option<bool> = None;
    let available = (definitely_uninstalled || execution_closed).then_some(false);
    let connected = (definitely_uninstalled || execution_closed).then_some(false);
    let admission_value = serde_json::json!({
        "enrollment": if admission == "server_enrollment_closed" { "denied" } else { "unknown_or_denied" },
        "server_execution": if admission == "server_execution_closed" { "denied" } else { "unknown_or_denied" },
        "binding": "unknown",
        "local": if admission == "closed" { "closed" } else { "unknown" },
        "reason": if error_code == "login_required" || error_code == "server_profile_required" {
            "login"
        } else if admission.starts_with("server_") {
            "server"
        } else {
            "local"
        },
        "overall": admission,
    });
    serde_json::json!({
        "error_code": error_code,
        "state": {
            "phase": phase,
            "installed": installed,
            "enabled": enabled,
            "registered": registered,
            "available": available,
            "connected": connected,
        },
        "capability": {
            "configured_enabled": serde_json::Value::Null,
            "effective_enabled": serde_json::Value::Null,
            "node_execution_allowed": serde_json::Value::Null,
        },
        "admission": admission_value,
        "stale": stale,
        "next_action": next_action,
        "next_command": next_command,
    })
}

fn field_token<'a>(rendered: &'a str, field: &str) -> Option<&'a str> {
    rendered
        .split_whitespace()
        .find_map(|value| value.strip_prefix(&format!("{field}=")))
        .filter(|value| !value.is_empty())
}

fn field_between<'a>(rendered: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let value = rendered.split_once(start)?.1;
    let value = value.split_once(end).map_or(value, |(prefix, _)| prefix);
    (!value.is_empty()).then_some(value)
}

async fn run(cli: Cli) -> Result<()> {
    let json = cli.json;
    let paths = AppPaths::new(cli.home)?;
    match cli.command {
        Command::Init(args) => init(paths, args).await,
        Command::Login(args) => login(paths, args).await,
        Command::Logout(args) => logout(paths, args.revoke_remote).await,
        Command::Status(args) => status(paths, args.online).await,
        Command::Doctor(args) => Doctor::new(paths).run(args.fix).await,
        Command::Deps(DepsCommand::Status(args)) => deps_status(paths, args.fix),
        Command::Wireguard(WireGuardCommand::Config(args)) => wireguard_config(paths, args).await,
        Command::Wireguard(WireGuardCommand::Check(args)) => wireguard_action(paths, "check", args),
        Command::Wireguard(WireGuardCommand::Status) => wireguard::show_status(&paths),
        Command::Wireguard(WireGuardCommand::Up(args)) => wireguard_action(paths, "up", args),
        Command::Wireguard(WireGuardCommand::Down(args)) => wireguard_action(paths, "down", args),
        Command::Ssh(SshCommand::Check(args)) => ssh_check(paths, args).await,
        Command::Forward(args) => port_forward::run(&paths, &args, None).await,
        Command::Sync(SyncCommand::Ensure(args)) => sync_ensure(paths, args).await,
        Command::Sync(SyncCommand::Status(args)) => sync_status(paths, args).await,
        Command::Sync(SyncCommand::Pause(args)) => sync_action(paths, "pause", args).await,
        Command::Sync(SyncCommand::Resume(args)) => sync_action(paths, "resume", args).await,
        Command::Sync(SyncCommand::Resolve(args)) => sync_action(paths, "resolve", args).await,
        Command::Sync(SyncCommand::Reset(args)) => sync_action(paths, "reset", args).await,
        Command::Account(AccountCommand::List(args)) => account_list(paths, args).await,
        Command::Account(AccountCommand::Create(args)) => account_create(paths, args).await,
        Command::Account(AccountCommand::Bind(args)) => account_bind(paths, args).await,
        Command::Account(AccountCommand::ImportConfig(args)) => {
            account_import_config(paths, args).await
        }
        Command::Account(AccountCommand::Verify(args)) => account_verify(paths, args).await,
        Command::Account(AccountCommand::Status(args)) => account_status(paths, args).await,
        Command::Account(AccountCommand::Disable(args)) => account_disable(paths, args).await,
        Command::Account(AccountCommand::Default(AccountDefaultCommand::Set(args))) => {
            account_default_set(paths, args).await
        }
        Command::Account(AccountCommand::Default(AccountDefaultCommand::Get(args))) => {
            account_default_get(paths, args)
        }
        Command::Account(AccountCommand::Default(AccountDefaultCommand::Clear(args))) => {
            account_default_clear(paths, args)
        }
        Command::Credentials(CredentialsCommand::List(args)) => credentials_list(paths, args).await,
        Command::Credentials(CredentialsCommand::Create(args)) => {
            credentials_create(paths, args).await
        }
        Command::Credentials(CredentialsCommand::Bind(args)) => credentials_bind(paths, args).await,
        Command::Credentials(CredentialsCommand::Unbind(args)) => {
            credentials_unbind(paths, args).await
        }
        Command::Device(DeviceCommand::Install(args)) => device::install(&args.source),
        Command::Device(DeviceCommand::Uninstall(args)) => device_uninstall(args),
        Command::Device(DeviceCommand::Status) => device::status(),
        Command::Device(DeviceCommand::Launch) => device::launch(&paths),
        Command::Device(DeviceCommand::Diagnose) => device::diagnose(),
        Command::Device(DeviceCommand::Revoke(args)) => device_revoke(paths, args).await,
        Command::Device(DeviceCommand::RotateToken(args)) => device_rotate_token(paths, args).await,
        Command::Node(NodeCommand::Install(args)) => node_install(paths, args).await,
        Command::EgoBrowser(command) => ego_browser::run(paths, command, json).await,
        Command::Attach(args) => attach(paths, args).await,
    }
}

fn device_uninstall(args: DeviceUninstallArgs) -> Result<()> {
    if !args.yes
        && !prompt_yes_no(
            "Remove the local Agent Remote Device app, credentials, permissions, and data? [y/N] ",
        )?
    {
        terminal::note("Device app removal cancelled.");
        return Ok(());
    }
    device::uninstall()
}

async fn device_revoke(paths: AppPaths, args: DeviceRevokeArgs) -> Result<()> {
    let mut config = Config::load(&paths)?;
    let server_url = config
        .server_url
        .clone()
        .context("server URL is not configured")?;
    let device_id = args
        .device
        .or_else(|| config.active_device_id.clone())
        .context("no device selected; pass --device or register an active device")?;
    let secret_store = SecretStore::new(paths.clone());
    let user_token = auth::load_user_token(&paths, &server_url).await?.context(
        "a user token is required; run agent-remote login --skip-device-registration first",
    )?;
    if !args.yes
        && !prompt_yes_no(&format!(
            "Revoke device {device_id} and invalidate its remote access? [y/N] "
        ))?
    {
        terminal::note("Device revocation cancelled.");
        return Ok(());
    }

    ApiClient::new(server_url.clone())?
        .revoke_device(&user_token, &device_id)
        .await
        .context("failed to revoke device")?;

    let mut cleanup_errors = Vec::new();
    if let Err(error) = delete_broker_credential_if_matches(&paths, &server_url, &device_id) {
        cleanup_errors.push(format!("Network Broker credential: {error}"));
    }
    if let Err(error) = secret_store.delete_secret(&device_token_key(&server_url, &device_id)) {
        cleanup_errors.push(format!("device credential: {error}"));
    }
    if let Err(error) = clear_device_token_refresh(&paths, &server_url, &device_id) {
        cleanup_errors.push(format!("device refresh state: {error}"));
    }
    if config.active_device_id.as_deref() == Some(device_id.as_str()) {
        config.active_device_id = None;
        if let Err(error) = config.save(&paths) {
            cleanup_errors.push(format!("active device configuration: {error}"));
        }
    }
    match LocalState::open(&paths).and_then(|state| {
        state.init_schema()?;
        if let Some(mut device) = state.get_device(&device_id)? {
            device.status = "revoked".to_string();
            state.upsert_device(&device)?;
        }
        Ok(())
    }) {
        Ok(()) => {}
        Err(error) => cleanup_errors.push(format!("local device metadata: {error}")),
    }

    if !cleanup_errors.is_empty() {
        bail!(
            "device {device_id} was revoked remotely, but local cleanup is incomplete: {}",
            cleanup_errors.join("; ")
        )
    }
    terminal::success_line(format!("Revoked device {device_id}"));
    Ok(())
}

async fn device_rotate_token(paths: AppPaths, args: DeviceRotateTokenArgs) -> Result<()> {
    let config = Config::load(&paths)?;
    let server_url = config.server_url.context("server URL is not configured")?;
    let device_id = config
        .active_device_id
        .context("no active device is configured")?;
    let user_token = auth::load_user_token(&paths, &server_url).await?.context(
        "a user token is required; run agent-remote login --skip-device-registration first",
    )?;
    if !args.yes
        && !prompt_yes_no(
            "Rotate the active device token and replace its local credential? [y/N] ",
        )?
    {
        terminal::note("Device token rotation cancelled.");
        return Ok(());
    }

    let rotated = ApiClient::new(server_url.clone())?
        .rotate_device_token(&user_token, &device_id)
        .await
        .context("failed to rotate device token")?;
    if let Err(error) = store_device_token(&paths, &server_url, &device_id, &rotated) {
        bail!(
            "device token was rotated remotely, but local credential replacement is incomplete: \
             {error:#}"
        )
    }
    terminal::success_line(format!("Rotated credential for device {device_id}"));
    Ok(())
}

/// Issues a secret-free Node join flow and re-resolves the target before delivery.
async fn node_install(paths: AppPaths, args: NodeInstallArgs) -> Result<()> {
    let config = Config::load(&paths)?;
    let server_url = config
        .server_url
        .clone()
        .context("server URL is not configured; run agent-remote login first")?;
    if !valid_node_install_server_url(&server_url) {
        bail!("configured server URL is not a canonical HTTP(S) origin; run login again")
    }
    let token = auth::load_user_token(&paths, &server_url)
        .await?
        .context("a logged-in user credential is required; run agent-remote login first")?;
    let client = ApiClient::new(server_url.clone())?;
    let listed = client
        .list_nodes(&token)
        .await
        .context("failed to list managed Nodes")?;
    let node_id = resolve_id(
        &args.node,
        "managed Node",
        listed.iter().map(|node| node.id.as_str()),
    )?;
    if !uuid::Uuid::parse_str(&node_id).is_ok_and(|value| value.to_string() == node_id) {
        bail!("control plane returned a non-canonical Node ID")
    }
    let selected = listed
        .iter()
        .find(|node| node.id == node_id)
        .context("selected Node disappeared")?;
    let refreshed = client
        .list_nodes(&token)
        .await
        .context("failed to refresh managed Node list")?;
    let current = refreshed
        .iter()
        .find(|node| node.id == node_id)
        .filter(|node| node_fingerprint(node) == node_fingerprint(selected))
        .context("selected Node state is stale; refresh and retry")?;
    if !current.enrollment_admission {
        bail!("selected Node enrollment admission is closed")
    }
    let host = current
        .ssh_host
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("selected Node has no managed SSH host")?;
    if !valid_managed_ssh_host(host) {
        bail!("selected Node has an invalid managed SSH host")
    }
    let user = current
        .ssh_user
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("agent-remote");
    if !valid_managed_ssh_user(user) {
        bail!("selected Node has an invalid managed SSH user")
    }
    let port = current.ssh_port.unwrap_or(22);
    if port == 0 {
        bail!("selected Node has an invalid managed SSH port")
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            bail!("error_code=confirmation_required next_action=select_node")
        }
        let intent = if args.enable_ego_browser {
            " and explicitly enable the verified ego-browser capability"
        } else {
            ""
        };
        if !prompt_yes_no(&format!(
            "Install signed Node release {} and enroll {} over SSH{}? [y/N] ",
            MANAGED_NODE_VERSION, current.name, intent
        ))? {
            terminal::note("Node installation cancelled.");
            return Ok(());
        }
    }
    let ssh = std::env::var_os("AGENT_REMOTE_NODE_SSH").unwrap_or_else(|| "ssh".into());
    let release_target = detect_remote_node_release_target(&ssh, user, host, port).await?;
    let fingerprint = node_install_fingerprint(current);
    let created_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let pending = node_install_state::load(&paths)?;
    let resuming_release_installed = pending
        .as_ref()
        .is_some_and(|state| state.stage == NodeInstallStage::ReleaseInstalled);
    let mut exchange = match pending {
        Some(state) => {
            if !state.matches(
                &server_url,
                &node_id,
                &fingerprint,
                args.enable_ego_browser,
                MANAGED_NODE_VERSION,
                &release_target,
            ) {
                bail!(
                    "error_code=exchange_conflict state=exchange_pending \
                     next_action=finish_or_revoke_pending_node_install"
                )
            }
            state
        }
        None => {
            let state = NodeInstallExchangeState::prepared(
                server_url.clone(),
                node_id.clone(),
                fingerprint,
                args.enable_ego_browser,
                MANAGED_NODE_VERSION.to_owned(),
                release_target.clone(),
                created_at_unix,
            )?;
            node_install_state::save(&paths, &state)?;
            state
        }
    };

    if exchange.stage == NodeInstallStage::Prepared {
        let release = node_release::obtain(&release_target)
            .await
            .context("error_code=release_verification_failed state=release_pending")?;
        if !remote_node_release_is_staged(
            &ssh,
            user,
            host,
            port,
            MANAGED_NODE_VERSION,
            &release_target,
            Some(release.sha256()),
        )
        .await?
        {
            transfer_node_release(&ssh, user, host, port, &release)
                .await
                .context(
                    "error_code=transport_unavailable state=release_pending \
                     next_action=retry_same_command",
                )?;
        }
        // A staging marker proves arrival only; installation must finish before code issue.
        install_staged_node_release(&ssh, user, host, port, &release)
            .await
            .context(
                "error_code=transport_unavailable state=release_pending \
                 next_action=retry_same_command",
            )?;
        exchange.mark_release_installed(release.sha256().to_owned())?;
        node_install_state::save(&paths, &exchange)?;
    }

    // After a lost issue response, revoke the unconsumed exchange before rotating its ID.
    if exchange.stage == NodeInstallStage::ReleaseInstalled && resuming_release_installed {
        let revocation = client
            .revoke_node_join_code(&token, &node_id, &exchange.exchange_id)
            .await
            .context("failed to revoke an incomplete Node join-code issuance")?;
        if revocation == NodeJoinCodeRevokeState::Consumed {
            bail!("error_code=unknown_result state=exchange_pending next_action=retry_same_command")
        }
        let release_sha256 = exchange
            .release_sha256
            .clone()
            .context("release-installed exchange has no artifact digest")?;
        node_install_state::clear(&paths)?;
        exchange = NodeInstallExchangeState::prepared(
            server_url.clone(),
            node_id.clone(),
            node_install_fingerprint(current),
            args.enable_ego_browser,
            MANAGED_NODE_VERSION.to_owned(),
            release_target.clone(),
            created_at_unix,
        )?;
        exchange.mark_release_installed(release_sha256)?;
        node_install_state::save(&paths, &exchange)?;
    }

    let requested_intent = args.enable_ego_browser.then_some(true);
    let mut join_code = None;
    if exchange.stage == NodeInstallStage::ReleaseInstalled {
        let join = client
            .issue_node_join_code(&token, &node_id, requested_intent, &exchange.exchange_id)
            .await
            .context("failed to issue Node join code")?;
        if join.node_id != node_id
            || !valid_join_code(join.code.trim())
            || !valid_join_code_expiry(join.expires_at.trim())
            || join.ego_browser_enabled != requested_intent
        {
            if client
                .revoke_node_join_code(&token, &node_id, &exchange.exchange_id)
                .await
                .is_ok_and(|state| state != NodeJoinCodeRevokeState::Consumed)
            {
                node_install_state::clear(&paths)?;
            }
            bail!("control plane returned an invalid Node join code")
        }
        exchange.mark_issued(join.expires_at.trim().to_owned())?;
        node_install_state::save(&paths, &exchange)?;
        join_code = Some(join.code.trim().to_owned());
    }
    let remote_command = node_enrollment_command(
        &exchange.exchange_id,
        &server_url,
        &node_id,
        join_code.is_some(),
        args.enable_ego_browser,
    );
    let mut command = AsyncCommand::new(ssh);
    command
        .arg("-T")
        .arg("-p")
        .arg(port.to_string())
        .arg("--")
        .arg(format!("{user}@{host}"))
        .arg(remote_command)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if join_code.is_some() {
        command.stdin(std::process::Stdio::piped());
    } else {
        command.stdin(std::process::Stdio::null());
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return Err(node_install_transport_failure(
                &client, &token, &node_id, &exchange, &paths,
            )
            .await)
        }
    };
    if let Some(join_code) = join_code {
        let mut stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(node_install_transport_failure(
                    &client, &token, &node_id, &exchange, &paths,
                )
                .await);
            }
        };
        if stdin.write_all(join_code.as_bytes()).await.is_err()
            || stdin.write_all(b"\n").await.is_err()
        {
            drop(stdin);
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(node_install_transport_failure(
                &client, &token, &node_id, &exchange, &paths,
            )
            .await);
        }
        drop(stdin);
    }
    let output = match child.wait_with_output().await {
        Ok(output) => output,
        Err(_) => {
            return Err(node_install_transport_failure(
                &client, &token, &node_id, &exchange, &paths,
            )
            .await)
        }
    };
    if !output.status.success() {
        return Err(
            node_install_transport_failure(&client, &token, &node_id, &exchange, &paths).await,
        );
    }
    client
        .revoke_node_join_code(&token, &node_id, &exchange.exchange_id)
        .await
        .context(
            "Node enrolled, but join-code cleanup is pending; retry the same Node install command",
        )?;
    node_install_state::clear(&paths)?;
    cleanup_staged_node_release(
        std::env::var_os("AGENT_REMOTE_NODE_SSH").unwrap_or_else(|| "ssh".into()),
        user,
        host,
        port,
        MANAGED_NODE_VERSION,
        &release_target,
        exchange.release_sha256.as_deref(),
    )
    .await;
    terminal::success_line(format!(
        "Node {} enrolled; ego-browser intent remains {}.",
        current.name,
        if args.enable_ego_browser {
            "enabled"
        } else {
            "unchanged"
        }
    ));
    Ok(())
}

fn node_ssh_command(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    remote_command: &str,
) -> AsyncCommand {
    let mut command = AsyncCommand::new(ssh);
    command
        .arg("-T")
        .arg("-p")
        .arg(port.to_string())
        .arg("--")
        .arg(format!("{user}@{host}"))
        .arg(remote_command);
    command
}

async fn detect_remote_node_release_target(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
) -> Result<String> {
    let probe = r#"set -eu
test "$(uname -s)" = Linux
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) exit 64 ;;
esac
libc=glibc
if ldd --version 2>&1 | grep -qi musl || ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then
  libc=musl
fi
printf 'linux-%s-%s\n' "$arch" "$libc"
"#;
    let output = node_ssh_command(ssh, user, host, port, probe)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .context("failed to probe the managed Node release target over SSH")?;
    if !output.status.success() || output.stdout.len() > 128 {
        bail!("error_code=transport_unavailable state=target_unknown next_action=repair_node_ssh")
    }
    let value = std::str::from_utf8(&output.stdout)
        .context("remote Node release target is not UTF-8")?
        .trim();
    Ok(node_release::validate_target(value)?.to_owned())
}

fn remote_node_release_root(version: &str, target: &str) -> String {
    format!(
        "$HOME/.cache/agent-remote-node/releases/{version}/{target}",
        version = version,
        target = target
    )
}

async fn remote_node_release_digest(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    version: &str,
    target: &str,
) -> Result<String> {
    node_release::validate_target(target)?;
    let stage = remote_node_release_root(version, target);
    let command = format!(
        "set -eu\nmarker={}/RELEASE\npython3 - \"$marker\" {} {} <<'PY'\n",
        stage,
        posix_shell_quote(version),
        posix_shell_quote(target)
    ) + r#"import os
import stat
import sys

path, version, target = sys.argv[1:]
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
with os.fdopen(descriptor, "r", encoding="ascii") as source:
    metadata = os.fstat(source.fileno())
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise SystemExit(1)
    fields = source.read(256).split()
if len(fields) != 3 or fields[0] != version or fields[1] != target:
    raise SystemExit(1)
digest = fields[2]
if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
    raise SystemExit(1)
print(digest)
PY
"#;
    let output = node_ssh_command(ssh, user, host, port, &command)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .context("failed to inspect the staged Node release over SSH")?;
    if !output.status.success() || output.stdout.len() > 128 {
        bail!("staged Node release is unavailable")
    }
    let digest = std::str::from_utf8(&output.stdout)?.trim().to_owned();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("staged Node release digest is invalid")
    }
    Ok(digest)
}

async fn remote_node_release_is_staged(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    version: &str,
    target: &str,
    expected_sha256: Option<&str>,
) -> Result<bool> {
    match remote_node_release_digest(ssh, user, host, port, version, target).await {
        Ok(digest) => Ok(expected_sha256.is_none_or(|expected| expected == digest)),
        Err(_) => Ok(false),
    }
}

fn node_release_stage_command(release: &node_release::VerifiedNodeRelease) -> String {
    let version = MANAGED_NODE_VERSION;
    let target = release.target();
    let digest = release.sha256();
    let package = release.archive_name().trim_end_matches(".tar.gz");
    let stage = remote_node_release_root(version, target);
    let header = format!(
        "set -eu\numask 077\nversion={}\ntarget={}\ndigest={}\npackage={}\nstage={}\n",
        posix_shell_quote(version),
        posix_shell_quote(target),
        posix_shell_quote(digest),
        posix_shell_quote(package),
        stage,
    );
    header
        + r#"root=${stage%/*}
parent=${root%/*}
mkdir -p "$HOME/.cache" "$HOME/.cache/agent-remote-node" "$HOME/.cache/agent-remote-node/releases" "$parent" "$root"
chmod 700 "$HOME/.cache/agent-remote-node" "$HOME/.cache/agent-remote-node/releases" "$parent" "$root"
lock="$root/.install-lock"
if ! mkdir "$lock" 2>/dev/null; then
  echo local_lock_busy >&2
  exit 75
fi
work="$root/.incoming.$$"
cleanup() {
  [ -z "$work" ] || rm -rf -- "$work"
  rmdir "$lock" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
mkdir "$work"
chmod 700 "$work"
archive="$work/release.tar.gz"
cat > "$archive"
chmod 600 "$archive"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
test "$actual" = "$digest"
extract="$work/unpacked"
mkdir "$extract"
python3 - "$archive" "$extract" "$package" "$version" <<'PY'
import os
import shutil
import stat
import sys
import tarfile
from pathlib import PurePosixPath

archive_path, destination, package, version = sys.argv[1:]
seen = set()
total = 0
with tarfile.open(archive_path, "r:gz") as source:
    members = source.getmembers()
    if not members or len(members) > 10000:
        raise SystemExit("Node release archive inventory is invalid")
    for member in members:
        path = PurePosixPath(member.name)
        parts = path.parts
        if (
            not parts
            or parts[0] != package
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
            or member.name in seen
            or not (member.isdir() or member.isfile())
        ):
            raise SystemExit("Node release archive contains an unsafe entry")
        seen.add(member.name)
        total += member.size
        if total > 8 * 1024 * 1024 * 1024:
            raise SystemExit("Node release archive expands beyond its size limit")
    for member in members:
        parts = PurePosixPath(member.name).parts
        output = os.path.join(destination, *parts)
        if member.isdir():
            os.makedirs(output, mode=0o700, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(output), mode=0o700, exist_ok=True)
        payload = source.extractfile(member)
        if payload is None:
            raise SystemExit("Node release archive file is unreadable")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with payload, os.fdopen(descriptor, "wb") as destination_file:
            shutil.copyfileobj(payload, destination_file)
        os.chmod(output, (member.mode & 0o777) | stat.S_IRUSR | stat.S_IWUSR)
release = os.path.join(destination, package)
required = ("VERSION", "install.sh", "agent-remote-node", "agent-remote-attach", "agent-remote-runtime")
for name in required:
    path = os.path.join(release, name)
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SystemExit("Node release archive is incomplete")
with open(os.path.join(release, "VERSION"), encoding="ascii") as source:
    if source.read().strip() != version:
        raise SystemExit("Node release archive version is incorrect")
PY
printf '%s %s %s\n' "$version" "$target" "$digest" > "$work/RELEASE"
chmod 600 "$work/RELEASE"
rm -rf -- "$stage.previous"
if [ -e "$stage" ] || [ -L "$stage" ]; then
  mv "$stage" "$stage.previous"
fi
mv "$work" "$stage"
work=""
rm -rf -- "$stage.previous"
"#
}

async fn transfer_node_release(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    release: &node_release::VerifiedNodeRelease,
) -> Result<()> {
    let remote = node_release_stage_command(release);
    let mut command = node_ssh_command(ssh, user, host, port, &remote);
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .context("failed to open the Node release transfer channel")?;
    let mut input = File::open(release.archive())?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to open the Node release transfer stdin")?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if stdin.write_all(&buffer[..count]).await.is_err() {
            drop(stdin);
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!("managed Node release transfer failed")
        }
    }
    drop(stdin);
    let status = child.wait().await?;
    if !status.success() {
        bail!("managed Node rejected the authenticated release transfer")
    }
    Ok(())
}

fn staged_node_install_command(release: &node_release::VerifiedNodeRelease) -> String {
    let stage = remote_node_release_root(MANAGED_NODE_VERSION, release.target());
    let package = release.archive_name().trim_end_matches(".tar.gz");
    format!(
        "set -eu\nstage={}\nexpected={}\narchive=\"$stage/release.tar.gz\"\n\
         test -f \"$stage/RELEASE\"\ntest ! -L \"$stage/RELEASE\"\n\
         test \"$(cat \"$stage/RELEASE\")\" = {}\n\
         test -f \"$archive\"\ntest ! -L \"$archive\"\n\
         if command -v sha256sum >/dev/null 2>&1; then\n\
           actual=$(sha256sum \"$archive\" | awk '{{print $1}}')\n\
         else\n\
           actual=$(shasum -a 256 \"$archive\" | awk '{{print $1}}')\n\
         fi\n\
         test \"$actual\" = \"$expected\"\n\
         installer=\"$stage/unpacked/{}/install.sh\"\n\
         test -f \"$installer\"\ntest ! -L \"$installer\"\n\
         if [ \"$(id -u)\" -eq 0 ]; then\n\
           exec env USE_SUDO=0 bash \"$installer\" --version {} --no-start\n\
         fi\n\
         exec sudo -n env USE_SUDO=0 bash \"$installer\" --version {} --no-start\n",
        stage,
        posix_shell_quote(release.sha256()),
        posix_shell_quote(&format!(
            "{} {} {}",
            MANAGED_NODE_VERSION,
            release.target(),
            release.sha256()
        )),
        package,
        posix_shell_quote(MANAGED_NODE_VERSION),
        posix_shell_quote(MANAGED_NODE_VERSION),
    )
}

async fn install_staged_node_release(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    release: &node_release::VerifiedNodeRelease,
) -> Result<()> {
    let remote = staged_node_install_command(release);
    let status = node_ssh_command(ssh, user, host, port, &remote)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .context("failed to launch the authenticated Node release installer")?;
    if !status.success() {
        bail!("authenticated Node release installation failed")
    }
    Ok(())
}

fn node_enrollment_command(
    exchange_id: &str,
    server_url: &str,
    node_id: &str,
    has_join_code: bool,
    enable_ego_browser: bool,
) -> String {
    let mut arguments = format!(
        "install --config /etc/agent-remote-node/config.json --system-install \
         --version {} --exchange-id {} --server-url {} --node-id {}",
        posix_shell_quote(MANAGED_NODE_VERSION),
        posix_shell_quote(exchange_id),
        posix_shell_quote(server_url),
        posix_shell_quote(node_id),
    );
    if has_join_code {
        arguments.push_str(" --join-code-stdin");
    }
    if enable_ego_browser {
        arguments.push_str(" --enable-ego-browser");
    }
    format!(
        "set -eu\nnode=/usr/local/bin/agent-remote-node\ntest -x \"$node\"\n\
         if [ \"$(id -u)\" -eq 0 ] && id agent-remote >/dev/null 2>&1; then\n\
           runuser -u agent-remote -- \"$node\" {arguments}\n\
         else\n\
           \"$node\" {arguments}\n\
         fi\n\
         privileged() {{\n\
           if [ \"$(id -u)\" -eq 0 ]; then \"$@\"; else sudo -n \"$@\"; fi\n\
         }}\n\
         privileged systemctl enable agent-remote-runtime.service\n\
         privileged systemctl restart agent-remote-runtime.service\n\
         privileged systemctl enable wg-quick@agent-remote.service\n\
         privileged systemctl restart wg-quick@agent-remote.service\n\
         privileged systemctl enable agent-remote-node.service\n\
         privileged systemctl restart agent-remote-node.service\n\
         privileged systemctl is-active --quiet agent-remote-runtime.service\n\
         privileged systemctl is-active --quiet agent-remote-node.service\n"
    )
}

async fn cleanup_staged_node_release(
    ssh: impl AsRef<OsStr>,
    user: &str,
    host: &str,
    port: u16,
    version: &str,
    target: &str,
    expected_sha256: Option<&str>,
) {
    let Some(expected) = expected_sha256 else {
        return;
    };
    if expected.len() != 64 || node_release::validate_target(target).is_err() {
        return;
    }
    let stage = remote_node_release_root(version, target);
    let command = format!(
        "set -eu\nstage={}\nmarker=\"$stage/RELEASE\"\n\
         test \"$(cat \"$marker\")\" = {}\nrm -rf -- \"$stage\"\n",
        stage,
        posix_shell_quote(&format!("{version} {target} {expected}")),
    );
    let _ = node_ssh_command(ssh.as_ref(), user, host, port, &command)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
}

fn valid_join_code(value: &str) -> bool {
    (16..=4096).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
}

fn valid_node_install_server_url(value: &str) -> bool {
    if value.is_empty() || value.len() > 2048 || !value.is_ascii() {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && url.as_str().trim_end_matches('/') == value
}

fn valid_managed_ssh_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && value.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'-' | b'_' | b'%')
        })
}

fn valid_managed_ssh_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn posix_shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn valid_join_code_expiry(value: &str) -> bool {
    let Some(timestamp) = parse_rfc3339_seconds(value) else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    timestamp > now
}

fn parse_rfc3339_seconds(value: &str) -> Option<u64> {
    if value.len() < 20 {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let number = |start: usize, end: usize| -> Option<u32> { value.get(start..end)?.parse().ok() };
    let year = number(0, 4)? as i64;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[(month - 1) as usize] {
        return None;
    }
    let mut cursor = 19;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let fraction_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == fraction_start || cursor - fraction_start > 9 {
            return None;
        }
    }
    let offset_minutes: i64 = match bytes.get(cursor..) {
        Some(b"Z") => 0,
        Some(offset)
            if offset.len() == 6
                && (offset[0] == b'+' || offset[0] == b'-')
                && offset[3] == b':' =>
        {
            let hours: i64 = std::str::from_utf8(&offset[1..3]).ok()?.parse().ok()?;
            let minutes: i64 = std::str::from_utf8(&offset[4..6]).ok()?.parse().ok()?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let total = hours * 60 + minutes;
            if offset[0] == b'-' {
                -total
            } else {
                total
            }
        }
        _ => return None,
    };
    let adjusted_year = year - i64::from(month <= 2);
    let era = (if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    }) / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month as i64 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    let utc = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))?
        .checked_sub(offset_minutes * 60)?;
    u64::try_from(utc).ok()
}

async fn node_install_transport_failure(
    client: &ApiClient,
    token: &str,
    node_id: &str,
    exchange: &NodeInstallExchangeState,
    paths: &AppPaths,
) -> anyhow::Error {
    match client
        .revoke_node_join_code(token, node_id, &exchange.exchange_id)
        .await
    {
        Ok(NodeJoinCodeRevokeState::Revoked | NodeJoinCodeRevokeState::Missing)
            if node_install_state::clear(paths).is_ok() =>
        {
            anyhow::anyhow!(
                "error_code=transport_unavailable state=join_code_revoked next_action=retry_node_install"
            )
        }
        _ => node_install_pending_transport_failure(),
    }
}

fn node_install_pending_transport_failure() -> anyhow::Error {
    anyhow::anyhow!(
        "error_code=transport_unavailable state=exchange_pending next_action=retry_same_command"
    )
}

fn node_install_fingerprint(node: &NodeData) -> String {
    use std::fmt::Write as _;

    let transport = format!(
        "{}\0{}\0{}\0{}",
        node.id,
        node.ssh_host.as_deref().unwrap_or(""),
        node.ssh_port.unwrap_or(22),
        node.ssh_user.as_deref().unwrap_or("agent-remote")
    );
    let digest = Sha256::digest(transport.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn node_fingerprint(node: &NodeData) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        node.id,
        node.name,
        node.status,
        node.ssh_host.as_deref().unwrap_or(""),
        node.ssh_port.unwrap_or_default(),
        node.ssh_user.as_deref().unwrap_or(""),
        node.version.as_deref().unwrap_or(""),
        node.configured_enabled,
        node.effective_enabled,
        node.node_execution_allowed,
        node.ego_browser_enabled,
        node.enrollment_admission,
        node.execution_admission,
    )
}

struct DeviceRegistrationOptions {
    device_name: Option<String>,
    ssh_public_key: Option<PathBuf>,
    wireguard_public_key: Option<String>,
    skip_device_registration: bool,
}

async fn init(paths: AppPaths, args: crate::cli::InitArgs) -> Result<()> {
    terminal::section("Agent Remote Setup");
    paths.ensure_base_dirs()?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;

    let manager = DependencyManager::new(paths.clone());
    manager.ensure_manifest()?;
    terminal::section("Managed Dependencies");
    for status in manager.check_all()? {
        let message = format!("{} at {}", status.name, status.binary_path.display());
        if status.installed {
            terminal::success_line(message);
        } else {
            terminal::warning_line(message);
        }
    }

    let config = Config::load(&paths)?;
    let server_url = match args.server_url.or(config.server_url) {
        Some(value) => normalize_server_url(&value),
        None if args.yes => "http://127.0.0.1:8765".to_string(),
        None => normalize_server_url(&prompt_line_default("Server URL", "http://127.0.0.1:8765")?),
    };
    let client = ApiClient::new(server_url.clone())?;
    match client.healthz().await {
        Ok(health) => terminal::success_line(format!("Server reachable ({})", health.status)),
        Err(error) => terminal::warning_line(format!("Server health check failed: {error}")),
    }

    terminal::note("Sign in with an existing agent-remote user account.");
    let login_args = crate::cli::LoginArgs {
        server_url: Some(server_url.clone()),
        method: args.method,
        username: args.username,
        password: None,
        totp_code: None,
        device_name: args.device_name.clone(),
        ssh_public_key: args.ssh_public_key.clone(),
        wireguard_public_key: args.wireguard_public_key.clone(),
        skip_device_registration: args.skip_device_registration,
    };
    let user_token = match login_args.method {
        LoginMethod::Password => password_login(&client, &login_args).await?,
        LoginMethod::DeviceCode => device_code_login(&client).await?,
    };

    let registered_device_id = finalize_login(
        paths.clone(),
        server_url.clone(),
        user_token,
        DeviceRegistrationOptions {
            device_name: args.device_name,
            ssh_public_key: init_ssh_public_key(
                args.ssh_public_key,
                args.skip_device_registration,
            )?,
            wireguard_public_key: args.wireguard_public_key,
            skip_device_registration: args.skip_device_registration,
        },
    )
    .await?;

    if !args.skip_wireguard_config && registered_device_id.is_some() {
        let should_write = args.yes
            || prompt_yes_no_default("Fetch and write WireGuard config now? [Y/n] ", true)?;
        if should_write {
            match write_default_wireguard_config(paths.clone()).await {
                Ok(()) => {}
                Err(error) => {
                    terminal::warning_line(format!("WireGuard config not written: {error}"))
                }
            }
        }
    }

    terminal::success_line("Initialization complete");
    terminal::note(format!(
        "Next: {}",
        terminal::command("agent-remote status --online")
    ));
    terminal::note(format!("Next: {}", terminal::command("fclaude")));
    Ok(())
}

async fn login(paths: AppPaths, args: crate::cli::LoginArgs) -> Result<()> {
    paths.ensure_base_dirs()?;
    let config = Config::load(&paths)?;
    let server_url = args
        .server_url
        .clone()
        .or_else(|| config.server_url.clone())
        .context("missing server URL; pass --server-url or set AGENT_REMOTE_SERVER_URL")?;
    let server_url = normalize_server_url(&server_url);
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    DependencyManager::new(paths.clone()).ensure_manifest()?;

    let client = ApiClient::new(server_url.clone())?;
    let user_token = match args.method {
        LoginMethod::Password => password_login(&client, &args).await?,
        LoginMethod::DeviceCode => device_code_login(&client).await?,
    };

    finalize_login(
        paths,
        server_url,
        user_token,
        DeviceRegistrationOptions {
            device_name: args.device_name,
            ssh_public_key: args.ssh_public_key,
            wireguard_public_key: args.wireguard_public_key,
            skip_device_registration: args.skip_device_registration,
        },
    )
    .await?;
    Ok(())
}

async fn finalize_login(
    paths: AppPaths,
    server_url: String,
    user_token: AuthToken,
    options: DeviceRegistrationOptions,
) -> Result<Option<String>> {
    paths.ensure_base_dirs()?;
    let mut config = Config::load(&paths)?;
    let existing_device_id = match config.server_url.as_deref() {
        Some(configured_server_url)
            if normalize_server_url(configured_server_url) == server_url =>
        {
            config.active_device_id.clone()
        }
        _ => None,
    };
    config.server_url = Some(server_url.clone());
    config.save(&paths)?;

    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    DependencyManager::new(paths.clone()).ensure_manifest()?;
    if options.skip_device_registration {
        let backend = auth::store_user_token(&paths, &server_url, &user_token).await?;
        state.set_kv("last_login_mode", "user_token")?;
        terminal::success_line(format!("Logged in to {server_url}"));
        Details::new()
            .field("Credential store", backend)
            .field(
                "Token lifetime",
                format!("{} seconds", user_token.expires_in),
            )
            .field("Device", "not registered")
            .render();
        return Ok(None);
    }

    let ssh_public_key = resolve_ssh_public_key(options.ssh_public_key.as_deref())?;
    let device_name = options
        .device_name
        .unwrap_or_else(platform::default_device_name);
    let platform = platform::current_platform()?;
    let request = RegisterDeviceRequest {
        name: device_name.clone(),
        platform,
        cli_version: VERSION.to_string(),
        ssh_public_key,
        wireguard_public_key: options.wireguard_public_key,
        existing_device_id,
    };
    let registration = ApiClient::new(server_url.clone())?
        .register_device(&user_token.access_token, &request)
        .await
        .context("failed to register local device")?;
    let device = registration.data.device;

    state.upsert_device(&LocalDevice {
        id: device.id.clone(),
        server_url: server_url.clone(),
        name: device.name.clone(),
        platform: device.platform.clone(),
        status: device.status.clone(),
        ssh_key_id: Some(registration.data.ssh_key_id),
        wireguard_peer_id: registration.data.wireguard_peer_id,
        created_at: Some(device.created_at),
        last_seen_at: device.last_seen_at,
    })?;
    state.set_kv("last_login_mode", "device_token")?;
    config.active_device_id = Some(device.id.clone());
    config.save(&paths)?;

    let backend = store_device_token(
        &paths,
        &server_url,
        &device.id,
        &registration.data.device_token,
    )?;
    auth::store_user_token(&paths, &server_url, &user_token).await?;

    terminal::success_line(format!("Logged in to {server_url}"));
    Details::new()
        .field("Device", format!("{} ({})", device.name, device.id))
        .field("Credential store", backend)
        .field(
            "Token lifetime",
            format!("{} seconds", registration.data.device_token.expires_in),
        )
        .render();
    Ok(Some(device.id))
}

async fn password_login(client: &ApiClient, args: &crate::cli::LoginArgs) -> Result<AuthToken> {
    let username = match &args.username {
        Some(username) => username.clone(),
        None => prompt_line("Username: ")?,
    };
    let password = match &args.password {
        Some(password) => password.clone(),
        None => rpassword::prompt_password(terminal::prompt("Password: "))?,
    };
    client
        .login_password(&username, &password, args.totp_code.as_deref())
        .await
        .context("login failed")
}

async fn device_code_login(client: &ApiClient) -> Result<AuthToken> {
    let start = client.start_cli_login().await?;
    terminal::section("Device Login");
    Details::new()
        .field("Open", start.verification_url)
        .field("Code", terminal::command(start.user_code))
        .status("Status", "waiting for approval")
        .render();

    let deadline = Instant::now() + Duration::from_secs(start.expires_in);
    while Instant::now() < deadline {
        match client.complete_cli_login(&start.device_code).await {
            Ok(token) => return Ok(token),
            Err(error) if error.is_pending_cli_login() => {
                sleep(Duration::from_secs(start.interval.max(1))).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    bail!("CLI login expired before approval")
}

async fn logout(paths: AppPaths, revoke_remote: bool) -> Result<()> {
    let config = Config::load(&paths)?;
    let Some(server_url) = config.server_url.clone() else {
        terminal::note("Not logged in.");
        return Ok(());
    };
    let secret_store = SecretStore::new(paths.clone());
    let mut token = None;

    if let Some(device_id) = config.active_device_id.clone() {
        let key = device_token_key(&server_url, &device_id);
        token = load_device_token(&paths)
            .await
            .ok()
            .map(|(_, _, token)| token);
        let _ = delete_broker_credential_if_matches(&paths, &server_url, &device_id);
        let _ = secret_store.delete_secret(&key);
        let _ = clear_device_token_refresh(&paths, &server_url, &device_id);
    }
    if let Err(error) = auth::logout_user(&paths, &server_url, revoke_remote).await {
        terminal::warning_line(format!("User logout could not be fully confirmed: {error}"));
    }

    if revoke_remote {
        if let Some(access_token) = token {
            let client = ApiClient::new(server_url.clone())?;
            if let Err(error) = client.logout(&access_token).await {
                eprintln!(
                    "{} Remote logout failed: {error}",
                    terminal::warning("WARN")
                );
            }
        }
    }

    let mut config = config;
    config.active_device_id = None;
    config.save(&paths)?;
    terminal::success_line(format!("Logged out from {server_url}"));
    Ok(())
}

async fn status(paths: AppPaths, online: bool) -> Result<()> {
    let config = Config::load(&paths)?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;

    terminal::section("Client Status");
    let mut details = Details::new().field("Home", paths.home().display());
    details = match &config.server_url {
        Some(server_url) => details.field("Server", server_url),
        None => details.status("Server", "not configured"),
    };

    let active_device = match &config.active_device_id {
        Some(device_id) => state.get_device(device_id)?,
        None => None,
    };
    details = match &active_device {
        Some(device) => details
            .field("Device", format!("{} ({})", device.name, device.id))
            .status("Device status", device.status.clone()),
        None => details.status("Device", "not registered"),
    };
    details = match state.get_kv("last_login_mode")? {
        Some(mode) => details.field("Login mode", mode),
        None => details.status("Login mode", "unknown"),
    };

    let token_present = match (&config.server_url, &config.active_device_id) {
        (Some(server_url), Some(device_id)) => {
            has_device_token(&paths, server_url, device_id).unwrap_or(false)
        }
        (Some(server_url), None) => SecretStore::new(paths.clone())
            .get_secret(&user_token_key(server_url))
            .ok()
            .flatten()
            .is_some(),
        (None, _) => false,
    };
    details = details.status(
        "Credential",
        if token_present { "present" } else { "missing" },
    );
    details.render();

    if online {
        if let Some(server_url) = config.server_url {
            let client = ApiClient::new(server_url.clone())?;
            let health = client.healthz().await?;
            terminal::section("Live Status");
            let mut online_details = Details::new().status("Server", health.status);
            if let Some(device) = active_device {
                let (_, _, token) = load_device_token(&paths).await?;
                let remote = client.get_device(&token, &device.id).await?;
                online_details = online_details.status("Remote device", remote.status);
            }
            online_details.render();
        }
    }
    Ok(())
}

async fn wireguard_config(paths: AppPaths, args: crate::cli::WireGuardConfigArgs) -> Result<()> {
    write_wireguard_config(paths, args.output).await
}

async fn write_default_wireguard_config(paths: AppPaths) -> Result<()> {
    write_wireguard_config(paths, None).await
}

async fn write_wireguard_config(paths: AppPaths, output: Option<PathBuf>) -> Result<()> {
    let (server_url, device_id, token) = load_device_token(&paths).await?;
    let store = SecretStore::new(paths.clone());
    let private_key_name = wireguard_private_key_key(&server_url, &device_id);
    let private_key = match store.get_secret(&private_key_name)? {
        Some(private_key) => private_key,
        None => {
            let private_key = wireguard::generate_private_key();
            store.set_secret(&private_key_name, &private_key)?;
            private_key
        }
    };
    let public_key = wireguard::public_key_from_private(&private_key)?;
    let client = ApiClient::new(server_url)?;
    client.enroll_wireguard_peer(&token, &public_key).await?;
    let config = client.get_wireguard_config(&token).await?;
    let output = output.unwrap_or_else(|| wireguard::default_config_path(&paths));
    wireguard::write_config(&output, &config, &private_key)?;
    terminal::success_line("WireGuard configuration written");
    Details::new()
        .field("Path", output.display())
        .field("Device", config.device_id)
        .field("Peers", config.peers.len())
        .render();
    Ok(())
}

fn wireguard_action(
    paths: AppPaths,
    action: &str,
    args: crate::cli::WireGuardActionArgs,
) -> Result<()> {
    let config = args
        .config
        .unwrap_or_else(|| wireguard::default_config_path(&paths));
    wireguard::run_helper(&paths, action, &config, args.dry_run)?;
    terminal::success_line(format!("WireGuard {action} using {}", config.display()));
    Ok(())
}

async fn ssh_check(paths: AppPaths, args: crate::cli::SshCheckArgs) -> Result<()> {
    let version = ssh::check_ssh_available()?;
    terminal::success_line(format!("SSH available ({version})"));
    if let Some(session_id) = args.session_id {
        let (server_url, _device_id, token) = load_device_token(&paths).await?;
        let client = ApiClient::new(server_url)?;
        let session_id = resolve_session_reference(&client, &token, &session_id).await?;
        let attach = client.attach_session(&token, &session_id).await?;
        terminal::section("Attach Authorization");
        Details::new()
            .field("Session", attach.session_id)
            .field(
                "Node",
                format!("{} ({})", attach.node_id, attach.node_wireguard_ip),
            )
            .field("Tmux", attach.tmux_session_name)
            .field("Command", terminal::command(attach.ssh_command))
            .field("Task", attach.authorization_task_id)
            .field("Expires", format!("{} seconds", attach.expires_in))
            .render();
    }
    Ok(())
}

async fn attach(paths: AppPaths, args: crate::cli::AttachArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let reference = args
        .session
        .or(args.session_id)
        .context("missing session reference")?;
    let client = ApiClient::new(server_url)?;
    let session_id = resolve_session_reference(&client, &token, &reference).await?;
    let attach = client.attach_session(&token, &session_id).await?;
    terminal::section("Attach");
    Details::new()
        .field("Command", terminal::command(&attach.ssh_command))
        .field("Tmux", &attach.tmux_session_name)
        .field("Expires", format!("{} seconds", attach.expires_in))
        .render();
    if args.print_only {
        return Ok(());
    }
    let attach = client.wait_for_attach_authorization(&token, attach).await?;
    ssh::execute_attach(&paths, &attach)
}

async fn resolve_session_reference(
    client: &ApiClient,
    token: &str,
    reference: &str,
) -> Result<String> {
    let sessions = client.list_sessions(token, None, &[]).await?;
    resolve_id(
        reference,
        "session",
        sessions.iter().map(|session| session.id.as_str()),
    )
}

async fn resolve_account_reference(
    client: &ApiClient,
    token: &str,
    reference: &str,
) -> Result<String> {
    let accounts = client.list_tool_accounts(token).await?;
    resolve_id(
        reference,
        "tool account",
        accounts.iter().map(|account| account.id.as_str()),
    )
}

async fn resolve_profile_reference(
    client: &ApiClient,
    token: &str,
    reference: &str,
) -> Result<String> {
    let profiles = client.list_developer_credential_profiles(token).await?;
    resolve_id(
        reference,
        "credential profile",
        profiles.iter().map(|profile| profile.id.as_str()),
    )
}

async fn account_list(paths: AppPaths, args: crate::cli::ListArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let accounts = ApiClient::new(server_url)?
        .list_tool_accounts(&token)
        .await?;
    if accounts.is_empty() {
        terminal::note("No tool accounts found.");
        return Ok(());
    }
    let mut table = Table::new(["ID", "TOOL", "NAME", "STATUS", "REGION", "RUNTIME"]);
    for account in accounts {
        table.row([
            if args.no_trunc {
                account.id
            } else {
                short_id(&account.id)
            },
            account.tool_type,
            account.display_name,
            account.status,
            account.region_code,
            account.runtime_backend.unwrap_or_else(|| "-".to_string()),
        ]);
    }
    table.render();
    Ok(())
}

async fn account_create(paths: AppPaths, args: crate::cli::AccountCreateArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let account = ApiClient::new(server_url)?
        .create_tool_account(
            &token,
            &CreateToolAccountRequest {
                tool_type: args.tool,
                display_name: args.name,
                region_code: args.region,
                timezone: args.timezone,
                locale: args.locale,
                preferred_node_tags: args.tags,
            },
        )
        .await?;
    print_tool_account(&account);
    Ok(())
}

async fn account_bind(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account_id).await?;
    let binding = client
        .start_tool_account_binding(&token, &account_id)
        .await?;
    print_binding_status(&binding);
    Ok(())
}

async fn account_import_config(
    paths: AppPaths,
    args: crate::cli::AccountImportConfigArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account).await?;
    let include = discover_claude_config_paths(args.include_resume_history)?;
    if include.is_empty() {
        terminal::note("No supported local Claude configuration paths found.");
        return Ok(());
    }
    terminal::section("Configuration Import");
    println!("{}", terminal::label("Candidate paths"));
    for path in &include {
        println!("  {}", terminal::command(path));
    }
    if args.include_resume_history {
        terminal::warning_line(
            "Resume history may include private prompts, transcripts, and local paths.",
        );
    }
    if !args.yes
        && !args.dry_run
        && !prompt_yes_no("Import these files to the remote account now? [y/N] ")?
    {
        bail!("config import not confirmed");
    }
    let files = if args.dry_run {
        Vec::new()
    } else {
        collect_claude_config_files(&include)?
    };
    let result = client
        .create_tool_account_config_import(
            &token,
            &account_id,
            &ToolAccountConfigImportRequest {
                tool_type: args.tool,
                source: "local_cli".to_string(),
                include,
                exclude: vec![
                    "~/.claude.json".to_string(),
                    "~/.claude/cache".to_string(),
                    "~/.claude/logs".to_string(),
                    "~/.claude/transcripts".to_string(),
                ],
                files,
                include_resume_history: args.include_resume_history,
                dry_run: args.dry_run,
            },
        )
        .await?;
    terminal::success_line(if result.dry_run {
        "Configuration import preview complete"
    } else {
        "Configuration import queued"
    });
    Details::new()
        .field("Tool account", result.tool_account_id)
        .field("Dry run", result.dry_run)
        .render();
    println!("{}", terminal::label("Accepted"));
    for path in &result.accepted {
        println!("  {path}");
    }
    println!("{}", terminal::label("Rejected"));
    for path in &result.rejected {
        println!("  {path}");
    }
    for warning in &result.warnings {
        terminal::warning_line(warning);
    }
    if let Some(task_id) = &result.task_id {
        Details::new().field("Task", task_id).render();
    }
    if let Some(path) = &result.account_remote_path {
        Details::new().field("Remote path", path).render();
    }
    if let Some(count) = result.imported_file_count {
        Details::new().field("Files queued", count).render();
    }
    if let Some(task_id) = &result.task_id {
        wait_for_config_import(&client, &token, &account_id, task_id).await?;
    }
    Ok(())
}

async fn wait_for_config_import(
    client: &ApiClient,
    token: &str,
    account_id: &str,
    task_id: &str,
) -> Result<()> {
    terminal::note("Waiting for the remote node to finish the configuration import...");
    let deadline = Instant::now() + CONFIG_IMPORT_WAIT_TIMEOUT;
    loop {
        let status = client
            .get_tool_account_config_import_status(token, account_id, task_id)
            .await?;
        if config_import_complete(&status.status, status.error.as_deref(), task_id)? {
            terminal::success_line("Configuration import completed");
            Details::new()
                .field("Files imported", status.file_count)
                .field("Task", status.task_id)
                .render();
            for path in status.files_written {
                println!("  {path}");
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "configuration import did not finish within {} seconds; the remote task may still continue (task {task_id})",
                CONFIG_IMPORT_WAIT_TIMEOUT.as_secs()
            );
        }
        sleep(Duration::from_secs(1)).await;
    }
}

fn config_import_complete(status: &str, error: Option<&str>, task_id: &str) -> Result<bool> {
    match status {
        "succeeded" => Ok(true),
        "pending" | "leased" | "running" => Ok(false),
        "failed" | "cancelled" | "expired" => bail!(
            "configuration import {status}: {} (task {task_id})",
            error.unwrap_or("the remote node did not provide an error summary")
        ),
        value => bail!("configuration import returned unknown status {value} (task {task_id})"),
    }
}

async fn account_verify(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account_id).await?;
    let binding = client
        .verify_tool_account_binding(&token, &account_id)
        .await?;
    print_binding_status(&binding);
    Ok(())
}

async fn credentials_list(paths: AppPaths, args: crate::cli::ListArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let profiles = ApiClient::new(server_url)?
        .list_developer_credential_profiles(&token)
        .await?;
    if profiles.is_empty() {
        terminal::note("No developer credential profiles found.");
        return Ok(());
    }
    let mut table = Table::new(["ID", "NAME", "STATUS", "GITHUB CLI", "SSH"]);
    for profile in profiles {
        table.row([
            if args.no_trunc {
                profile.id
            } else {
                short_id(&profile.id)
            },
            profile.display_name,
            profile.status,
            profile.github_cli_mode,
            profile.ssh_mode,
        ]);
    }
    table.render();
    Ok(())
}

async fn credentials_create(
    paths: AppPaths,
    args: crate::cli::CredentialsCreateArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let profile = ApiClient::new(server_url)?
        .create_developer_credential_profile(
            &token,
            &CreateDeveloperCredentialProfileRequest {
                display_name: args.name,
                git_identity: DeveloperCredentialGitIdentity {
                    user_name: args.git_user_name,
                    user_email: args.git_user_email,
                },
                github_cli: DeveloperCredentialGitHubCli { mode: args.gh_mode },
                ssh: DeveloperCredentialSsh {
                    mode: args.ssh_mode,
                },
            },
        )
        .await?;
    print_developer_credential_profile(&profile);
    Ok(())
}

async fn credentials_bind(paths: AppPaths, args: crate::cli::CredentialsBindArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account).await?;
    let profile_id = resolve_profile_reference(&client, &token, &args.profile).await?;
    let profile = client
        .bind_developer_credential_profile(&token, &account_id, &profile_id)
        .await?;
    print_developer_credential_profile(&profile);
    Ok(())
}

async fn credentials_unbind(
    paths: AppPaths,
    args: crate::cli::CredentialsUnbindArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account).await?;
    client
        .unbind_developer_credential_profile(&token, &account_id)
        .await?;
    terminal::success_line(format!(
        "Developer credential profile unbound from account {}",
        account_id
    ));
    Ok(())
}

async fn account_status(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account_id).await?;
    let account = client.get_tool_account(&token, &account_id).await?;
    print_tool_account(&account);
    let binding = client
        .get_tool_account_binding_status(&token, &account_id)
        .await?;
    print_binding_status(&binding);
    Ok(())
}

async fn account_disable(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account_id).await?;
    let account = client.disable_tool_account(&token, &account_id).await?;
    print_tool_account(&account);
    Ok(())
}

async fn account_default_set(
    paths: AppPaths,
    args: crate::cli::AccountDefaultSetArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let account_id = resolve_account_reference(&client, &token, &args.account_id).await?;
    let account = client.get_tool_account(&token, &account_id).await?;
    if account.tool_type != args.tool {
        bail!(
            "account {} is {}, not {}",
            account.id,
            account.tool_type,
            args.tool
        );
    }
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    state.set_kv(&default_account_key(&args.tool), &account.id)?;
    terminal::success_line(format!(
        "Default {} account set to {}",
        args.tool, account.id
    ));
    Ok(())
}

fn account_default_get(paths: AppPaths, args: crate::cli::AccountDefaultGetArgs) -> Result<()> {
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    match state.get_kv(&default_account_key(&args.tool))? {
        Some(account_id) => Details::new()
            .field(format!("Default {} account", args.tool), account_id)
            .render(),
        None => terminal::note(format!("Default {} account is not set.", args.tool)),
    }
    Ok(())
}

fn account_default_clear(paths: AppPaths, args: crate::cli::AccountDefaultGetArgs) -> Result<()> {
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    state.delete_kv(&default_account_key(&args.tool))?;
    terminal::success_line(format!("Default {} account cleared", args.tool));
    Ok(())
}

fn print_tool_account(account: &ToolAccountData) {
    terminal::section("Tool Account");
    let mut details = Details::new()
        .field("Account", &account.id)
        .field("Tool", &account.tool_type)
        .field("Name", &account.display_name)
        .status("Status", account.status.clone())
        .field("Region", &account.region_code)
        .field("Timezone", &account.timezone)
        .field("Locale", &account.locale)
        .field(
            "Runtime",
            account.runtime_backend.as_deref().unwrap_or("not pinned"),
        );
    if let Some(node_id) = &account.affinity_node_id {
        details = details.field("Affinity node", node_id);
    }
    if !account.preferred_node_tags.is_empty() {
        details = details.field("Node tags", account.preferred_node_tags.join(", "));
    }
    details.render();
}

fn print_developer_credential_profile(profile: &DeveloperCredentialProfileData) {
    terminal::section("Developer Credential Profile");
    let mut details = Details::new()
        .field("Profile", &profile.id)
        .field("Name", &profile.display_name)
        .status("Status", profile.status.clone())
        .field("GitHub CLI", &profile.github_cli_mode)
        .field("SSH", &profile.ssh_mode);
    if !profile.git_identity.is_null() {
        details = details.field("Git identity", &profile.git_identity);
    }
    details.render();
}

fn discover_claude_config_paths(include_resume_history: bool) -> Result<Vec<String>> {
    let home = home_dir()?;
    let claude = home.join(".claude");
    let mut paths = Vec::new();
    for relative in [
        "settings.json",
        "CLAUDE.md",
        "agents",
        "skills",
        "plugins",
        "hooks",
        "rules",
    ] {
        push_if_exists(&claude, relative, &mut paths);
    }
    for entry in std::fs::read_dir(&claude)
        .with_context(|| format!("failed to read {}", claude.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("md")
            && path.file_name().and_then(|value| value.to_str()) != Some("CLAUDE.md")
        {
            if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
                paths.push(format!("~/.claude/{name}"));
            }
        }
    }
    if include_resume_history {
        for relative in [
            "projects",
            "sessions",
            "history.jsonl",
            "file-history",
            "plans",
            "tasks",
            "session-env",
        ] {
            push_if_exists(&claude, relative, &mut paths);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn push_if_exists(root: &Path, relative: &str, output: &mut Vec<String>) {
    if root.join(relative).exists() {
        output.push(format!("~/.claude/{relative}"));
    }
}

fn collect_claude_config_files(include: &[String]) -> Result<Vec<ToolAccountConfigImportFile>> {
    let home = home_dir()?;
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    for path in include {
        let local_path = expand_claude_config_path(&home, path)?;
        if local_path.is_file() {
            push_config_file(&home, &local_path, &mut files, &mut total_bytes)?;
        } else if local_path.is_dir() {
            collect_config_dir(&home, &local_path, &mut files, &mut total_bytes)?;
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files.dedup_by(|left, right| left.path == right.path);
    Ok(files)
}

fn collect_config_dir(
    home: &Path,
    dir: &Path,
    files: &mut Vec<ToolAccountConfigImportFile>,
    total_bytes: &mut u64,
) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read config directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_config_dir(home, &path, files, total_bytes)?;
        } else if file_type.is_file() {
            push_config_file(home, &path, files, total_bytes)?;
        }
    }
    Ok(())
}

fn push_config_file(
    home: &Path,
    path: &Path,
    files: &mut Vec<ToolAccountConfigImportFile>,
    total_bytes: &mut u64,
) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat config file {}", path.display()))?;
    if metadata.len() > CONFIG_IMPORT_MAX_FILE_BYTES {
        bail!(
            "config file {} is larger than {} bytes",
            path.display(),
            CONFIG_IMPORT_MAX_FILE_BYTES
        );
    }
    *total_bytes += metadata.len();
    if *total_bytes > CONFIG_IMPORT_MAX_TOTAL_BYTES {
        bail!(
            "config import exceeds {} bytes; use --include-resume-history only for small histories",
            CONFIG_IMPORT_MAX_TOTAL_BYTES
        );
    }
    let content = std::fs::read(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    files.push(ToolAccountConfigImportFile {
        path: to_claude_import_path(home, path)?,
        content_base64: BASE64_STANDARD.encode(content),
        mode: 0o600,
    });
    Ok(())
}

fn expand_claude_config_path(home: &Path, path: &str) -> Result<PathBuf> {
    let suffix = path
        .strip_prefix("~/.claude/")
        .or_else(|| path.strip_prefix("$HOME/.claude/"))
        .context("only ~/.claude paths can be imported")?;
    if suffix
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("unsafe config import path: {path}");
    }
    Ok(home.join(".claude").join(suffix))
}

fn to_claude_import_path(home: &Path, path: &Path) -> Result<String> {
    let claude = home.join(".claude");
    let relative = path
        .strip_prefix(&claude)
        .with_context(|| format!("{} is outside {}", path.display(), claude.display()))?;
    let relative = relative
        .to_str()
        .context("Claude config path is not valid UTF-8")?
        .replace('\\', "/");
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("unsafe config import path: {}", path.display());
    }
    Ok(format!("~/.claude/{relative}"))
}

fn home_dir() -> Result<PathBuf> {
    platform::user_home_dir().context(if cfg!(windows) {
        "USERPROFILE is not set"
    } else {
        "HOME is not set"
    })
}

fn print_binding_status(status: &BindingStatusData) {
    terminal::section("Account Binding");
    let mut details = Details::new().status("Status", status.status.clone());
    if let Some(node_id) = &status.node_id {
        details = details.field("Node", node_id);
    }
    if let Some(task_id) = &status.task_id {
        details = details.field("Task", task_id);
    }
    if let Some(binding_session_id) = &status.binding_session_id {
        details = details.field("Binding session", binding_session_id);
    }
    if let Some(tmux_session_name) = &status.tmux_session_name {
        details = details.field("Tmux", tmux_session_name);
    }
    if let Some(path) = &status.account_remote_path {
        details = details.field("Remote path", path);
    }
    if let Some(command) = &status.connect_command {
        details = details.field("Command", terminal::command(command));
    }
    if let Some(verifier) = &status.verifier {
        details = details.field("Verifier", verifier);
    }
    if let Some(error) = &status.error {
        details = details.field("Error", terminal::failure(error));
    }
    details.render();
}

async fn sync_ensure(paths: AppPaths, args: crate::cli::SyncEnsureArgs) -> Result<()> {
    let sync =
        ensure_workspace_sync(&paths, args.workspace.as_deref(), args.yes, args.dry_run).await?;
    terminal::success_line("Workspace synchronization ready");
    let mut details = Details::new()
        .field("Workspace", sync.workspace_id)
        .field("Sync session", sync.id)
        .status("Status", sync.status)
        .field("Remote path", sync.remote_path);
    if let Some(endpoint) = sync.remote_endpoint {
        details = details.field("Endpoint", endpoint);
    }
    details.render();
    Ok(())
}

async fn sync_status(paths: AppPaths, args: crate::cli::SyncStatusArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let identity = workspace::identify_workspace(args.workspace.as_deref())?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    let Some(local_workspace) =
        state.get_workspace_by_project_key(&server_url, &identity.project_key)?
    else {
        terminal::note("Workspace is not registered.");
        Details::new()
            .field("Path", identity.local_path.display())
            .render();
        return Ok(());
    };
    let Some(local_sync) = state.get_sync_session_for_workspace(&local_workspace.id)? else {
        Details::new()
            .field("Workspace", local_workspace.id)
            .status("Sync session", "missing")
            .render();
        return Ok(());
    };
    let client = ApiClient::new(server_url.clone())?;
    let sync = client.get_sync_session(&token, &local_sync.id).await?;
    persist_sync_session(&state, &server_url, &sync)?;
    let mutagen_status = mutagen::status(&paths, &sync)?;
    terminal::section("Workspace Sync");
    Details::new()
        .field("Workspace", local_workspace.id)
        .field("Path", local_workspace.local_path)
        .field("Sync session", sync.id)
        .status("Status", sync.status)
        .status("Conflicts", sync.conflict_status.clone())
        .status(
            "Mutagen",
            if !mutagen_status.installed {
                "missing"
            } else if mutagen_status.session_exists {
                "active"
            } else if mutagen_status.session_missing {
                "session missing"
            } else {
                "unavailable"
            },
        )
        .render();
    if !mutagen_status.output.is_empty() {
        terminal::section("Mutagen");
        println!("{}", mutagen_status.output.trim());
    }
    if sync.conflict_status != "none" || mutagen_status.has_conflicts {
        if args.fail_on_conflict {
            bail!("workspace sync has unresolved conflicts");
        }
        terminal::warning_line("Workspace sync has unresolved conflicts");
    }
    Ok(())
}

async fn sync_action(
    paths: AppPaths,
    action: &str,
    args: crate::cli::SyncActionArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let identity = workspace::identify_workspace(args.workspace.as_deref())?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    let local_workspace = state
        .get_workspace_by_project_key(&server_url, &identity.project_key)?
        .context("workspace is not registered; run agent-remote sync ensure")?;
    let local_sync = state
        .get_sync_session_for_workspace(&local_workspace.id)?
        .context("sync session is missing; run agent-remote sync ensure")?;
    let client = ApiClient::new(server_url.clone())?;
    let current = client.get_sync_session(&token, &local_sync.id).await?;
    match action {
        "pause" => {
            mutagen::pause(&paths, &current, args.dry_run)?;
            let sync = client.pause_sync_session(&token, &current.id).await?;
            persist_sync_session(&state, &server_url, &sync)?;
            terminal::success_line(format!("Sync paused ({})", sync.id));
        }
        "resume" => {
            let sync = client.resume_sync_session(&token, &current.id).await?;
            mutagen::resume(&paths, &sync, args.dry_run)?;
            persist_sync_session(&state, &server_url, &sync)?;
            terminal::success_line(format!("Sync resumed ({})", sync.id));
        }
        "resolve" => {
            mutagen::resolve(&paths, &current, args.dry_run)?;
            let sync = client.resolve_sync_session(&token, &current.id).await?;
            persist_sync_session(&state, &server_url, &sync)?;
            terminal::success_line(format!("Sync conflicts resolved ({})", sync.id));
        }
        "reset" => {
            let sync = client.reset_sync_session(&token, &current.id).await?;
            mutagen::reset(&paths, &sync, args.dry_run)?;
            persist_sync_session(&state, &server_url, &sync)?;
            terminal::success_line(format!("Sync reset ({})", sync.id));
        }
        _ => bail!("unsupported sync action: {action}"),
    }
    Ok(())
}

async fn ensure_workspace_sync(
    paths: &AppPaths,
    workspace_path: Option<&std::path::Path>,
    assume_yes: bool,
    dry_run: bool,
) -> Result<SyncSessionData> {
    let (server_url, device_id, token) = load_device_token(paths).await?;
    let identity = workspace::identify_workspace(workspace_path)?;
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    let client = ApiClient::new(server_url.clone())?;

    let local_workspace = state.get_workspace_by_project_key(&server_url, &identity.project_key)?;
    if local_workspace.is_none() && !assume_yes {
        terminal::section("Workspace Setup");
        Details::new()
            .field("Workspace", identity.local_path.display())
            .render();
        terminal::note("A remote synchronization relationship is required for this directory.");
        if !prompt_yes_no("Create workspace sync now? [y/N] ")? {
            bail!("workspace sync not confirmed; remote session will not be started");
        }
    }
    let workspace = client
        .create_workspace(
            &token,
            &CreateWorkspaceRequest {
                device_id: device_id.clone(),
                project_key: identity.project_key.clone(),
                local_start_path: identity.local_path.to_string_lossy().to_string(),
                display_name: identity.display_name.clone(),
                sync_git: true,
                git_sync_policy: GitSyncPolicy::default(),
            },
        )
        .await?;
    if let Some(local) = &local_workspace {
        if local.id != workspace.id {
            if let Some(stale_sync) = state.get_sync_session_for_workspace(&local.id)? {
                if let Some(name) = stale_sync.mutagen_session_id.as_deref() {
                    let _ = mutagen::terminate_session(paths, name, dry_run);
                }
            }
            state.delete_workspace_mapping(&local.id)?;
        }
    }
    persist_workspace(&state, &server_url, &workspace)?;

    let local_sync = state.get_sync_session_for_workspace(&workspace.id)?;
    let mut sync = client
        .create_sync_session(
            &token,
            &CreateSyncSessionRequest {
                workspace_id: workspace.id.clone(),
                node_id: None,
                local_path: Some(identity.local_path.to_string_lossy().to_string()),
                sync_mode: "two_way".to_string(),
                sync_git: true,
                exclude: workspace::DEFAULT_EXCLUDES
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            },
        )
        .await?;
    if let Some(local) = &local_sync {
        if local.id != sync.id {
            if let Some(name) = local.mutagen_session_id.as_deref() {
                let _ = mutagen::terminate_session(paths, name, dry_run);
            }
            state.delete_sync_session(&local.id)?;
        }
    }
    persist_sync_session(&state, &server_url, &sync)?;
    if sync.status != "active" {
        sync = wait_until_sync_active(&client, &token, sync).await?;
        persist_sync_session(&state, &server_url, &sync)?;
    }
    if sync.status == "active" {
        mutagen::ensure(paths, &sync, dry_run)?;
    }
    Ok(sync)
}

async fn wait_until_sync_active(
    client: &ApiClient,
    token: &str,
    initial: SyncSessionData,
) -> Result<SyncSessionData> {
    if initial.status == "active" {
        return Ok(initial);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        sleep(Duration::from_secs(1)).await;
        let sync = client.get_sync_session(token, &initial.id).await?;
        if sync.status == "active" {
            return Ok(sync);
        }
        if sync.status == "failed" || sync.status == "stopped" {
            bail!("sync session {} became {}", sync.id, sync.status);
        }
    }
    bail!(
        "sync session {} was not prepared within 30 seconds",
        initial.id
    )
}

fn persist_workspace(
    state: &LocalState,
    server_url: &str,
    workspace: &WorkspaceData,
) -> Result<()> {
    state.upsert_workspace(&LocalWorkspace {
        id: workspace.id.clone(),
        server_url: server_url.to_string(),
        project_key: workspace.project_key.clone(),
        local_path: workspace.local_start_path.clone(),
        display_name: workspace.display_name.clone(),
        remote_path: workspace.remote_path.clone(),
    })
}

fn persist_sync_session(
    state: &LocalState,
    server_url: &str,
    sync: &SyncSessionData,
) -> Result<()> {
    state.upsert_sync_session(&LocalSyncSession {
        id: sync.id.clone(),
        server_url: server_url.to_string(),
        workspace_id: sync.workspace_id.clone(),
        node_id: sync.node_id.clone(),
        status: sync.status.clone(),
        conflict_status: sync.conflict_status.clone(),
        mutagen_session_id: sync.mutagen_session_id.clone(),
        remote_endpoint: sync.remote_endpoint.clone(),
    })
}

fn default_account_key(tool: &str) -> String {
    format!("default_tool_account:{tool}")
}
fn deps_status(paths: AppPaths, fix: bool) -> Result<()> {
    let manager = DependencyManager::new(paths);
    if fix {
        manager.ensure_manifest()?;
    }
    let mut table = Table::new(["DEPENDENCY", "STATUS", "PATH", "LICENSE"]);
    for dependency in manager.check_all()? {
        table.row([
            dependency.name,
            if dependency.installed {
                "present".to_string()
            } else {
                "missing".to_string()
            },
            dependency.binary_path.display().to_string(),
            dependency.license,
        ]);
    }
    table.render();
    Ok(())
}

fn normalize_server_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(prompt));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("empty value is not allowed")
    }
    Ok(value)
}

fn prompt_line_default(prompt: &str, default: &str) -> Result<String> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(format!("{prompt} [{default}]: ")));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim();
    if value.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(value.to_string())
    }
}

fn prompt_optional_line(prompt: &str) -> Result<Option<String>> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(prompt));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(prompt));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let normalized = value.trim().to_ascii_lowercase();
    Ok(matches!(normalized.as_str(), "y" | "yes"))
}

fn prompt_yes_no_default(prompt: &str, default: bool) -> Result<bool> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(prompt));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(default);
    }
    Ok(matches!(normalized.as_str(), "y" | "yes"))
}

fn init_ssh_public_key(
    explicit: Option<PathBuf>,
    skip_device_registration: bool,
) -> Result<Option<PathBuf>> {
    if skip_device_registration {
        return Ok(explicit);
    }
    if explicit.is_some() {
        return Ok(explicit);
    }
    if let Some(default_path) = platform::default_ssh_public_key_path() {
        terminal::note(format!("Using SSH public key {}", default_path.display()));
        return Ok(Some(default_path));
    }
    let path = prompt_optional_line("SSH public key path: ")?;
    Ok(path.map(PathBuf::from))
}

fn resolve_ssh_public_key(explicit: Option<&std::path::Path>) -> Result<String> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => platform::default_ssh_public_key_path().context(
            "missing SSH public key; pass --ssh-public-key or use --skip-device-registration",
        )?,
    };
    let value = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read SSH public key at {}", path.display()))?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("SSH public key at {} is empty", path.display());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        config_import_complete, json_error_value, normalize_server_url, parse_rfc3339_seconds,
        posix_shell_quote, valid_join_code, valid_join_code_expiry, valid_managed_ssh_host,
        valid_managed_ssh_user, valid_node_install_server_url,
    };
    use anyhow::anyhow;

    #[test]
    fn trims_trailing_slashes_from_server_url() {
        assert_eq!(
            normalize_server_url(" https://example.test/// "),
            "https://example.test"
        );
    }

    #[test]
    fn config_import_completion_classifies_terminal_states() {
        assert!(!config_import_complete("pending", None, "task-1").unwrap());
        assert!(!config_import_complete("running", None, "task-1").unwrap());
        assert!(config_import_complete("succeeded", None, "task-1").unwrap());

        let failed = config_import_complete("failed", Some("write failed"), "task-1")
            .unwrap_err()
            .to_string();
        assert!(failed.contains("write failed"));
        assert!(failed.contains("task-1"));
        assert!(config_import_complete("unexpected", None, "task-1").is_err());
    }

    #[test]
    fn node_join_code_metadata_is_strictly_validated() {
        assert!(valid_join_code("jcode_0123456789abcdef"));
        assert!(!valid_join_code("too short"));
        assert!(!valid_join_code("jcode_with\nnewline"));
        assert!(parse_rfc3339_seconds("2099-01-02T03:04:05Z").is_some());
        assert!(parse_rfc3339_seconds("2099-01-02T03:04:05+08:00").is_some());
        assert!(valid_join_code_expiry("2099-01-02T03:04:05Z"));
        assert!(!valid_join_code_expiry("not-a-timestamp"));
        assert!(!valid_join_code_expiry("2000-01-02T03:04:05Z"));
    }

    #[test]
    fn node_install_transport_fields_are_strictly_validated_and_quoted() {
        assert!(valid_node_install_server_url(
            "https://control.example:8443"
        ));
        assert!(!valid_node_install_server_url(
            "https://control.example/path"
        ));
        assert!(!valid_node_install_server_url(
            "https://control.example?next=1"
        ));
        assert!(valid_managed_ssh_host("node-1.internal"));
        assert!(valid_managed_ssh_host("fe80::1%en0"));
        assert!(!valid_managed_ssh_host("-oProxyCommand=bad"));
        assert!(!valid_managed_ssh_host("node\nother"));
        assert!(valid_managed_ssh_user("agent-remote"));
        assert!(!valid_managed_ssh_user("-oProxyCommand=bad"));
        assert!(!valid_managed_ssh_user("agent remote"));
        assert_eq!(posix_shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn json_error_projection_is_stable_and_secret_free() {
        let error = anyhow!(
            "error_code=admission_disabled state=ready admission=server_execution_closed next_action=request_execution_admission next_command=agent-remote ego-browser connect stale=false token=do-not-leak"
        );
        let value = json_error_value(&error);
        assert_eq!(value["error_code"], "admission_disabled");
        assert!(value["state"]["installed"].is_null());
        assert!(value["state"]["enabled"].is_null());
        assert!(value["state"]["registered"].is_null());
        assert_eq!(value["state"]["available"], false);
        assert_eq!(value["state"]["connected"], false);
        assert!(value["capability"]["effective_enabled"].is_null());
        assert_eq!(value["admission"]["binding"], "unknown");
        assert_eq!(value["admission"]["server_execution"], "denied");
        assert_eq!(value["next_action"], "request_execution_admission");
        assert_eq!(value["next_command"], "agent-remote ego-browser connect");
        assert!(!serde_json::to_string(&value)
            .unwrap()
            .contains("do-not-leak"));
    }
}
