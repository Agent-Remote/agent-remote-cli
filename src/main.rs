mod api;
mod auth;
mod broker_credentials;
mod cli;
mod config;
mod dependencies;
mod device;
mod doctor;
mod identifiers;
mod local_state;
mod mutagen;
mod platform;
mod port_forward;
mod secrets;
mod ssh;
mod terminal;
mod wireguard;
mod workspace;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use clap::Parser;
use tokio::time::sleep;

use crate::api::{
    ApiClient, AuthToken, BindingStatusData, CreateDeveloperCredentialProfileRequest,
    CreateSyncSessionRequest, CreateToolAccountRequest, CreateWorkspaceRequest,
    DeveloperCredentialGitHubCli, DeveloperCredentialGitIdentity, DeveloperCredentialProfileData,
    DeveloperCredentialSsh, GitSyncPolicy, RegisterDeviceRequest, SyncSessionData,
    ToolAccountConfigImportFile, ToolAccountConfigImportRequest, ToolAccountData, WorkspaceData,
};
use crate::auth::{
    clear_device_token_refresh, has_device_token, load_device_token, store_device_token,
};
use crate::broker_credentials::delete_broker_credential_if_matches;
use crate::cli::{
    AccountCommand, AccountDefaultCommand, Cli, Command, CredentialsCommand, DepsCommand,
    DeviceCommand, DeviceRevokeArgs, DeviceRotateTokenArgs, DeviceUninstallArgs, LoginMethod,
    SshCommand, SyncCommand, WireGuardCommand, VERSION,
};
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManager;
use crate::doctor::Doctor;
use crate::local_state::{LocalDevice, LocalState, LocalSyncSession, LocalWorkspace};
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
    if let Err(error) = run(cli).await {
        eprintln!("{} {error:#}", terminal::failure("ERROR"));
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
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
        Command::Device(DeviceCommand::Diagnose) => device::diagnose(),
        Command::Device(DeviceCommand::Revoke(args)) => device_revoke(paths, args).await,
        Command::Device(DeviceCommand::RotateToken(args)) => device_rotate_token(paths, args).await,
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
    let user_token = secret_store
        .get_secret(&user_token_key(&server_url))?
        .context(
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
    let user_token = SecretStore::new(paths.clone())
        .get_secret(&user_token_key(&server_url))?
        .context(
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
    let secret_store = SecretStore::new(paths.clone());
    if options.skip_device_registration {
        let key = user_token_key(&server_url);
        let backend = secret_store.set_secret(&key, &user_token.access_token)?;
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
    let _ = secret_store.delete_secret(&user_token_key(&server_url));

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
    let user_key = user_token_key(&server_url);
    if token.is_none() {
        token = secret_store.get_secret(&user_key)?;
    }
    let _ = secret_store.delete_secret(&user_key);

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
    use super::{config_import_complete, normalize_server_url};

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
}
