use std::ffi::OsString;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command as ProcessCommand;
use uuid::Uuid;

use crate::api::{ApiClient, EgoBrowserBindingData, EgoBrowserRequestData};
use crate::auth::load_device_token;
use crate::cli::{
    EgoBrowserCancelRequestArgs, EgoBrowserClaimArgs, EgoBrowserCommand, EgoBrowserLifecycleArgs,
    EgoBrowserRegisterArgs, EgoBrowserRequestsArgs, EgoBrowserStatusArgs, ListArgs,
};
use crate::config::{AppPaths, Config};
use crate::identifiers::{resolve_id, short_id};
use crate::local_state::{LocalEgoBrowserBinding, LocalState};
use crate::secrets::{user_token_key, SecretStore};
use crate::terminal::{self, Details, Table};

const FULL_TRUST_WARNING: &str = "Remote fclaude will execute complete ego-browser heredoc scripts as the current macOS user without an App Sandbox. Scripts can access that user's files, environment, network, browser login data, Node modules, subprocesses, and other tabs or Task Spaces, and can send data remotely. Stopping terminates supervised work only; it cannot roll back side effects or guarantee cleanup of deliberately detached processes.";

/// Run one independent ego-browser control command.
pub async fn run(paths: AppPaths, command: EgoBrowserCommand) -> Result<()> {
    match command {
        EgoBrowserCommand::Register(args) => register(paths, args).await,
        EgoBrowserCommand::Status(args) => status(paths, args).await,
        EgoBrowserCommand::List(args) => list(paths, args).await,
        EgoBrowserCommand::Requests(args) => requests(paths, args).await,
        EgoBrowserCommand::CancelRequest(args) => cancel_request(paths, args).await,
        EgoBrowserCommand::Claim(args) => claim(args).await,
        EgoBrowserCommand::Pause(args) => lifecycle(paths, "pause", args).await,
        EgoBrowserCommand::Resume(args) => resume(paths, args).await,
        EgoBrowserCommand::Stop(args) => lifecycle(paths, "stop", args).await,
        EgoBrowserCommand::Revoke(args) => lifecycle(paths, "revoke", args).await,
    }
}

async fn register(paths: AppPaths, args: EgoBrowserRegisterArgs) -> Result<()> {
    let (server_url, token) =
        load_control_token_for_server(&paths, args.server_url.as_deref()).await?;
    let certificate = args
        .signer_certificate_sha256
        .or_else(|| std::env::var("EGO_BROWSER_SIGNER_CERTIFICATE_SHA256").ok())
        .context(
            "Bridge signing-certificate SHA-256 is required; pass --signer-certificate-sha256",
        )?;
    let certificate = certificate.trim().to_ascii_lowercase();
    if certificate.len() != 64 || !certificate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Bridge signing-certificate SHA-256 is invalid")
    }

    terminal::note(
        "Registering the ego-browser Device Client with the agent-remote credential store.",
    );
    run_device_client_with_token(
        [
            OsString::from("register"),
            OsString::from("--server"),
            OsString::from(server_url),
            OsString::from("--token-stdin"),
            OsString::from("--signer-certificate-sha256"),
            OsString::from(certificate),
        ],
        &token,
    )
    .await?;
    terminal::success_line("Ego-browser Device Client registered");
    Ok(())
}

async fn status(paths: AppPaths, args: EgoBrowserStatusArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let devices = client.list_ego_browser_devices(&token).await?;
    let bindings = client.list_ego_browser_bindings(&token).await?;
    persist_bindings(&paths, &server_url, &bindings)?;

    if let Some(reference) = args.binding {
        let binding_id = resolve_binding_reference(&bindings, &reference)?;
        let binding = client.get_ego_browser_binding(&token, &binding_id).await?;
        persist_binding(&paths, &server_url, &binding)?;
        print_binding(&binding);
        let requests = client
            .list_ego_browser_requests(&token, &binding_id)
            .await?;
        ensure_requests_for_binding(&requests, &binding_id)?;
        terminal::section("Active Ego Browser Requests");
        render_requests(&requests, args.no_trunc);
        return Ok(());
    }

    terminal::section("Ego Browser Devices");
    if devices.is_empty() {
        terminal::note("No independent ego-browser Device Client is registered.");
    } else {
        let mut table = Table::new(["ID", "STATUS", "PROFILE", "BRIDGE", "EGO RUNTIME", "SKILL"]);
        for device in devices {
            table.row([
                display_id(&device.id, args.no_trunc),
                device.status,
                device.release_profile,
                device.bridge_version.unwrap_or_else(|| "-".to_string()),
                device
                    .local_ego_browser_runtime_version
                    .or(device.ego_lite_runtime_version)
                    .unwrap_or_else(|| "-".to_string()),
                device.skill_version.unwrap_or_else(|| "-".to_string()),
            ]);
        }
        table.render();
    }

    terminal::section("Ego Browser Bindings");
    render_bindings(&bindings, args.no_trunc);
    Ok(())
}

async fn list(paths: AppPaths, args: ListArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let bindings = ApiClient::new(server_url.clone())?
        .list_ego_browser_bindings(&token)
        .await?;
    persist_bindings(&paths, &server_url, &bindings)?;
    render_bindings(&bindings, args.no_trunc);
    Ok(())
}

async fn requests(paths: AppPaths, args: EgoBrowserRequestsArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let bindings = client.list_ego_browser_bindings(&token).await?;
    let binding_id = resolve_binding_reference(&bindings, &args.binding)?;
    persist_bindings(&paths, &server_url, &bindings)?;
    let requests = client
        .list_ego_browser_requests(&token, &binding_id)
        .await?;
    ensure_requests_for_binding(&requests, &binding_id)?;
    render_requests(&requests, args.no_trunc);
    Ok(())
}

async fn cancel_request(paths: AppPaths, args: EgoBrowserCancelRequestArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let bindings = client.list_ego_browser_bindings(&token).await?;
    let binding_id = resolve_binding_reference(&bindings, &args.binding)?;
    let requests = client
        .list_ego_browser_requests(&token, &binding_id)
        .await?;
    ensure_requests_for_binding(&requests, &binding_id)?;
    let ledger_id = resolve_id(
        &args.request,
        "ego-browser request",
        requests.iter().map(|request| request.id.as_str()),
    )?;
    let request = requests
        .iter()
        .find(|request| request.id == ledger_id)
        .context("resolved ego-browser request disappeared")?;
    if !args.yes
        && !super::prompt_yes_no(&format!(
            "Cancel browser request {}? [y/N] ",
            short_id(&request.id)
        ))?
    {
        terminal::note("Ego-browser request cancellation cancelled.");
        return Ok(());
    }
    let result = client
        .cancel_ego_browser_request(
            &token,
            &binding_id,
            &request.request_id,
            request.generation,
            request.sequence,
        )
        .await?;
    if result.status == "completed" {
        terminal::note(format!(
            "Ego-browser request {} completed before cancellation.",
            short_id(&result.id)
        ));
    } else {
        terminal::success_line(format!(
            "Ego-browser request {} is {}.",
            short_id(&result.id),
            result.status
        ));
    }
    Ok(())
}

async fn claim(args: EgoBrowserClaimArgs) -> Result<()> {
    Uuid::parse_str(&args.tool_session).context("tool session must be a full UUID")?;
    if !args.yes {
        terminal::warning_line(FULL_TRUST_WARNING);
        if !super::prompt_yes_no(
            "Authorize this exact tool session for full-trust control? [y/N] ",
        )? {
            terminal::note("Ego-browser claim cancelled.");
            return Ok(());
        }
    }
    run_device_client([
        OsString::from("claim"),
        OsString::from(args.tool_session),
        OsString::from("--confirm"),
    ])
    .await
}

async fn resume(paths: AppPaths, args: EgoBrowserLifecycleArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let bindings = client.list_ego_browser_bindings(&token).await?;
    let binding_id = resolve_binding_reference(&bindings, &args.binding)?;
    if !args.yes {
        terminal::warning_line(FULL_TRUST_WARNING);
        if !super::prompt_yes_no("Reauthorize full-trust control for this binding? [y/N] ")? {
            terminal::note("Ego-browser resume cancelled.");
            return Ok(());
        }
    }
    run_device_client([
        OsString::from("resume"),
        OsString::from(binding_id),
        OsString::from("--generation"),
        OsString::from(args.generation.to_string()),
        OsString::from("--confirm"),
    ])
    .await
}

async fn lifecycle(paths: AppPaths, action: &str, args: EgoBrowserLifecycleArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let bindings = client.list_ego_browser_bindings(&token).await?;
    let binding_id = resolve_binding_reference(&bindings, &args.binding)?;
    if !args.yes {
        let prompt = match action {
            "pause" => "Pause this binding and invalidate its current generation? [y/N] ",
            "stop" => "Stop this binding and all supervised browser execution? [y/N] ",
            "revoke" => "Permanently revoke this browser binding? [y/N] ",
            _ => bail!("unsupported ego-browser lifecycle action"),
        };
        if !super::prompt_yes_no(prompt)? {
            terminal::note(format!("Ego-browser {action} cancelled."));
            return Ok(());
        }
    }
    let binding = client
        .control_ego_browser_binding(
            &token,
            &binding_id,
            args.generation,
            action,
            &format!("cli_{action}"),
        )
        .await?;
    persist_binding(&paths, &server_url, &binding)?;
    terminal::success_line(format!(
        "Ego-browser binding {} is {} (generation {})",
        short_id(&binding.id),
        binding.status,
        binding.generation
    ));
    Ok(())
}

async fn run_device_client<const N: usize>(args: [OsString; N]) -> Result<()> {
    let executable = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from("ego-browser-device"));
    let status = ProcessCommand::new(&executable)
        .args(args)
        .status()
        .await
        .with_context(|| {
            format!(
                "failed to launch {}; install the independent agent-remote-ego-browser Device Client",
                executable.to_string_lossy()
            )
        })?;
    if !status.success() {
        bail!("independent ego-browser Device Client exited with {status}")
    }
    Ok(())
}

async fn run_device_client_with_token<const N: usize>(
    args: [OsString; N],
    token: &str,
) -> Result<()> {
    if token.is_empty() {
        bail!("agent-remote credential store returned an empty token")
    }
    let executable = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from("ego-browser-device"));
    let mut child = ProcessCommand::new(&executable)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "failed to launch {}; install the independent agent-remote-ego-browser Device Client",
                executable.to_string_lossy()
            )
        })?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to open the Device Client token pipe")?;
    stdin
        .write_all(token.as_bytes())
        .await
        .context("failed to pass the credential to the Device Client")?;
    drop(stdin);
    let status = child
        .wait()
        .await
        .context("failed waiting for the Device Client")?;
    if !status.success() {
        bail!("independent ego-browser Device Client exited with {status}")
    }
    Ok(())
}

async fn load_control_token(paths: &AppPaths) -> Result<(String, String)> {
    load_control_token_for_server(paths, None).await
}

async fn load_control_token_for_server(
    paths: &AppPaths,
    requested_server: Option<&str>,
) -> Result<(String, String)> {
    let config = Config::load(paths)?;
    let configured_server = config
        .server_url
        .clone()
        .context("not logged in: server URL is missing")?;
    let configured_server = crate::normalize_server_url(&configured_server);
    if configured_server.is_empty() {
        bail!("configured agent-remote server URL is empty")
    }
    let server_url = requested_server
        .map(crate::normalize_server_url)
        .unwrap_or_else(|| configured_server.clone());
    if server_url != configured_server {
        bail!(
            "requested server URL does not match the configured agent-remote server ({configured_server})"
        )
    }
    if let Some(token) = SecretStore::new(paths.clone()).get_secret(&user_token_key(&server_url))? {
        return Ok((server_url, token));
    }
    let (device_server, _device_id, token) = load_device_token(paths).await?;
    if crate::normalize_server_url(&device_server) != server_url {
        bail!("stored agent-remote credential is bound to a different server")
    }
    Ok((server_url, token))
}

fn resolve_binding_reference(
    bindings: &[EgoBrowserBindingData],
    reference: &str,
) -> Result<String> {
    resolve_id(
        reference,
        "ego-browser binding",
        bindings.iter().map(|binding| binding.id.as_str()),
    )
}

fn display_id(value: &str, no_trunc: bool) -> String {
    if no_trunc {
        value.to_string()
    } else {
        short_id(value)
    }
}

fn render_bindings(bindings: &[EgoBrowserBindingData], no_trunc: bool) {
    if bindings.is_empty() {
        terminal::note("No ego-browser bindings found.");
        return;
    }
    let mut table = Table::new(["ID", "SESSION", "DEVICE", "STATUS", "GEN", "LEASE"]);
    for binding in bindings {
        table.row([
            display_id(&binding.id, no_trunc),
            display_id(&binding.tool_session_id, no_trunc),
            display_id(&binding.ego_browser_device_id, no_trunc),
            binding.status.clone(),
            binding.generation.to_string(),
            binding
                .lease_until
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ]);
    }
    table.render();
}

fn render_requests(requests: &[EgoBrowserRequestData], no_trunc: bool) {
    if requests.is_empty() {
        terminal::note("No active ego-browser requests found.");
        return;
    }
    let mut table = Table::new([
        "ID", "REQUEST", "TYPE", "GEN", "SEQ", "BYTES", "STATUS", "STARTED",
    ]);
    for request in requests {
        table.row([
            display_id(&request.id, no_trunc),
            if no_trunc {
                request.request_id.clone()
            } else {
                request.request_id.chars().take(12).collect()
            },
            request.message_type.clone(),
            request.generation.to_string(),
            request.sequence.to_string(),
            request.payload_bytes.to_string(),
            request.status.clone(),
            request.created_at.clone(),
        ]);
    }
    table.render();
}

fn ensure_requests_for_binding(requests: &[EgoBrowserRequestData], binding_id: &str) -> Result<()> {
    if requests
        .iter()
        .any(|request| request.binding_id != binding_id)
    {
        bail!("control plane returned an ego-browser request for a different binding")
    }
    Ok(())
}

fn print_binding(binding: &EgoBrowserBindingData) {
    terminal::section("Ego Browser Binding");
    Details::new()
        .field("ID", &binding.id)
        .status("Status", &binding.status)
        .field("Generation", binding.generation)
        .field("Tool session", &binding.tool_session_id)
        .field("Device", &binding.ego_browser_device_id)
        .field("Node", &binding.node_id)
        .field("Relay", &binding.relay_binding_kind)
        .field("Authorization", &binding.authorization_mode)
        .field("Release profile", &binding.release_profile)
        .field("Protocol", &binding.bridge_protocol_version)
        .field(
            "Local runtime",
            binding
                .local_runtime_version
                .as_deref()
                .unwrap_or("unavailable"),
        )
        .field(
            "ego lite runtime",
            binding
                .ego_lite_runtime_version
                .as_deref()
                .unwrap_or("unavailable"),
        )
        .field(
            "Skill",
            binding.skill_version.as_deref().unwrap_or("unavailable"),
        )
        .field("Allowlist revision", binding.allowlist_revision)
        .field("Lease health", &binding.lease_health)
        .field("Lease until", binding.lease_until.as_deref().unwrap_or("-"))
        .field(
            "Learning bundle",
            binding
                .learning_bundle_digest
                .as_deref()
                .unwrap_or("unavailable"),
        )
        .field("Connected", binding.connected_at.as_deref().unwrap_or("no"))
        .field("Stop reason", binding.stop_reason.as_deref().unwrap_or("-"))
        .render();
    terminal::warning_line(FULL_TRUST_WARNING);
}

fn persist_bindings(
    paths: &AppPaths,
    server_url: &str,
    bindings: &[EgoBrowserBindingData],
) -> Result<()> {
    for binding in bindings {
        persist_binding(paths, server_url, binding)?;
    }
    Ok(())
}

fn persist_binding(
    paths: &AppPaths,
    server_url: &str,
    binding: &EgoBrowserBindingData,
) -> Result<()> {
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    state.upsert_ego_browser_binding(&LocalEgoBrowserBinding {
        id: binding.id.clone(),
        server_url: server_url.to_string(),
        ego_browser_device_id: binding.ego_browser_device_id.clone(),
        tool_session_id: binding.tool_session_id.clone(),
        node_id: binding.node_id.clone(),
        status: binding.status.clone(),
        generation: binding.generation,
        relay_binding_kind: binding.relay_binding_kind.clone(),
        lease_until: binding.lease_until.clone(),
    })
}
