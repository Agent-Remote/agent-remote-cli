use std::ffi::OsString;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command as ProcessCommand;
use uuid::Uuid;

use crate::api::{ApiClient, EgoBrowserBindingData, EgoBrowserRequestData};
use crate::auth::load_device_token;
use crate::cli::{
    EgoBrowserCancelRequestArgs, EgoBrowserClaimArgs, EgoBrowserCommand, EgoBrowserDeleteArgs,
    EgoBrowserLifecycleArgs, EgoBrowserRegisterArgs, EgoBrowserRequestsArgs, EgoBrowserStatusArgs,
    ListArgs,
};
use crate::config::{AppPaths, Config};
use crate::identifiers::{resolve_id, short_id};
use crate::local_state::{LocalEgoBrowserBinding, LocalState};
use crate::secrets::{user_token_key, SecretStore};
use crate::terminal::{self, Details, Table};

const FULL_TRUST_WARNING: &str = "Remote fclaude will execute complete ego-browser heredoc scripts as the current macOS user without an App Sandbox. Scripts can access that user's files, environment, network, browser login data, Node modules, subprocesses, and other tabs or Task Spaces, and can send data remotely. Stopping terminates supervised work only; it cannot roll back side effects or guarantee cleanup of deliberately detached processes.";
const SAFE_DEVICE_CLIENT_ERROR_CODES: &[&str] = &[
    "credential_missing",
    "credential_invalid_path",
    "credential_unsafe_permissions",
    "credential_malformed",
    "policy_invalid",
    "policy_conflict",
    "rotation_conflict",
    "learning_bundle_invalid",
    "credential_too_large",
    "control_plane_error",
    "io_error",
    "operation_failed",
];

/// Run one independent ego-browser control command.
pub async fn run(paths: AppPaths, command: EgoBrowserCommand) -> Result<()> {
    match command {
        EgoBrowserCommand::Register(args) => register(paths, args).await,
        EgoBrowserCommand::Status(args) => status(paths, args).await,
        EgoBrowserCommand::List(args) => list(paths, args).await,
        EgoBrowserCommand::Requests(args) => requests(paths, args).await,
        EgoBrowserCommand::CancelRequest(args) => cancel_request(paths, args).await,
        EgoBrowserCommand::Claim(args) => claim(paths, args).await,
        EgoBrowserCommand::Pause(args) => lifecycle(paths, "pause", args).await,
        EgoBrowserCommand::Resume(args) => resume(paths, args).await,
        EgoBrowserCommand::Stop(args) => lifecycle(paths, "stop", args).await,
        EgoBrowserCommand::Revoke(args) => lifecycle(paths, "revoke", args).await,
        EgoBrowserCommand::DeleteDevice(args) => delete_device(paths, args).await,
        EgoBrowserCommand::DeleteBinding(args) => delete_binding(paths, args).await,
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
        print_binding(&binding, args.no_trunc);
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

async fn claim(paths: AppPaths, args: EgoBrowserClaimArgs) -> Result<()> {
    let tool_session_id = if let Some(canonical_id) = canonical_full_uuid(&args.tool_session) {
        canonical_id
    } else {
        let (server_url, token) = load_control_token(&paths).await?;
        let sessions = ApiClient::new(server_url)?
            .list_sessions(&token, Some("claude"), &[])
            .await?;
        resolve_id(
            &args.tool_session,
            "Claude tool session",
            sessions.iter().map(|session| session.id.as_str()),
        )?
    };
    if !args.yes {
        terminal::warning_line(FULL_TRUST_WARNING);
        if !super::prompt_yes_no(&format!(
            "Authorize Claude session {} for full-trust control? [y/N] ",
            short_id(&tool_session_id)
        ))? {
            terminal::note("Ego-browser claim cancelled.");
            return Ok(());
        }
    }
    run_device_client([
        OsString::from("claim"),
        OsString::from(tool_session_id.clone()),
        OsString::from("--confirm"),
    ])
    .await?;
    terminal::success_line(format!(
        "Ego-browser claim submitted for Claude session {}",
        short_id(&tool_session_id)
    ));
    Ok(())
}

fn canonical_full_uuid(value: &str) -> Option<String> {
    Uuid::parse_str(value).ok().map(|id| id.to_string())
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
        OsString::from(binding_id.clone()),
        OsString::from("--generation"),
        OsString::from(args.generation.to_string()),
        OsString::from("--confirm"),
    ])
    .await?;
    terminal::success_line(format!(
        "Ego-browser binding {} reauthorization submitted",
        short_id(&binding_id)
    ));
    Ok(())
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

async fn delete_device(paths: AppPaths, args: EgoBrowserDeleteArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let devices = client.list_ego_browser_devices(&token).await?;
    let device_id = resolve_id(
        &args.id,
        "ego-browser device",
        devices.iter().map(|device| device.id.as_str()),
    )?;
    let device = devices
        .iter()
        .find(|device| device.id == device_id)
        .context("resolved ego-browser device disappeared")?;
    if device.status != "revoked" {
        bail!(
            "ego-browser device {} must be revoked before deletion",
            short_id(&device.id)
        );
    }
    if !args.yes
        && !super::prompt_yes_no(&format!(
            "Permanently delete revoked ego-browser device {}? [y/N] ",
            short_id(&device.id)
        ))?
    {
        terminal::note("Ego-browser device deletion cancelled.");
        return Ok(());
    }
    client
        .delete_ego_browser_device(&token, &device_id)
        .await
        .context("failed to delete ego-browser device")?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    state.delete_ego_browser_bindings_for_device(&server_url, &device_id)?;
    terminal::success_line(format!(
        "Deleted ego-browser device {}",
        short_id(&device_id)
    ));
    Ok(())
}

async fn delete_binding(paths: AppPaths, args: EgoBrowserDeleteArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let bindings = client.list_ego_browser_bindings(&token).await?;
    let binding_id = resolve_binding_reference(&bindings, &args.id)?;
    let binding = bindings
        .iter()
        .find(|binding| binding.id == binding_id)
        .context("resolved ego-browser binding disappeared")?;
    if !terminal_statuses().contains(&binding.status.as_str()) {
        bail!(
            "ego-browser binding {} must be stopped or revoked before deletion",
            short_id(&binding.id)
        );
    }
    if !args.yes
        && !super::prompt_yes_no(&format!(
            "Permanently delete ego-browser binding {}? [y/N] ",
            short_id(&binding.id)
        ))?
    {
        terminal::note("Ego-browser binding deletion cancelled.");
        return Ok(());
    }
    client
        .delete_ego_browser_binding(&token, &binding_id)
        .await
        .context("failed to delete ego-browser binding")?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    state.delete_ego_browser_binding(&server_url, &binding_id)?;
    terminal::success_line(format!(
        "Deleted ego-browser binding {}",
        short_id(&binding_id)
    ));
    Ok(())
}

fn terminal_statuses() -> &'static [&'static str] {
    &["stopped", "expired", "failed", "revoked"]
}

async fn run_device_client<const N: usize>(args: [OsString; N]) -> Result<()> {
    let executable = device_client_executable();
    let output = ProcessCommand::new(&executable)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| device_client_launch_context(&executable))?;
    finish_device_client(output)
}

async fn run_device_client_with_token<const N: usize>(
    args: [OsString; N],
    token: &str,
) -> Result<()> {
    if token.is_empty() {
        bail!("agent-remote credential store returned an empty token")
    }
    let executable = device_client_executable();
    let mut child = ProcessCommand::new(&executable)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| device_client_launch_context(&executable))?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to open the Device Client token pipe")?;
    stdin
        .write_all(token.as_bytes())
        .await
        .context("failed to pass the credential to the Device Client")?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .await
        .context("failed waiting for the Device Client")?;
    finish_device_client(output)
}

fn device_client_launch_context(executable: &OsString) -> String {
    format!(
        "failed to launch independent ego-browser Device Client ({}); install the independent agent-remote-ego-browser Device Client",
        executable.to_string_lossy()
    )
}

fn finish_device_client(output: std::process::Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    if let Some(code) = extract_device_client_error_code(&output.stderr, &output.stdout) {
        bail!("independent ego-browser Device Client failed ({code})")
    }
    bail!(
        "independent ego-browser Device Client exited with {}",
        output.status
    )
}

fn extract_device_client_error_code(stderr: &[u8], stdout: &[u8]) -> Option<String> {
    for bytes in [stderr, stdout] {
        let text = String::from_utf8_lossy(bytes);
        for marker in ["error=", "error:", "code="] {
            let mut search_from = 0;
            while search_from < text.len() {
                let Some(relative_start) = text[search_from..].find(marker) else {
                    break;
                };
                let start = search_from + relative_start;
                let value = text[start + marker.len()..]
                    .trim_start()
                    .trim_matches(|character: char| character == '"' || character == '\'');
                let code: String = value
                    .chars()
                    .take_while(|character| {
                        character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
                    })
                    .collect();
                if SAFE_DEVICE_CLIENT_ERROR_CODES.contains(&code.as_str()) {
                    return Some(code);
                }
                search_from = start + marker.len();
            }
        }
    }
    None
}

fn device_client_executable() -> OsString {
    if let Some(executable) =
        std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE").filter(|value| !value.is_empty())
    {
        return executable;
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = crate::platform::user_home_dir() {
        use std::os::unix::fs::PermissionsExt;

        let candidate = home.join(
            "Library/Application Support/Agent Remote Ego Browser/current/bin/ego-browser-device",
        );
        if candidate
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        {
            return candidate.into_os_string();
        }
    }
    OsString::from("ego-browser-device")
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
                short_id(&request.request_id)
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

fn print_binding(binding: &EgoBrowserBindingData, no_trunc: bool) {
    terminal::section("Ego Browser Binding");
    Details::new()
        .field("ID", display_id(&binding.id, no_trunc))
        .status("Status", &binding.status)
        .field("Generation", binding.generation)
        .field(
            "Tool session",
            display_id(&binding.tool_session_id, no_trunc),
        )
        .field(
            "Device",
            display_id(&binding.ego_browser_device_id, no_trunc),
        )
        .field("Node", display_id(&binding.node_id, no_trunc))
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

#[cfg(test)]
mod tests {
    use super::canonical_full_uuid;

    #[test]
    fn canonicalizes_full_uuid_variants_before_delegation() {
        assert_eq!(
            canonical_full_uuid("149AEF7A-BA99-4BD5-A0E9-BAF1A2635C09"),
            Some("149aef7a-ba99-4bd5-a0e9-baf1a2635c09".to_string())
        );
        assert_eq!(
            canonical_full_uuid("149aef7aba994bd5a0e9baf1a2635c09"),
            Some("149aef7a-ba99-4bd5-a0e9-baf1a2635c09".to_string())
        );
    }
}
