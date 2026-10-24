//! Native terminal connection to one confirmed account-binding generation.

mod validation;

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::time::{sleep, timeout, Instant};

use crate::api::{binding_attach::BindingAttachData, ApiClient, AttachSessionData};
use crate::cli::AccountAttachArgs;
use crate::config::{AppPaths, Config};

const NODE_UPGRADE: &str = "Exact binding connection requires an updated Node and SSH gateway; upgrade both components and wait for a fresh Node heartbeat before reconnecting.";

/// A binding is not a normal tool session. Only the fixed, generation-bound
/// forced command is sent over SSH; a server command string is never executed.
pub async fn run(paths: &AppPaths, input: &AccountAttachArgs) -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            biased;
            _ = terminate.recv() => bail!("Binding connection canceled; any authorization outcome may be unknown."),
            result = run_inner(paths, input) => result,
        }
    }
    #[cfg(not(unix))]
    run_inner(paths, input).await
}

async fn run_inner(paths: &AppPaths, input: &AccountAttachArgs) -> Result<()> {
    if !validation::account(&input.account_id)
        || !validation::binding(&input.binding_session, &input.account_id)
        || input.expected_server.is_some() != input.expected_device.is_some()
    {
        bail!("An exact account UUID and its binding session ID are required.");
    }
    let authorized = timeout(Duration::from_secs(90), authorize(paths, input))
        .await
        .map_err(|_| {
            anyhow!("Binding authorization timed out; refresh account status before reconnecting.")
        })??;
    // Authorization guards and credentials are dropped before the long-lived
    // terminal starts. The Node independently verifies the exact generation.
    crate::ssh::execute_attach(paths, &attach(authorized)).await
}

async fn authorize(paths: &AppPaths, input: &AccountAttachArgs) -> Result<BindingAttachData> {
    let initial =
        Config::load_strict(paths).map_err(|_| anyhow!("Client configuration is unavailable."))?;
    if input.expected_server.is_some()
        && (initial.server_url != input.expected_server
            || initial.active_device_id != input.expected_device)
    {
        bail!("Client configuration changed; refresh account status before reconnecting.");
    }
    let login_guard = crate::auth::login::lock(paths)
        .await
        .map_err(|_| anyhow!("Client authentication is busy or unavailable."))?;
    let token = crate::auth::load_device_token_strict_locked(
        paths,
        &login_guard,
        &initial,
        &AtomicBool::new(false),
    )
    .await
    .map_err(|_| anyhow!("Current device credentials are unavailable."))?;
    let _config_guard = crate::config::write_lock(paths)
        .map_err(|_| anyhow!("Client configuration is busy or unavailable."))?;
    if Config::load_strict(paths).ok().as_ref() != Some(&initial) {
        bail!("Client configuration changed; refresh account status before reconnecting.");
    }
    let client = ApiClient::new(token.server_url.clone())
        .map_err(|_| anyhow!("Client server configuration is invalid."))?;
    let mut response = client
        .authorize_binding_attach(
            token.token.as_str(),
            &input.account_id,
            &input.binding_session,
        )
        .await
        .map_err(submission_error)?;
    validation::response(&response, input, &token.device_id)?;
    let original = response.clone();
    let deadline = Instant::now() + Duration::from_secs(30.min(response.expires_in));
    loop {
        match response.authorization_task_status.as_str() {
            "succeeded" => return Ok(response),
            "failed" | "cancelled" | "expired" => {
                bail!("Binding SSH authorization did not complete; refresh account status before reconnecting.");
            }
            "pending" | "leased" | "running" => {}
            _ => bail!("Binding authorization response is incompatible."),
        }
        if Instant::now() >= deadline {
            bail!("Binding SSH authorization is still pending; refresh account status before reconnecting.");
        }
        sleep(Duration::from_millis(500)).await;
        response = tokio::time::timeout_at(
            deadline,
            client.binding_attach_status(
                token.token.as_str(),
                &input.account_id,
                &input.binding_session,
                &original.authorization_task_id,
            ),
        )
        .await
        .map_err(|_| {
            anyhow!("Binding authorization observation timed out; no request was replayed.")
        })?
        .map_err(|error| {
            if error.status_code() == Some(409)
                && error.code() == Some("NODE_BINDING_ATTACH_UNSUPPORTED")
            {
                anyhow!(NODE_UPGRADE)
            } else {
                anyhow!("Binding authorization could not be observed; no request was replayed.")
            }
        })?;
        validation::response(&response, input, &token.device_id)?;
        if !validation::same_target(&original, &response) {
            bail!(
                "Binding authorization target changed; refresh account status before reconnecting."
            );
        }
    }
}

fn submission_error(error: crate::api::ApiError) -> anyhow::Error {
    if error.status_code() == Some(409) && error.code() == Some("NODE_BINDING_ATTACH_UNSUPPORTED") {
        return anyhow!(NODE_UPGRADE);
    }
    match error.status_code() {
        Some(401 | 403) => anyhow!("Binding connection was not authorized for this device."),
        Some(404 | 405 | 501) => anyhow!(
            "Exact binding connection is unavailable; check the account and Server version."
        ),
        Some(status) if (400..500).contains(&status) => {
            anyhow!("Binding connection was rejected; refresh account status before reconnecting.")
        }
        _ => anyhow!(
            "Binding authorization outcome is unknown; refresh account status before reconnecting."
        ),
    }
}

fn attach(value: BindingAttachData) -> AttachSessionData {
    AttachSessionData {
        session_id: value.tool_account_id.clone(),
        node_id: value.node_id,
        node_wireguard_ip: value.ssh_host.clone(),
        ssh_host: value.ssh_host,
        ssh_port: value.ssh_port,
        ssh_user: value.ssh_user,
        tmux_session_name: value.tmux_session_name,
        command_args: vec![
            "agent-remote-attach".into(),
            "--binding".into(),
            value.tool_account_id,
            "--binding-session".into(),
            value.binding_session_id,
        ],
        ssh_command: String::new(),
        forward_ssh_agent: false,
        authorization_task_id: value.authorization_task_id,
        authorization_task_status: value.authorization_task_status,
        expires_in: value.expires_in,
    }
}

#[cfg(test)]
#[path = "../tests/unit/src/account_binding.rs"]
mod tests;
