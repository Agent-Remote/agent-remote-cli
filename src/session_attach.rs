//! Native session attachment bound to a reviewed server, device and full session UUID.

pub mod attachment;
mod validation;

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::time::{sleep, timeout, Instant};

use crate::api::session_attach::{AuthorizationStatus, SessionAttachData};
use crate::api::{ApiClient, AttachSessionData};
use crate::config::{AppPaths, Config};

const NODE_UPGRADE: &str = "Exact session connection requires an updated Node and SSH gateway; upgrade both components and wait for a fresh Node heartbeat before reconnecting.";

/// Only public reviewed identity is accepted. HOME is selected by the caller's AppPaths.
pub struct ExactSessionAttach<'a> {
    pub session_id: &'a str,
    pub expected_server: &'a str,
    pub expected_device: &'a str,
    pub print_only: bool,
}

pub async fn run(paths: &AppPaths, input: &ExactSessionAttach<'_>) -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            biased;
            _ = terminate.recv() => bail!("Session connection canceled; any authorization outcome may be unknown."),
            result = run_inner(paths, input) => result,
        }
    }
    #[cfg(not(unix))]
    run_inner(paths, input).await
}

async fn run_inner(paths: &AppPaths, input: &ExactSessionAttach<'_>) -> Result<()> {
    validation::input(input)?;
    let authorized = timeout(Duration::from_secs(90), authorize(paths, input))
        .await
        .map_err(|_| anyhow!("Session authorization timed out; its outcome may be unknown. Refresh session status before reconnecting."))??;
    // Credentials and both publication locks have been dropped. No current
    // configuration is consulted by the long-lived terminal.
    if input.print_only {
        println!("ssh {}-o ClearAllForwardings=yes -x -tt -p {} {}@{} agent-remote-attach --session {} --expected-device {}",
            if authorized.forward_ssh_agent { "-A " } else { "-a " },
            authorized.ssh_port, authorized.ssh_user, authorized.ssh_host,
            authorized.session_id, input.expected_device);
        return Ok(());
    }
    // Exact sessions use a separate, identity-bound transfer gateway. The
    // legacy account receiver is deliberately unavailable on this path.
    let attachment =
        if std::env::var_os("AGENT_REMOTE_ATTACHMENTS").is_none_or(|value| value != "0") {
            Some(crate::attachments::AttachmentContext::new_exact(
                &authorized,
                input.expected_device,
            )?)
        } else {
            None
        };
    let cleanup = attachment.clone();
    let result = crate::ssh::execute_attach_with_context(paths, &authorized, attachment).await;
    if let Some(attachment) = cleanup {
        if let Err(error) = attachment.cleanup(paths).await {
            crate::terminal::warning_line(format!(
                "Exact attachment cleanup was not confirmed; retry the transfer cleanup: {error:#}"
            ));
        }
    }
    result
}

async fn authorize(paths: &AppPaths, input: &ExactSessionAttach<'_>) -> Result<AttachSessionData> {
    let initial =
        Config::load_strict(paths).map_err(|_| anyhow!("Client configuration is unavailable."))?;
    if initial.server_url.as_deref() != Some(input.expected_server)
        || initial.active_device_id.as_deref() != Some(input.expected_device)
    {
        bail!("Client configuration changed; refresh session status before reconnecting.");
    }
    let login_guard = crate::auth::login::lock(paths)
        .await
        .map_err(|_| anyhow!("Client authentication is busy or unavailable."))?;
    // Hold configuration publication before token refresh, not merely before
    // SSH authorization. Login/logout acquire their lock in this same order.
    let _config_guard = crate::config::write_lock_existing(paths)
        .map_err(|_| anyhow!("Client configuration is busy or unavailable."))?;
    if Config::load_strict(paths).ok().as_ref() != Some(&initial) {
        bail!("Client configuration changed; refresh session status before reconnecting.");
    }
    let token = crate::auth::load_device_token_strict_locked(
        paths,
        &login_guard,
        &initial,
        &AtomicBool::new(false),
    )
    .await
    .map_err(|_| anyhow!("Current device credentials are unavailable."))?;
    let client = ApiClient::new(token.server_url.clone())
        .map_err(|_| anyhow!("Client server configuration is invalid."))?;
    let mut response = client
        .authorize_session_attach(
            token.token.as_str(),
            input.session_id,
            input.expected_device,
        )
        .await
        .map_err(submission_error)?;
    validation::response(&response, input)?;
    let original = response.clone();
    let deadline = Instant::now() + Duration::from_secs(30.min(response.expires_in));
    loop {
        match response.authorization_task_status {
            AuthorizationStatus::Succeeded => break,
            AuthorizationStatus::Failed
            | AuthorizationStatus::Cancelled
            | AuthorizationStatus::Expired => {
                bail!("Session SSH authorization did not complete; refresh session status before reconnecting.");
            }
            AuthorizationStatus::Pending
            | AuthorizationStatus::Leased
            | AuthorizationStatus::Running => {}
        }
        if Instant::now() >= deadline {
            bail!("Session SSH authorization is still pending; refresh session status before reconnecting.");
        }
        tokio::time::timeout_at(deadline, sleep(Duration::from_millis(500)))
            .await
            .map_err(|_| {
                anyhow!("Session authorization observation timed out; no request was replayed.")
            })?;
        response = tokio::time::timeout_at(
            deadline,
            client.session_attach_status(
                token.token.as_str(),
                input.session_id,
                input.expected_device,
                &original.authorization_task_id,
                &original.authorization_task_record_id,
            ),
        )
        .await
        .map_err(|_| {
            anyhow!("Session authorization observation timed out; no request was replayed.")
        })?
        .map_err(|error| {
            if unsupported_gateway(&error) {
                anyhow!(NODE_UPGRADE)
            } else {
                anyhow!("Session authorization could not be observed; no request was replayed.")
            }
        })?;
        validation::response(&response, input)?;
        if !validation::same_target(&original, &response) {
            bail!(
                "Session authorization target changed; refresh session status before reconnecting."
            );
        }
    }
    Ok(attach(response))
}

fn unsupported_gateway(error: &crate::api::ApiError) -> bool {
    error.status_code() == Some(409) && error.code() == Some("NODE_SESSION_ATTACH_UNSUPPORTED")
}

fn submission_error(error: crate::api::ApiError) -> anyhow::Error {
    if unsupported_gateway(&error) {
        return anyhow!(NODE_UPGRADE);
    }
    match error.status_code() {
        Some(401 | 403) => anyhow!("Session connection was not authorized for this device."),
        Some(404 | 405 | 501) => anyhow!(
            "Exact session connection is unavailable; check the session and Server version."
        ),
        Some(status) if (400..500).contains(&status) && !matches!(status, 408 | 429) => {
            anyhow!("Session connection was rejected; refresh session status before reconnecting.")
        }
        _ => anyhow!(
            "Session authorization outcome is unknown; refresh session status before reconnecting."
        ),
    }
}

fn attach(value: SessionAttachData) -> AttachSessionData {
    AttachSessionData {
        command_args: vec![
            "agent-remote-attach".into(),
            "--session".into(),
            value.session_id.clone(),
            "--expected-device".into(),
            value.device_id,
        ],
        session_id: value.session_id,
        node_id: value.node_id,
        node_wireguard_ip: value.ssh_host.clone(),
        ssh_host: value.ssh_host,
        ssh_port: value.ssh_port,
        ssh_user: value.ssh_user,
        tmux_session_name: value.tmux_session_name,
        ssh_command: String::new(),
        forward_ssh_agent: value.forward_ssh_agent,
        authorization_task_id: value.authorization_task_id,
        authorization_task_status: "succeeded".into(),
        expires_in: value.expires_in,
    }
}

#[cfg(test)]
#[path = "../tests/unit/src/session_attach.rs"]
mod tests;
