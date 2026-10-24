//! Opt-in end-to-end exact attachment transfer.
//!
//! This test is intentionally ignored by default. It must run against a real
//! authenticated device, Server, Node and SSH forced-command gateway. The
//! ordinary contract tests use HTTP/PTY fixtures and are not evidence for this
//! path.

use agent_remote_cli::{
    api::{session_attach::AuthorizationStatus, ApiClient, AttachSessionData},
    attachments::{AttachmentContext, ClipboardPayload},
    auth::load_device_token,
    config::AppPaths,
};
use anyhow::{ensure, Context, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[tokio::test]
#[ignore = "requires AGENT_REMOTE_EXACT_ATTACHMENT_TEST_SESSION and a real Server/Node SSH gateway"]
async fn real_exact_attachment_upload_and_cleanup() -> Result<()> {
    let session_id = std::env::var("AGENT_REMOTE_EXACT_ATTACHMENT_TEST_SESSION")?;
    let expected_device = std::env::var("AGENT_REMOTE_EXACT_ATTACHMENT_TEST_DEVICE")?;
    let paths = AppPaths::new(None)?;
    let (server, device, token) = load_device_token(&paths).await?;
    ensure!(
        device == expected_device,
        "selected device changed during test setup"
    );
    let client = ApiClient::new(server)?;
    let mut authorized = client
        .authorize_session_attach(&token, &session_id, &expected_device)
        .await?;
    let original_task = (
        authorized.authorization_task_id.clone(),
        authorized.authorization_task_record_id.clone(),
    );
    let deadline = Instant::now() + Duration::from_secs(30.min(authorized.expires_in));
    while authorized.authorization_task_status != AuthorizationStatus::Succeeded {
        ensure!(
            !matches!(
                authorized.authorization_task_status,
                AuthorizationStatus::Failed
                    | AuthorizationStatus::Cancelled
                    | AuthorizationStatus::Expired
            ),
            "exact session authorization ended as {:?}",
            authorized.authorization_task_status
        );
        ensure!(
            Instant::now() < deadline,
            "exact session authorization timed out"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        let observed = client
            .session_attach_status(
                &token,
                &session_id,
                &expected_device,
                &original_task.0,
                &original_task.1,
            )
            .await?;
        ensure!(
            observed.session_id == session_id
                && observed.device_id == expected_device
                && observed.authorization_task_id == original_task.0
                && observed.authorization_task_record_id == original_task.1,
            "exact session authorization target changed during live test"
        );
        authorized = observed;
    }
    let attach = AttachSessionData {
        session_id: authorized.session_id,
        node_id: authorized.node_id,
        node_wireguard_ip: authorized.ssh_host.clone(),
        ssh_host: authorized.ssh_host,
        ssh_port: authorized.ssh_port,
        ssh_user: authorized.ssh_user,
        tmux_session_name: authorized.tmux_session_name,
        command_args: Vec::new(),
        ssh_command: String::new(),
        forward_ssh_agent: authorized.forward_ssh_agent,
        authorization_task_id: authorized.authorization_task_id,
        authorization_task_status: "succeeded".to_owned(),
        expires_in: authorized.expires_in,
    };
    let context = AttachmentContext::new_exact(&attach, &expected_device)?;
    let local = tempfile::tempdir()?;
    let source = local.path().join("exact transfer fixture.txt");
    std::fs::write(&source, b"agent-remote exact attachment live fixture")?;
    let uploaded = context
        .stage_payload(
            &paths,
            ClipboardPayload::Files(vec![PathBuf::from(&source)]),
        )
        .await?;
    ensure!(uploaded.len() == 1, "expected one acknowledged upload");
    let remote = &uploaded[0];
    ensure!(
        remote.contains(".agent-remote-attachments") && !remote.contains(".."),
        "gateway returned an unsafe/non-derived path: {remote}"
    );
    context
        .cleanup(&paths)
        .await
        .context("exact attachment cleanup was not confirmed")?;
    println!("exact attachment upload and cleanup passed for one file");
    Ok(())
}
