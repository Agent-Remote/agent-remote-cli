//! An owned SSH child with stdin-only credentials, bounded transfer and mandatory successful exit.

use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};

use super::{
    stream::{receive, unavailable},
    types::{require, Authorization, Exported, Request},
};
use crate::{api::ApiError, skills::export::ExportBundle};

/// Returns private staging only; command orchestration separately decides whether to publish it.
pub async fn download(
    authorization: Authorization,
    known_hosts: PathBuf,
    output: PathBuf,
) -> Result<(ExportBundle, Exported), ApiError> {
    authorization.validate(
        &authorization.binding.snapshot_id,
        &Request {
            device_id: authorization.device_id.clone(),
            ssh_key_id: authorization.ssh_key_id.clone(),
        },
    )?;
    require(authorization.authorization_task_status == "succeeded")?;
    transfer(authorization, known_hosts, output).await
}

async fn transfer(
    authorization: Authorization,
    known_hosts: PathBuf,
    output: PathBuf,
) -> Result<(ExportBundle, Exported), ApiError> {
    let args = crate::ssh::skill_export_args(
        &authorization.ssh_host,
        authorization.ssh_port,
        &authorization.ssh_user,
        &authorization.binding.snapshot_id,
        &known_hosts,
    );
    let mut child = Command::new(crate::platform::ssh_binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| unavailable())?;
    let result = async {
        let mut input = child.stdin.take().ok_or_else(unavailable)?;
        let grant = serde_json::to_vec(
            &serde_json::json!({"version": 1, "grant": authorization.grant, "recovery_version": 1}),
        )
        .map_err(|_| unavailable())?;
        tokio::time::timeout(Duration::from_secs(10), input.write_all(&grant))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        input.shutdown().await.map_err(|_| unavailable())?;
        drop(input);
        let mut reader = child.stdout.take().ok_or_else(unavailable)?;
        let bundle = receive(&mut reader, &authorization.binding, output).await?;
        let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        require(status.success())?;
        Ok(bundle)
    }
    .await;
    if result.is_err() {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    }
    result
}
