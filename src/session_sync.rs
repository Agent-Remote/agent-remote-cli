//! Bounded synchronization readiness for tool launchers.
use crate::mutagen::{binary_path, configured_mutagen_command, session_name};
use crate::{api::SyncSessionData, config::AppPaths};
use anyhow::{bail, Context, Result};
use std::time::Duration;

/// Waits for a synchronization cycle before a new remote process reads files.
/// Cancelling the local wait does not stop the persistent Mutagen session.
pub async fn flush_before_launch(
    paths: &AppPaths,
    sync: &SyncSessionData,
    dry_run: bool,
) -> Result<()> {
    let name = session_name(sync)?;
    if dry_run {
        return Ok(());
    }
    let binary = binary_path(paths);
    let directory = binary
        .parent()
        .context("Mutagen binary has no parent directory")?;
    let mut command =
        tokio::process::Command::from(configured_mutagen_command(paths, &binary, directory)?);
    command.args(["sync", "flush", name]);
    tokio::select! {
        result = wait_for_flush(command, Duration::from_secs(30)) => result,
        _ = tokio::signal::ctrl_c() => bail!("workspace sync wait cancelled; Claude was not started"),
    }
}

async fn wait_for_flush(mut command: tokio::process::Command, limit: Duration) -> Result<()> {
    // Mutagen output may include file names or endpoints. Keep errors bounded
    // and do not retain an unbounded progress stream.
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(limit, command.status()).await
        .context("workspace sync timed out; Claude was not started. Check agent-remote sync status and retry")?
        .context("failed to wait for workspace sync; Claude was not started")?;
    if !status.success() {
        bail!("workspace sync did not complete; Claude was not started. Check agent-remote sync status and resolve conflicts before retrying");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[tokio::test]
    async fn launch_flush_requires_success_and_bounds_the_wait() {
        use std::time::Duration;
        let mut success = tokio::process::Command::new("/bin/sh");
        success.args(["-c", "exit 0"]);
        assert!(super::wait_for_flush(success, Duration::from_secs(1))
            .await
            .is_ok());
        let mut failed = tokio::process::Command::new("/bin/sh");
        failed.args(["-c", "exit 3"]);
        let error = super::wait_for_flush(failed, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Claude was not started"));
        let mut blocked = tokio::process::Command::new("/bin/sh");
        blocked.args(["-c", "exec sleep 30"]);
        let started = std::time::Instant::now();
        let error = super::wait_for_flush(blocked, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
