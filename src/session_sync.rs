//! Bounded synchronization readiness for tool launchers.
mod verified;
use crate::mutagen::{binary_path, configured_mutagen_command, session_name};
use crate::{api::SyncSessionData, config::AppPaths};
use anyhow::{bail, Context, Result};
use std::time::Duration;
pub use verified::{flush_verified, FlushError, VerifiedFlush};

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
    let (_guard, _) = tokio::select! {
        result = crate::mutagen::desktop::environment::prepare_guard(paths) => result.context(
            "Mutagen environment requires review; run agent-remote deps mutagen-environment, then agent-remote deps mutagen-environment --repair if needed"
        )?,
        _ = tokio::signal::ctrl_c() => bail!("workspace sync wait cancelled; Claude was not started"),
    };
    let binary = binary_path(paths);
    let directory = binary
        .parent()
        .context("Mutagen binary has no parent directory")?;
    let mut command =
        tokio::process::Command::from(configured_mutagen_command(paths, &binary, directory)?);
    command
        .args(["sync", "flush", name])
        .env("MUTAGEN_DISABLE_AUTOSTART", "1");
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
#[path = "../tests/unit/src/session_sync.rs"]
mod tests;
