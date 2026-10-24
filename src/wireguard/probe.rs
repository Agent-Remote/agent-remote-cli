//! Fixed, bounded machine-format probe. Captured bytes are never diagnostics.

use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

#[cfg(windows)]
use crate::platform::child_job as windows_job;

pub(super) const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_STDERR: usize = 16 * 1024;

/// Deliberately not Debug or Serialize: wg dump contains private keys and PSKs.
pub(super) struct Dump(pub(super) Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProbeError {
    Failed,
    TimedOut,
    OutputTooLarge,
    Canceled,
}

pub(super) async fn run(path: &Path, cancel: &AtomicBool) -> Result<Dump, ProbeError> {
    run_with_budget(path, cancel, Duration::from_secs(10)).await
}

async fn run_with_budget(
    path: &Path,
    cancel: &AtomicBool,
    budget: Duration,
) -> Result<Dump, ProbeError> {
    if cancel.load(Ordering::Acquire) {
        return Err(ProbeError::Canceled);
    }
    let mut command = Command::new(path);
    command
        .args(["show", "all", "dump"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    command.creation_flags(0x0800_0000 | 0x0000_0004);
    let child = command.spawn().map_err(|_| ProbeError::Failed)?;
    let mut process = Process::new(child);
    #[cfg(windows)]
    {
        process.job = windows_job::attach_and_resume(&process.child);
        if process.job.is_none() {
            process.cleanup().await;
            return Err(ProbeError::Failed);
        }
    }
    let stdout = process.child.stdout.take().ok_or(ProbeError::Failed)?;
    let stderr = process.child.stderr.take().ok_or(ProbeError::Failed)?;
    let capture = async {
        let wait = async { process.child.wait().await.map_err(|_| ProbeError::Failed) };
        let (status, output, ()) =
            tokio::try_join!(wait, read_stdout(stdout), drain_stderr(stderr))?;
        if status.success() {
            Ok(Dump(output))
        } else {
            Err(ProbeError::Failed)
        }
    };
    let canceled = async {
        while !cancel.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    let result = tokio::select! {
        result = capture => result,
        _ = canceled => Err(ProbeError::Canceled),
        _ = tokio::time::sleep(budget) => Err(ProbeError::TimedOut),
    };
    process.cleanup().await;
    if cancel.load(Ordering::Acquire) {
        return Err(ProbeError::Canceled);
    }
    result
}

async fn read_stdout(stream: impl AsyncRead + Unpin) -> Result<Vec<u8>, ProbeError> {
    let mut output = Vec::new();
    stream
        .take(MAX_OUTPUT as u64 + 1)
        .read_to_end(&mut output)
        .await
        .map_err(|_| ProbeError::Failed)?;
    if output.len() > MAX_OUTPUT {
        return Err(ProbeError::OutputTooLarge);
    }
    Ok(output)
}

async fn drain_stderr(mut stream: impl AsyncRead + Unpin) -> Result<(), ProbeError> {
    let mut bytes = [0; 4096];
    let mut count = 0;
    loop {
        let size = stream
            .read(&mut bytes)
            .await
            .map_err(|_| ProbeError::Failed)?;
        if size == 0 {
            return Ok(());
        }
        count += size;
        if count > MAX_STDERR {
            return Err(ProbeError::OutputTooLarge);
        }
    }
}

struct Process {
    child: Child,
    #[cfg(unix)]
    group: Option<i32>,
    #[cfg(windows)]
    job: Option<std::os::windows::io::OwnedHandle>,
}

impl Process {
    fn new(child: Child) -> Self {
        Self {
            #[cfg(unix)]
            group: child.id().and_then(|id| i32::try_from(id).ok()),
            child,
            #[cfg(windows)]
            job: None,
        }
    }

    fn terminate(&mut self) {
        #[cfg(unix)]
        if let Some(group) = self.group.take() {
            unsafe { libc::kill(-group, libc::SIGKILL) };
        }
        #[cfg(windows)]
        drop(self.job.take());
        let _ = self.child.start_kill();
    }

    async fn cleanup(&mut self) {
        self.terminate();
        let _ = tokio::time::timeout(Duration::from_millis(500), self.child.wait()).await;
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(all(test, unix))]
#[path = "../../tests/unit/src/wireguard_probe.rs"]
mod tests;
