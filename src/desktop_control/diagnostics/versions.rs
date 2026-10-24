//! Explicit bounded version commands, separate from passive inventory.
#[cfg(windows)]
use crate::platform::child_job as windows_job;

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::{timeout, Instant};

use super::Report;

pub(super) async fn inspect(report: &mut Report) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let home = std::fs::canonicalize(&report.home);
    for dependency in &mut report.dependencies {
        if dependency.status != "present" {
            dependency.version_status = match dependency.status {
                "invalid" => "unsafe_path",
                "inaccessible" => "inaccessible",
                _ => "missing",
            };
            continue;
        }
        let path = Path::new(&dependency.path);
        if path.extension().is_some_and(|ext| ext == "msi") {
            dependency.version_status = "unsupported";
            continue;
        }
        let canonical = std::fs::canonicalize(path);
        let safe = matches!((&home, &canonical), (Ok(home), Ok(path)) if path.starts_with(home));
        if !safe {
            dependency.version_status = "unsafe_path";
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            dependency.version_status = "budget_exhausted";
            continue;
        }
        let (status, output, exit_code) = run(path, remaining.min(Duration::from_secs(3))).await;
        dependency.version_status = status;
        dependency.version_output = output;
        dependency.version_exit_code = exit_code;
    }
}

async fn read_output<R: AsyncRead + Unpin>(stream: R) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    stream
        .take(4097)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| "failed")?;
    if bytes.len() > 4096 {
        return Err("output_limit");
    }
    Ok(bytes)
}

async fn run(path: &Path, duration: Duration) -> (&'static str, Option<String>, Option<i32>) {
    let mut command = Command::new(path);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    command.creation_flags(0x0800_0000 | 0x0000_0004); // CREATE_NO_WINDOW | CREATE_SUSPENDED
    let Ok(mut child) = command.spawn() else {
        return ("inaccessible", None, None);
    };
    #[cfg(windows)]
    let Some(_job) = windows_job::attach_and_resume(&child) else {
        let _ = child.kill().await;
        return ("inaccessible", None, None);
    };
    #[cfg(unix)]
    let _group = ProcessGroup(child.id());
    let Some(stdout) = child.stdout.take() else {
        return ("failed", None, None);
    };
    let Some(stderr) = child.stderr.take() else {
        return ("failed", None, None);
    };
    let result = timeout(duration, async {
        tokio::try_join!(
            async { child.wait().await.map_err(|_| "failed") },
            read_output(stdout),
            read_output(stderr),
        )
    })
    .await;
    match result {
        Ok(Ok((status, stdout, stderr))) => {
            // Preserve CLI's stdout-first choice, including an unsuccessful
            // command's diagnostic text, but never write it into protocol stderr.
            let stdout = String::from_utf8_lossy(&stdout).trim().to_owned();
            let text = if stdout.is_empty() {
                String::from_utf8_lossy(&stderr).trim().to_owned()
            } else {
                stdout
            };
            (
                if status.success() { "ok" } else { "failed" },
                Some(text),
                status.code(),
            )
        }
        Ok(Err(code)) => {
            let _ = child.kill().await;
            (code, None, None)
        }
        Err(_) => {
            let _ = child.kill().await;
            ("timeout", None, None)
        }
    }
}

#[cfg(unix)]
struct ProcessGroup(Option<u32>);

#[cfg(unix)]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0.and_then(|pid| i32::try_from(pid).ok()) {
            // A dependency may leave children holding stdout after its leader
            // exits; clean its private group on success and cancellation alike.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
}
