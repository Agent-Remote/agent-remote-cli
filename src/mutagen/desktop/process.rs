//! Transient Mutagen clients are contained; an explicitly started daemon persists.
use super::{Error, Result};
use crate::config::AppPaths;
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
};

pub(super) async fn run(
    paths: &AppPaths,
    args: &[&str],
    deadline: Duration,
    mutation: bool,
    daemon_start: bool,
) -> Result<Vec<u8>> {
    let binary = crate::mutagen::binary_path(paths);
    let directory = binary
        .parent()
        .ok_or_else(|| Error::new("sync_mutagen_missing"))?;
    let configured = crate::mutagen::configured_mutagen_command(paths, &binary, directory)
        .map_err(|_| Error::new("sync_mutagen_environment_invalid"))?;
    let mut command = Command::from(configured);
    command
        .args(args)
        .env("MUTAGEN_DISABLE_AUTOSTART", "1")
        // An explicit path preserves the existing namespace but disables the
        // upstream Windows hidden-attribute write on every default-path lookup.
        .env("MUTAGEN_DATA_DIRECTORY", super::data_directory()?)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    if !daemon_start {
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED);
    }
    let child = command
        .spawn()
        .map_err(|_| Error::new("sync_mutagen_unavailable"))?;
    let mut process =
        Process::new(child, daemon_start).map_err(|e| if mutation { e.changed() } else { e })?;
    let stdout = process
        .child
        .stdout
        .take()
        .ok_or_else(|| Error::new("sync_mutagen_unavailable"))?;
    let stderr = process
        .child
        .stderr
        .take()
        .ok_or_else(|| Error::new("sync_mutagen_unavailable"))?;
    let work = async {
        let (out, _, status) = tokio::try_join!(
            bounded(stdout, 2 * 1024 * 1024),
            bounded(stderr, 64 * 1024),
            async {
                process
                    .child
                    .wait()
                    .await
                    .map_err(|_| Error::new("sync_mutagen_unavailable"))
            }
        )?;
        if !status.success() {
            return Err(Error::new("sync_mutagen_unavailable"));
        }
        Ok(out)
    };
    tokio::time::timeout(deadline, work)
        .await
        .map_err(|_| Error::new("sync_mutagen_timeout"))
        .and_then(|r| r)
        .map_err(|e| if mutation { e.changed() } else { e })
}

async fn bounded(mut reader: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>> {
    let mut buffer = [0; 8192];
    let mut output = Vec::new();
    loop {
        let size = reader
            .read(&mut buffer)
            .await
            .map_err(|_| Error::new("sync_mutagen_unavailable"))?;
        if size == 0 {
            return Ok(output);
        }
        if output.len() + size > limit {
            return Err(Error::new("sync_mutagen_output_limit"));
        }
        output.extend_from_slice(&buffer[..size]);
    }
}

struct Process {
    child: Child,
    #[cfg(unix)]
    group: Option<u32>,
    #[cfg(windows)]
    _job: Option<std::os::windows::io::OwnedHandle>,
}
impl Process {
    fn new(child: Child, daemon_start: bool) -> Result<Self> {
        #[cfg(unix)]
        let group = if daemon_start {
            None
        } else {
            Some(
                child
                    .id()
                    .ok_or_else(|| Error::new("sync_mutagen_unavailable"))?,
            )
        };
        #[cfg(windows)]
        let _job = if daemon_start {
            None
        } else {
            Some(
                crate::platform::child_job::attach_and_resume(&child)
                    .ok_or_else(|| Error::new("sync_mutagen_unavailable"))?,
            )
        };
        Ok(Self {
            child,
            #[cfg(unix)]
            group,
            #[cfg(windows)]
            _job,
        })
    }
}
#[cfg(unix)]
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(group) = self.group {
            // The daemon cannot be a descendant: autostart is disabled, and explicit
            // daemon startup uses a separate lifecycle. Kill only transient clients.
            unsafe {
                libc::kill(-(group as i32), libc::SIGKILL);
            }
        }
    }
}
