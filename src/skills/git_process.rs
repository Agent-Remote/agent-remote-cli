//! Isolated Git child processes with bounded output and cancellation of their descendants.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

/// Build in a private directory. Only credential lookup may read native user configuration.
pub fn command(directory: &Path, credential_lookup: bool) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    for name in [
        "PATH",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "GIT_SSL_CAINFO",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .current_dir(directory)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "Never")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_ALLOW_PROTOCOL", "https")
        .env("LC_ALL", "C")
        .args([
            "-c",
            "core.askPass=",
            "-c",
            "core.hooksPath=",
            "-c",
            "core.fsmonitor=false",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if !credential_lookup {
        command.env("GIT_CONFIG_NOSYSTEM", "1");
        #[cfg(unix)]
        command.env("GIT_CONFIG_GLOBAL", "/dev/null");
        #[cfg(windows)]
        command.env("GIT_CONFIG_GLOBAL", "NUL");
        command.args([
            "-c",
            "credential.helper=",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.sslVerify=true",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "fetch.fsckObjects=true",
            "-c",
            "transfer.fsckObjects=true",
            "-c",
            "fetch.recurseSubmodules=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ]);
    }
    #[cfg(unix)]
    command.process_group(0);
    command
}

/// Output and diagnostics never enter errors: Git/helpers may echo authorization material.
pub async fn run(
    mut command: Command,
    input: &[u8],
    output_limit: usize,
    duration: Duration,
    disk_root: Option<&Path>,
) -> Result<Option<Vec<u8>>> {
    let child = command
        .spawn()
        .context("GIT_UNAVAILABLE: cannot start native Git")?;
    let mut process = Process::new(child)?;
    let mut stdin = process
        .child
        .stdin
        .take()
        .context("Git stdin unavailable")?;
    let stdout = process
        .child
        .stdout
        .take()
        .context("Git stdout unavailable")?;
    let stderr = process
        .child
        .stderr
        .take()
        .context("Git stderr unavailable")?;
    let work = async {
        let send = async {
            stdin.write_all(input).await?;
            drop(stdin);
            Ok::<_, anyhow::Error>(())
        };
        let ((), output, _, status) = tokio::try_join!(
            send,
            read_bounded(stdout, output_limit),
            read_bounded(stderr, 64 * 1024),
            async { Ok::<_, anyhow::Error>(process.child.wait().await?) },
        )?;
        Ok::<_, anyhow::Error>(status.success().then_some(output))
    };
    tokio::select! {
        result = tokio::time::timeout(duration, work) => {
            let output = result.map_err(|_| anyhow::anyhow!("SOURCE_TIMEOUT: Git acquisition timed out"))??;
            if let Some(root) = disk_root { check_disk(root).await?; }
            Ok(output)
        }
        result = monitor_disk(disk_root) => { result?; unreachable!() }
    }
}

async fn read_bounded(mut input: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = input.read(&mut buffer).await?;
        if count == 0 {
            return Ok(output);
        }
        if output.len() + count > limit {
            bail!("QUOTA_EXCEEDED: Git process output exceeds its bound");
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

async fn monitor_disk(root: Option<&Path>) -> Result<()> {
    let Some(root) = root else {
        return std::future::pending().await;
    };
    loop {
        check_disk(root).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn check_disk(root: &Path) -> Result<()> {
    let root = root.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut queue = vec![root];
        let mut count = 0;
        let mut bytes = 0u64;
        while let Some(path) = queue.pop() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let metadata = match entry.path().symlink_metadata() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                };
                count += 1;
                bytes = bytes.saturating_add(metadata.len());
                if count > 100_000 || bytes > 512 * 1024 * 1024 {
                    bail!("QUOTA_EXCEEDED: Git staging exceeds 512 MiB or 100000 entries");
                }
                if metadata.is_dir() {
                    queue.push(entry.path());
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

struct Process {
    child: Child,
    #[cfg(unix)]
    group: u32,
    #[cfg(windows)]
    _job: std::os::windows::io::OwnedHandle,
}
impl Process {
    fn new(child: Child) -> Result<Self> {
        #[cfg(unix)]
        let group = child.id().context("Git process ID unavailable")?;
        #[cfg(windows)]
        let _job = windows_job(&child)?;
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
        // Also runs when the acquisition future is cancelled or a pipe exceeds its limit.
        unsafe {
            libc::kill(-(self.group as i32), libc::SIGKILL);
        }
    }
}

#[cfg(windows)]
fn windows_job(child: &Child) -> Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw.is_null() {
        bail!("cannot create Git process job");
    }
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let configured = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&limits).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    };
    let handle = child
        .raw_handle()
        .context("Git process handle unavailable")?;
    if configured == 0 || unsafe { AssignProcessToJobObject(job.as_raw_handle(), handle) } == 0 {
        bail!("cannot contain Git process descendants");
    }
    Ok(job)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn output_bound_and_timeout_kill_descendant_processes() {
        let root = tempfile::tempdir().unwrap();
        for excess in [true, false] {
            let marker = root.path().join(if excess {
                "output-child"
            } else {
                "timeout-child"
            });
            let mut command = Command::new("sh");
            command
                .args([
                    "-c",
                    if excess {
                        "(sleep 0.5; touch \"$1\") & printf too-much-output; wait"
                    } else {
                        "(sleep 0.5; touch \"$1\") & wait"
                    },
                    "fixture",
                ])
                .arg(&marker)
                .process_group(0);
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            let error = run(command, b"", 3, Duration::from_millis(100), None)
                .await
                .err()
                .unwrap();
            assert!(error.to_string().contains(if excess {
                "QUOTA_EXCEEDED"
            } else {
                "SOURCE_TIMEOUT"
            }));
            tokio::time::sleep(Duration::from_millis(650)).await;
            assert!(!marker.exists());
        }
    }
    #[tokio::test]
    async fn disk_guard_checks_fast_completion_and_sparse_file_sizes() {
        let root = tempfile::tempdir().unwrap();
        std::fs::File::create(root.path().join("pack"))
            .unwrap()
            .set_len(512 * 1024 * 1024 + 1)
            .unwrap();
        let mut command = Command::new("sh");
        command
            .args(["-c", "true"])
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let error = run(
            command,
            b"",
            1024,
            Duration::from_secs(10),
            Some(root.path()),
        )
        .await
        .err()
        .unwrap();
        assert!(error.to_string().contains("QUOTA_EXCEEDED"));
    }
    #[tokio::test]
    async fn cancellation_drops_the_whole_process_group() {
        let root = tempfile::tempdir().unwrap();
        let ready = root.path().join("ready");
        let marker = root.path().join("child");
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "touch \"$1\"; (sleep 0.5; touch \"$2\") & wait",
                "fixture",
            ])
            .arg(&ready)
            .arg(&marker)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let task =
            tokio::spawn(
                async move { run(command, b"", 1024, Duration::from_secs(10), None).await },
            );
        tokio::time::timeout(Duration::from_secs(5), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;
        tokio::time::sleep(Duration::from_millis(650)).await;
        assert!(!marker.exists());
    }
}
