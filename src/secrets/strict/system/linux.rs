use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

use super::{check_cancel, Error, SecretValue};
use crate::secrets::strict::MAX_SECRET_BYTES;

pub(super) async fn read(key: &str, cancel: &AtomicBool) -> Result<Option<SecretValue>, Error> {
    let (status, mut output, errors) = run(
        &["lookup", "service", crate::secrets::SERVICE, "account", key],
        None,
        cancel,
    )
    .await?;
    if status.success() {
        if output.last() == Some(&b'\n') {
            output.pop();
        }
        return SecretValue::new(String::from_utf8(output).map_err(|_| Error::Invalid)?).map(Some);
    }
    if status.code() == Some(1) && output.is_empty() && errors.is_empty() {
        return Ok(None);
    }
    Err(Error::Unavailable)
}

pub(super) async fn write(
    key: &str,
    value: &SecretValue,
    cancel: &AtomicBool,
) -> Result<(), Error> {
    let (status, _, _) = run(
        &[
            "store",
            "--label",
            "agent-remote",
            "service",
            crate::secrets::SERVICE,
            "account",
            key,
        ],
        Some(value.as_str().as_bytes()),
        cancel,
    )
    .await?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

async fn bounded_read(stream: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    stream
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

async fn run(
    args: &[&str],
    input: Option<&[u8]>,
    cancel: &AtomicBool,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), Error> {
    check_cancel(cancel)?;
    let mut command = Command::new("secret-tool");
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let process = command.spawn()?;
    let group_id = process
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .ok_or(Error::Unavailable)?;
    let mut child = ProcessGroup { process, group_id };
    let mut stdin = child.process.stdin.take().ok_or(Error::Unavailable)?;
    let stdout = child.process.stdout.take().ok_or(Error::Unavailable)?;
    let stderr = child.process.stderr.take().ok_or(Error::Unavailable)?;
    let io = async {
        let write = async {
            if let Some(input) = input {
                stdin.write_all(input).await?;
            }
            drop(stdin);
            Ok::<_, Error>(())
        };
        let wait = async { child.process.wait().await.map_err(Error::from) };
        let ((), output, errors, status) = tokio::try_join!(
            write,
            bounded_read(stdout, MAX_SECRET_BYTES + 1),
            bounded_read(stderr, 4096),
            wait
        )?;
        Ok((status, output, errors))
    };
    let canceled = async {
        while check_cancel(cancel).is_ok() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    let result = tokio::select! {
        result = io => result,
        _ = canceled => Err(Error::Canceled),
        _ = tokio::time::sleep(Duration::from_secs(3)) => Err(Error::TimedOut),
    };
    // Send the group kill synchronously, then give Tokio a bounded opportunity
    // to reap the leader before the CLI's cancellation wrapper exits.
    unsafe { libc::kill(-child.group_id, libc::SIGKILL) };
    let _ = child.process.start_kill();
    let _ = tokio::time::timeout(Duration::from_millis(500), child.process.wait()).await;
    result
}

struct ProcessGroup {
    process: Child,
    group_id: i32,
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        unsafe { libc::kill(-self.group_id, libc::SIGKILL) };
        let _ = self.process.start_kill();
    }
}
