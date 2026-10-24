//! Bounded diagnostic reads, deliberately separate from login fallback behavior.
use std::fs;
use std::io::{ErrorKind, Read};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, bail, Result};

use super::SecretStore;

const MAX_SECRET_BYTES: usize = 64 * 1024;

pub(super) fn contains(store: &SecretStore, key: &str, canceled: &AtomicBool) -> Result<bool> {
    if canceled.load(Ordering::Acquire) {
        bail!("credential inspection canceled")
    }
    let system_error = if store.prefer_system {
        match system_contains(key, canceled) {
            Ok(true) => return Ok(true),
            Ok(false) => None,
            Err(error) => Some(error),
        }
    } else {
        None
    };
    if file_contains(&store.secret_path(key))? {
        return Ok(true);
    }
    match system_error {
        Some(error) => Err(error),
        None => Ok(false),
    }
}

fn file_contains(path: &std::path::Path) -> Result<bool> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_) => bail!("credential fallback is inaccessible"),
    };
    let metadata = file
        .metadata()
        .map_err(|_| anyhow!("credential fallback is inaccessible"))?;
    if !metadata.is_file() || metadata.len() > MAX_SECRET_BYTES as u64 {
        bail!("credential fallback has an invalid type or size")
    }
    let mut bytes = Vec::new();
    file.take(MAX_SECRET_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("credential fallback is unreadable"))?;
    nonempty(&bytes)
}

fn nonempty(bytes: &[u8]) -> Result<bool> {
    if bytes.len() > MAX_SECRET_BYTES {
        bail!("credential exceeds diagnostic read limit")
    }
    std::str::from_utf8(bytes)
        .map(|text| !text.trim().is_empty())
        .map_err(|_| anyhow!("credential is not valid text"))
}

#[cfg(target_os = "macos")]
fn system_contains(key: &str, canceled: &AtomicBool) -> Result<bool> {
    inspect_command(
        "security",
        &[
            "find-generic-password",
            "-s",
            super::SERVICE,
            "-a",
            key,
            "-w",
        ],
        44,
        false,
        canceled,
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn system_contains(key: &str, canceled: &AtomicBool) -> Result<bool> {
    // libsecret lookup returns 1 both for no matching value and for GError.
    // GError is written to stderr; only a silent 1 with no output proves absence.
    inspect_command(
        "secret-tool",
        &["lookup", "service", super::SERVICE, "account", key],
        1,
        true,
        canceled,
    )
}

#[cfg(windows)]
fn system_contains(key: &str, canceled: &AtomicBool) -> Result<bool> {
    if canceled.load(Ordering::Acquire) {
        bail!("credential inspection canceled")
    }
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };
    let target = super::windows_target(key);
    let mut raw: *mut CREDENTIALW = std::ptr::null_mut();
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(1168) {
            return Ok(false);
        }
        bail!("system credential store is inaccessible")
    }
    if raw.is_null() {
        bail!("system credential response is invalid")
    }
    let result = unsafe {
        let credential = &*raw;
        let length = credential.CredentialBlobSize as usize;
        if length > MAX_SECRET_BYTES || (length > 0 && credential.CredentialBlob.is_null()) {
            Err(anyhow!("system credential response is invalid"))
        } else if length == 0 {
            Ok(false)
        } else {
            nonempty(std::slice::from_raw_parts(
                credential.CredentialBlob,
                length,
            ))
        }
    };
    unsafe {
        CredFree(raw.cast());
    }
    result
}

#[cfg(all(not(unix), not(windows)))]
fn system_contains(_key: &str, _canceled: &AtomicBool) -> Result<bool> {
    bail!("platform credential store is unavailable")
}

#[cfg(unix)]
fn inspect_command(
    program: &str,
    args: &[&str],
    missing_code: i32,
    missing_requires_silence: bool,
    canceled: &AtomicBool,
) -> Result<bool> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| anyhow!("system credential tool is unavailable"))?;
    let mut guard = ProbeChild(child);
    let mut stdout = guard
        .0
        .stdout
        .take()
        .ok_or_else(|| anyhow!("credential output unavailable"))?;
    let mut stderr = guard
        .0
        .stderr
        .take()
        .ok_or_else(|| anyhow!("credential output unavailable"))?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            bail!("credential output could not be bounded")
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let (mut out_done, mut err_done) = (false, false);
    let status = loop {
        if canceled.load(Ordering::Acquire) {
            bail!("credential inspection canceled")
        }
        if Instant::now() >= deadline {
            bail!("system credential tool timed out")
        }
        if !out_done {
            out_done = read_chunk(&mut stdout, &mut output, MAX_SECRET_BYTES)?;
        }
        if !err_done {
            err_done = read_chunk(&mut stderr, &mut errors, 4096)?;
        }
        if let Some(status) = guard
            .0
            .try_wait()
            .map_err(|_| anyhow!("credential tool wait failed"))?
        {
            if out_done && err_done {
                break status;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if status.success() {
        return nonempty(&output);
    }
    if status.code() == Some(missing_code)
        && output.is_empty()
        && (!missing_requires_silence || errors.is_empty())
    {
        return Ok(false);
    }
    bail!("system credential store is inaccessible")
}

#[cfg(unix)]
fn read_chunk(stream: &mut impl Read, bytes: &mut Vec<u8>, limit: usize) -> Result<bool> {
    let mut chunk = [0; 4096];
    match stream.read(&mut chunk) {
        Ok(0) => Ok(true),
        Ok(count) => {
            if bytes.len() + count > limit {
                bail!("credential tool output exceeded diagnostic limit")
            }
            bytes.extend_from_slice(&chunk[..count]);
            Ok(false)
        }
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            Ok(false)
        }
        Err(_) => Err(anyhow!("credential tool output unreadable")),
    }
}

#[cfg(unix)]
struct ProbeChild(std::process::Child);

#[cfg(unix)]
impl Drop for ProbeChild {
    fn drop(&mut self) {
        if let Ok(pid) = i32::try_from(self.0.id()) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(all(test, unix))]
#[path = "../../tests/unit/src/secrets_inspection.rs"]
mod tests;
