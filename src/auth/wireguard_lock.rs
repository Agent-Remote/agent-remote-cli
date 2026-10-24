//! User-wide key lock independent of AGENT_REMOTE_HOME.
//!
//! Required order: login lock, server/device key lock, output-directory lock.

use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, DirBuilder, OpenOptions};
use sha2::{Digest, Sha256};

pub struct WireGuardCredentialLock {
    _file: File,
}

/// All cooperating homes must use the same user-wide root. The override is
/// explicit so tests and sandboxed installations never touch real credentials.
pub async fn lock_wireguard_credentials(
    server: &str,
    device: &str,
    cancel: &AtomicBool,
) -> Result<WireGuardCredentialLock> {
    let root = match std::env::var_os("AGENT_REMOTE_WIREGUARD_LOCK_ROOT") {
        Some(value) => PathBuf::from(value),
        None => crate::platform::user_home_dir()
            .context("user home is unavailable")?
            .join(".agent-remote-wireguard-locks"),
    };
    lock_at(&root, server, device, cancel).await
}

async fn lock_at(
    root: &Path,
    server: &str,
    device: &str,
    cancel: &AtomicBool,
) -> Result<WireGuardCredentialLock> {
    if cancel.load(Ordering::Acquire) {
        bail!("WireGuard credential lock canceled")
    }
    if !root.is_absolute()
        || root
            .components()
            .any(|item| matches!(item, Component::ParentDir))
    {
        bail!("WireGuard credential lock root must be an absolute safe path")
    }
    let root: PathBuf = root.components().collect();
    let parent = root
        .parent()
        .context("WireGuard credential lock parent is missing")?;
    let name = root
        .file_name()
        .context("WireGuard credential lock directory is missing")?;
    let parent = Dir::open_ambient_dir(parent, cap_std::ambient_authority())
        .context("WireGuard credential lock parent is unavailable")?;
    let builder = DirBuilder::new();
    #[cfg(unix)]
    let mut builder = builder;
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match parent.create_dir_with(name, &builder) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).context("cannot create WireGuard credential lock directory")
        }
    }
    let directory = parent.open_dir_nofollow(name)?;
    crate::platform::validate_private_directory(&directory.try_clone()?.into_std_file())?;
    let mut digest = Sha256::new();
    digest.update((server.len() as u64).to_be_bytes());
    digest.update(server.as_bytes());
    digest.update((device.len() as u64).to_be_bytes());
    digest.update(device.as_bytes());
    let filename = format!("{:x}.lock", digest.finalize());
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    let file = match directory.open_with(&filename, &options) {
        Ok(file) => {
            let file = file.into_std();
            crate::platform::set_private_file_permissions(&file)?;
            file
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            options.create_new(false).create(false);
            directory.open_with(&filename, &options)?.into_std()
        }
        Err(error) => return Err(error).context("cannot open WireGuard credential lock"),
    };
    crate::platform::validate_private_file(&file)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if cancel.load(Ordering::Acquire) {
            bail!("WireGuard credential lock canceled")
        }
        match file.try_lock() {
            Ok(()) => return Ok(WireGuardCredentialLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(std::fs::TryLockError::WouldBlock) => bail!("WireGuard credential lock timed out"),
            Err(error) => return Err(error).context("WireGuard credential lock unavailable"),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_lock.rs"]
mod tests;
