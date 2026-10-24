//! Native locks compatible with Mutagen, not flock-based application locks.
use super::super::{Error, Result};
use super::inventory::{directory_identity, invalid, open_path, open_regular};
use cap_std::fs::Dir;
use std::{
    fs::File,
    path::{Path, PathBuf},
};

pub(super) enum Probe {
    Missing,
    Busy,
    Stopped(DaemonGuard),
}

/// Do not reopen/close this lock file while a POSIX guard is held: fcntl locks
/// belong to the process and closing ANY descriptor for the inode releases them.
pub(super) struct DaemonGuard {
    file: File,
    directory: Dir,
    path: PathBuf,
    directory_id: String,
    identity: String,
}

impl DaemonGuard {
    /// Verify the held inode still occupies the selected namespace lock path.
    pub(super) fn validate(&self) -> Result<()> {
        let current =
            open_path(self.path.parent().ok_or_else(invalid)?, false)?.ok_or_else(invalid)?;
        if directory_identity(&current)? != self.directory_id
            || directory_identity(&self.directory)? != self.directory_id
        {
            return Err(Error::new("sync_mutagen_inventory_changed"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // std lstat uses no second file descriptor, preserving the fcntl lock.
            let metadata = std::fs::symlink_metadata(&self.path).map_err(|_| invalid())?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || format!("{}:{}", metadata.dev(), metadata.ino()) != self.identity
            {
                return Err(Error::new("sync_mutagen_inventory_changed"));
            }
        }
        #[cfg(windows)]
        {
            let current =
                open_regular(&current, std::ffi::OsStr::new("daemon.lock"), false, false)?;
            if crate::platform::file_identity(&current).map_err(|_| invalid())? != self.identity {
                return Err(Error::new("sync_mutagen_inventory_changed"));
            }
        }
        crate::platform::validate_single_regular_file(&self.file).map_err(|_| invalid())
    }
}

pub(super) fn probe(data: &Path) -> Result<Probe> {
    match open(data, false, false)? {
        None => Ok(Probe::Missing),
        Some(guard) if lock(&guard.file, false)? => {
            guard.validate()?;
            Ok(Probe::Stopped(guard))
        }
        Some(_) => Ok(Probe::Busy),
    }
}

/// Create directories/the lock only after explicit environment-recovery consent.
pub(super) fn acquire(data: &Path, create: bool) -> Result<DaemonGuard> {
    let guard =
        open(data, true, create)?.ok_or_else(|| Error::new("sync_mutagen_daemon_lock_missing"))?;
    if !lock(&guard.file, true)? {
        return Err(Error::new("sync_mutagen_daemon_busy"));
    }
    guard.validate()?;
    Ok(guard)
}

fn open(data: &Path, write: bool, create: bool) -> Result<Option<DaemonGuard>> {
    let path = data.join("daemon");
    let Some(directory) = open_path(&path, create)? else {
        return Ok(None);
    };
    let directory_id = directory_identity(&directory)?;
    let missing = match directory.symlink_metadata("daemon.lock") {
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => return Err(invalid()),
    };
    if missing && !create {
        return Ok(None);
    }
    let file = open_regular(
        &directory,
        std::ffi::OsStr::new("daemon.lock"),
        write,
        missing,
    )?;
    let identity = crate::platform::file_identity(&file).map_err(|_| invalid())?;
    let guard = DaemonGuard {
        file,
        directory,
        path: path.join("daemon.lock"),
        directory_id,
        identity,
    };
    guard.validate()?;
    Ok(Some(guard))
}

#[cfg(unix)]
fn lock(file: &File, exclusive: bool) -> Result<bool> {
    use std::os::fd::AsRawFd;
    // Zero-initialization is valid for flock and avoids platform field differences.
    let mut specification: libc::flock = unsafe { std::mem::zeroed() };
    specification.l_type = if exclusive {
        libc::F_WRLCK
    } else {
        libc::F_RDLCK
    } as _;
    specification.l_whence = libc::SEEK_SET as _;
    loop {
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &specification) } == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN | libc::EACCES) => return Ok(false),
            _ => return Err(invalid()),
        }
    }
}

#[cfg(windows)]
fn lock(file: &File, exclusive: bool) -> Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_LOCK_VIOLATION},
        Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
        System::IO::OVERLAPPED,
    };
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let flags = LOCKFILE_FAIL_IMMEDIATELY
        | if exclusive {
            LOCKFILE_EXCLUSIVE_LOCK
        } else {
            0
        };
    if unsafe { LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &mut overlapped) } != 0 {
        return Ok(true);
    }
    if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
        Ok(false)
    } else {
        Err(invalid())
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/src/mutagen_environment_native_lock.rs"]
mod tests;
