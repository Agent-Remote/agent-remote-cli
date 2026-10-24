use std::fs::File;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt as StdOpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, DirBuilder, DirBuilderExt, OpenOptions, OpenOptionsExt};

use super::{Authority, DirectorySync};

pub(super) fn require_privileged() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "protected storage requires root process"
    );
    Ok(())
}

pub(super) fn normalize(path: &Path) -> Result<PathBuf> {
    let normalized: PathBuf = path.components().collect();
    #[cfg(target_os = "macos")]
    let mut normalized = normalized;
    #[cfg(target_os = "macos")]
    for alias in ["var", "etc", "tmp"] {
        let prefix = PathBuf::from("/").join(alias);
        if let Ok(remainder) = normalized.strip_prefix(&prefix) {
            let expected = PathBuf::from("private").join(alias);
            let metadata = std::fs::symlink_metadata(&prefix)?;
            ensure!(
                metadata.file_type().is_symlink()
                    && metadata.uid() == 0
                    && std::fs::read_link(&prefix)? == expected,
                "system alias changed"
            );
            normalized = Path::new("/").join(expected).join(remainder);
            break;
        }
    }
    Ok(normalized)
}

pub(super) fn open_root(path: &Path) -> Result<Dir> {
    let options = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    Ok(Dir::from_std_file(options))
}

#[cfg(test)]
pub(super) fn prepare_test_root(directory: &Dir) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let file = directory.try_clone()?.into_std_file();
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() },
        "test root must belong to the current user"
    );
    file.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(super) fn open_child(parent: &Dir, name: &str) -> Result<Option<Dir>> {
    match parent.open_dir_nofollow(name) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn validate_directory(file: &File, private: bool, authority: &Authority) -> Result<()> {
    let metadata = file.metadata()?;
    let owner = if authority.production() {
        0
    } else {
        unsafe { libc::geteuid() }
    };
    ensure!(
        metadata.is_dir() && metadata.uid() == owner,
        "protected directory ownership is unsafe"
    );
    ensure!(
        metadata.mode() & if private { 0o077 } else { 0o022 } == 0,
        "protected directory permissions are unsafe"
    );
    #[cfg(target_os = "macos")]
    reject_extended_acl(file)?;
    Ok(())
}

pub(super) fn validate_file(file: &File, authority: &Authority) -> Result<()> {
    let metadata = file.metadata()?;
    let owner = if authority.production() {
        0
    } else {
        unsafe { libc::geteuid() }
    };
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == owner
            && metadata.mode() & 0o077 == 0,
        "protected file ownership, type, links or permissions are unsafe"
    );
    #[cfg(target_os = "macos")]
    reject_extended_acl(file)?;
    Ok(())
}

/// macOS ACL grants are independent of mode bits. Refuse custom ACLs instead
/// of trying to infer effective access across users, groups and inheritance.
#[cfg(target_os = "macos")]
fn reject_extended_acl(file: &File) -> Result<()> {
    use std::ffi::{c_int, c_void};
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }
    // Constants and signatures from the macOS SDK's sys/acl.h.
    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FIRST_ENTRY: c_int = 0;
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        // Darwin reports ENOENT for an absent extended ACL. This is a pinned
        // valid descriptor, not a pathname lookup; reject unlinked objects and
        // all other retrieval failures, including unsupported filesystems.
        let error = std::io::Error::last_os_error();
        ensure!(
            error.raw_os_error() == Some(libc::ENOENT) && file.metadata()?.nlink() != 0,
            "cannot inspect protected extended ACL"
        );
        return Ok(());
    }
    let mut entry = std::ptr::null_mut();
    let result = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let error = std::io::Error::last_os_error();
    unsafe { acl_free(acl) };
    // Darwin returns -1/EINVAL when a valid ACL contains no entry; unlike
    // Linux's POSIX API, a successful entry lookup returns zero.
    ensure!(
        result == -1 && error.raw_os_error() == Some(libc::EINVAL),
        "protected storage has an extended ACL or unreadable ACL entry"
    );
    Ok(())
}

pub(super) fn create_file(parent: &Dir, name: &str, _authority: &Authority) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No)
        .custom_flags(libc::O_NONBLOCK);
    Ok(parent.open_with(name, &options)?.into_std())
}

pub(super) fn open_file(parent: &Dir, name: &str) -> Result<Option<File>> {
    let metadata = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "protected entry is not a regular file"
    );
    let mut options = OpenOptions::new();
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .custom_flags(libc::O_NONBLOCK);
    Ok(Some(parent.open_with(name, &options)?.into_std()))
}

pub(super) fn open_append_file(parent: &Dir, name: &str) -> Result<Option<File>> {
    let metadata = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "protected entry is not a regular file"
    );
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .append(true)
        .follow(FollowSymlinks::No)
        .custom_flags(libc::O_NONBLOCK);
    Ok(Some(parent.open_with(name, &options)?.into_std()))
}

pub(super) fn create_child(parent: &Dir, name: &str, _authority: &Authority) -> Result<Dir> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    parent.create_dir_with(name, &builder)?;
    Ok(parent.open_dir_nofollow(name)?)
}

pub(super) fn sync(directory: &Dir) -> Result<DirectorySync> {
    crate::platform::sync_directory(directory)?;
    Ok(DirectorySync::Synced)
}

#[cfg(test)]
#[path = "../../../tests/unit/src/protected_directory_unix.rs"]
mod tests;
