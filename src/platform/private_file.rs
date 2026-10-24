//! Handle-based permissions: secret bytes are written only after access is restricted.

use std::fs::File;

use anyhow::Result;

#[cfg(windows)]
mod windows;

/// Stable native object identity, including the full Windows 128-bit file ID.
pub fn file_identity(file: &File) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(format!("{}:{}", metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        windows::identity(file)
    }
}

/// Restrict a staging handle before writing any WireGuard configuration bytes.
pub fn set_private_wireguard_file_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        set_private_file_permissions(file)
    }
    #[cfg(windows)]
    {
        windows::restrict(file, true)
    }
}

pub(crate) fn set_private_file_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(windows)]
    {
        windows::restrict(file, false)
    }
}

/// Apply the private ACL to an existing path without resolving it through a
/// mutable path-based ACL tool. Windows callers use a handle opened with the
/// directory backup flag when `directory` is true.
#[cfg(windows)]
pub(crate) fn set_private_path_permissions(
    path: &std::path::Path,
    directory: bool,
    system_read: bool,
) -> Result<()> {
    windows::restrict_path(path, directory, system_read)
}

pub(crate) fn validate_private_file(file: &File) -> Result<()> {
    validate_single_regular_file(file)?;
    #[cfg(unix)]
    let metadata = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "credential file ownership, links or permissions are unsafe"
        );
    }
    #[cfg(windows)]
    windows::validate(file)?;
    Ok(())
}

/// Validate a secret-bearing tunnel configuration, including System read access
/// on Windows without widening the ordinary credential-file ACL policy.
pub(crate) fn validate_private_wireguard_file(file: &File) -> Result<()> {
    #[cfg(unix)]
    return validate_private_file(file);
    #[cfg(windows)]
    {
        validate_single_regular_file(file)?;
        windows::validate_wireguard(file)
    }
}

pub(crate) fn validate_single_regular_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "entry is not a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(metadata.nlink() == 1, "hard-linked file is unsafe");
    }
    #[cfg(windows)]
    windows::validate_kind(file)?;
    Ok(())
}

pub(crate) fn validate_private_directory(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_dir(), "entry is not a directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
            "directory ownership or write permissions are unsafe"
        );
    }
    #[cfg(windows)]
    windows::validate_directory(file)?;
    Ok(())
}

/// Open a readable descriptor relative to the pinned directory, since Linux
/// capability directories may use O_PATH handles that cannot be fsynced.
#[cfg(unix)]
pub(crate) fn sync_directory(directory: &cap_std::fs::Dir) -> std::io::Result<()> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
    use cap_std::fs::{OpenOptions, OpenOptionsExt};
    let mut options = OpenOptions::new();
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .custom_flags(libc::O_DIRECTORY);
    directory.open_with(".", &options)?.into_std().sync_all()
}

#[cfg(all(test, unix))]
#[path = "../../tests/unit/src/private_file_unix.rs"]
mod tests;
