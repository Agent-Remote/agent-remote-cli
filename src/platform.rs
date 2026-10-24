use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

#[cfg(windows)]
pub(crate) mod child_job;
mod private_file;
#[allow(dead_code)] // Privileged broker storage foundation; installation and IPC follow.
pub(crate) mod protected_directory;
#[cfg(unix)]
pub(crate) use private_file::sync_directory;
pub use private_file::{file_identity, set_private_wireguard_file_permissions};
pub(crate) use private_file::{
    set_private_file_permissions, validate_private_directory, validate_private_file,
    validate_private_wireguard_file, validate_single_regular_file,
};

pub fn current_platform() -> Result<String> {
    if cfg!(target_os = "macos") {
        Ok("macos".to_string())
    } else if cfg!(target_os = "linux") {
        Ok("linux".to_string())
    } else if cfg!(target_os = "windows") {
        Ok("windows".to_string())
    } else {
        bail!("agent-remote-cli supports Windows, macOS, and Linux")
    }
}

pub fn default_device_name() -> String {
    env::var(if cfg!(windows) {
        "COMPUTERNAME"
    } else {
        "HOSTNAME"
    })
    .ok()
    .filter(|value| !value.trim().is_empty())
    .or_else(|| command_output("hostname"))
    .unwrap_or_else(|| "local-device".to_string())
}

pub fn default_ssh_public_key_path() -> Option<PathBuf> {
    let home = user_home_dir()?;
    ["id_ed25519.pub", "id_rsa.pub"]
        .into_iter()
        .map(|name| home.join(".ssh").join(name))
        .find(|path| path.exists())
}

pub fn user_home_dir() -> Option<PathBuf> {
    env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

pub fn default_app_home() -> Result<PathBuf> {
    if cfg!(windows) {
        if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
            return Ok(PathBuf::from(local_app_data).join("agent-remote"));
        }
        return user_home_dir()
            .map(|home| home.join("AppData").join("Local").join("agent-remote"))
            .context("LOCALAPPDATA and USERPROFILE are not set");
    }
    user_home_dir()
        .map(|home| home.join(".config").join("agent-remote"))
        .context("HOME is not set")
}

pub fn executable_name(name: &str) -> String {
    if cfg!(windows) && !name.to_ascii_lowercase().ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

pub fn managed_binary(dir: &std::path::Path, name: &str) -> PathBuf {
    dir.join(executable_name(name))
}

#[cfg(windows)]
pub fn ssh_binary() -> PathBuf {
    windows_openssh_path("ssh").unwrap_or_else(|| PathBuf::from("ssh.exe"))
}

#[cfg(not(windows))]
pub fn ssh_binary() -> PathBuf {
    PathBuf::from("ssh")
}

#[cfg(windows)]
pub fn openssh_bin_dir() -> Option<PathBuf> {
    windows_openssh_path("ssh").and_then(|path| path.parent().map(std::path::Path::to_path_buf))
}

#[cfg(not(windows))]
pub fn openssh_bin_dir() -> Option<PathBuf> {
    None
}

#[cfg(windows)]
pub fn windows_openssh_path(name: &str) -> Option<PathBuf> {
    if let Some(windows) = env::var_os("WINDIR") {
        let candidate = PathBuf::from(windows)
            .join("System32")
            .join("OpenSSH")
            .join(executable_name(name));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    executable_on_path(&executable_name(name))
}

#[cfg(windows)]
pub fn windows_wireguard_path() -> Option<PathBuf> {
    if let Some(program_files) = env::var_os("ProgramFiles") {
        let candidate = PathBuf::from(program_files)
            .join("WireGuard")
            .join("wireguard.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    executable_on_path("wireguard.exe")
}

#[cfg(windows)]
#[allow(dead_code)] // Used by the sibling agent-remote-wireguard binary via the library crate.
pub fn windows_wg_path() -> Option<PathBuf> {
    if let Some(program_files) = env::var_os("ProgramFiles") {
        let candidate = PathBuf::from(program_files)
            .join("WireGuard")
            .join("wg.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    executable_on_path("wg.exe")
}

#[cfg(windows)]
fn executable_on_path(name: &str) -> Option<PathBuf> {
    for directory in env::split_paths(&env::var_os("PATH")?) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
pub fn set_owner_only_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Restrict a directory before it is used for credentials or other private
/// application state.  Directory permissions are deliberately separate from
/// file permissions: on POSIX a `600` directory cannot be traversed, while on
/// Windows the same owner-only ACL operation is valid for both object types.
#[cfg(unix)]
pub fn set_owner_only_directory_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
pub fn set_owner_only_permissions(path: &std::path::Path) -> Result<()> {
    private_file::set_private_path_permissions(path, false, false)
}

#[cfg(windows)]
pub fn set_owner_only_directory_permissions(path: &std::path::Path) -> Result<()> {
    private_file::set_private_path_permissions(path, true, false)
}

#[cfg(windows)]
#[allow(dead_code)] // Compatibility API; confirmed publication uses a native handle.
pub fn set_wireguard_config_permissions(path: &std::path::Path) -> Result<()> {
    private_file::set_private_path_permissions(path, false, true)
}

/// Publish a staged private file while retaining replacement semantics on
/// Windows even when another process still has the previous file open.
#[cfg(unix)]
pub fn replace_private_file(
    staged: tempfile::NamedTempFile,
    destination: &std::path::Path,
) -> Result<()> {
    staged
        .persist(destination)
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("failed to publish private file: {}", error.error))
}

#[cfg(windows)]
pub fn replace_private_file(
    staged: tempfile::NamedTempFile,
    destination: &std::path::Path,
) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfoEx, MoveFileExW, ReplaceFileW, SetFileInformationByHandle, DELETE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_RENAME_INFO, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    // Close the original tempfile handle before asking Windows to rename it.
    // The explicit replacement handle below is reopened with delete sharing;
    // retaining NamedTempFile's original handle makes MoveFileEx/ReplaceFile
    // reject an otherwise valid replacement on Windows.
    let staged = staged.into_temp_path();
    let destination = std::path::absolute(destination)?;
    let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    let size = std::mem::size_of::<FILE_RENAME_INFO>() - std::mem::size_of::<u16>()
        + name.len() * std::mem::size_of::<u16>();
    let mut info = vec![0u8; size];
    let rename = info.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let rename_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
        .open(&staged)?;
    unsafe {
        (*rename).Anonymous.Flags = 0x0000_0003; // REPLACE_IF_EXISTS | POSIX_SEMANTICS
        (*rename).RootDirectory = std::ptr::null_mut();
        (*rename).FileNameLength = (name.len() * std::mem::size_of::<u16>()) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*rename).FileName.as_mut_ptr(), name.len());
        if SetFileInformationByHandle(
            rename_file.as_raw_handle() as _,
            FileRenameInfoEx,
            rename.cast(),
            size as u32,
        ) == 0
        {
            drop(rename_file);
            let source: Vec<u16> = staged.as_os_str().encode_wide().chain([0]).collect();
            let target: Vec<u16> = destination.as_os_str().encode_wide().chain([0]).collect();
            let replaced = if destination.exists() {
                ReplaceFileW(
                    target.as_ptr(),
                    source.as_ptr(),
                    std::ptr::null(),
                    REPLACEFILE_WRITE_THROUGH,
                    std::ptr::null(),
                    std::ptr::null(),
                ) != 0
            } else {
                false
            };
            // ReplaceFileW has stricter requirements than MoveFileExW (for
            // example, it can reject a destination with an unusual sharing
            // mode). Keep the atomic replace fallback available in either
            // case so a transient existence check cannot turn publication
            // into a credential-unavailable failure.
            let replaced = replaced
                || MoveFileExW(
                    source.as_ptr(),
                    target.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                ) != 0;
            if !replaced {
                return Err(std::io::Error::last_os_error().into());
            };
        }
    }
    let _ = staged.keep();
    Ok(())
}

#[cfg(not(windows))]
#[allow(dead_code)] // Compatibility API; confirmed publication uses a native handle.
pub fn set_wireguard_config_permissions(path: &std::path::Path) -> Result<()> {
    set_owner_only_permissions(path)
}

#[cfg(all(not(unix), not(windows)))]
pub fn set_owner_only_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
pub fn set_owner_only_directory_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn command_output(command: &str) -> Option<String> {
    let output = Command::new(command).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
#[path = "../tests/unit/src/platform.rs"]
mod tests;
