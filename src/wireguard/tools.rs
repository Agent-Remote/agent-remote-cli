//! Passive WireGuard tool discovery. Explicit overrides never fall through.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::AppPaths;

#[derive(Clone, Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub state: &'static str,
    pub path: Option<PathBuf>,
}

/// Inventory only: no tool execution, privilege prompt, or installation.
pub fn inspect(paths: &AppPaths) -> Vec<ToolInfo> {
    vec![
        find_wg(paths),
        if cfg!(windows) {
            find(paths, "wireguard", "AGENT_REMOTE_WIREGUARD")
        } else {
            find(paths, "wg-quick", "AGENT_REMOTE_WG_QUICK")
        },
    ]
}

pub(super) fn find_wg(paths: &AppPaths) -> ToolInfo {
    find(paths, "wg", "AGENT_REMOTE_WG")
}

fn find(paths: &AppPaths, name: &'static str, override_name: &str) -> ToolInfo {
    let missing = || ToolInfo {
        name,
        state: "missing",
        path: None,
    };
    if let Some(path) = std::env::var_os(override_name) {
        return inspect_candidate(name, Path::new(&path)).unwrap_or_else(missing);
    }
    let executable = crate::platform::executable_name(name);
    let mut candidates = vec![paths.bin_dir().join(&executable)];
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join(&executable));
        }
    }
    #[cfg(windows)]
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        candidates.push(
            PathBuf::from(program_files)
                .join("WireGuard")
                .join(&executable),
        );
    }
    #[cfg(unix)]
    for directory in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        candidates.push(Path::new(directory).join(&executable));
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates
            .extend(std::env::split_paths(&path).map(|directory| directory.join(&executable)));
    }
    candidates
        .into_iter()
        .find_map(|candidate| inspect_candidate(name, &candidate))
        .unwrap_or_else(missing)
}

fn inspect_candidate(name: &'static str, path: &Path) -> Option<ToolInfo> {
    if path.as_os_str().is_empty() {
        return None;
    }
    let absolute = std::path::absolute(path).ok()?;
    protocol_path(&absolute)?;
    let metadata = match std::fs::metadata(&absolute) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(unavailable(name, &absolute)),
    };
    let path = match std::fs::canonicalize(&absolute) {
        Ok(path) => path,
        Err(_) => return Some(unavailable(name, &absolute)),
    };
    // Native paths that cannot be represented in JSON cannot be advertised as
    // usable protocol paths. No lossy replacement is allowed to select a tool.
    protocol_path(&path)?;
    let executable = metadata.is_file() && executable(&path);
    Some(ToolInfo {
        name,
        state: if executable {
            "available"
        } else {
            "not_executable"
        },
        path: Some(path),
    })
}

fn protocol_path(path: &Path) -> Option<()> {
    let text = path.to_str()?;
    (text.len() <= 32768 && !text.chars().any(char::is_control)).then_some(())
}

fn unavailable(name: &'static str, absolute: &Path) -> ToolInfo {
    // This path is display-only. Never run a lexically collapsed path: symlink
    // parents may change its meaning. Available tools must canonicalize above.
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    ToolInfo {
        name,
        state: "not_executable",
        path: Some(normalized),
    }
}

#[cfg(unix)]
fn executable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 }
}

#[cfg(windows)]
fn executable(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

/// Observes this process only; this is not a tunnel-access authorization check.
pub fn elevation() -> &'static str {
    #[cfg(unix)]
    return if unsafe { libc::geteuid() } == 0 {
        "elevated"
    } else {
        "standard"
    };
    #[cfg(windows)]
    windows_elevation()
}

#[cfg(windows)]
fn windows_elevation() -> &'static str {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 || raw.is_null()
    {
        return "unknown";
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            std::ptr::from_mut(&mut elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    } == 0
        || length as usize != std::mem::size_of::<TOKEN_ELEVATION>()
    {
        return "unknown";
    }
    if elevation.TokenIsElevated != 0 {
        "elevated"
    } else {
        "standard"
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_tools.rs"]
mod tests;
