use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

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

#[cfg(windows)]
pub fn set_owner_only_permissions(path: &std::path::Path) -> Result<()> {
    let username = env::var("USERNAME").context("USERNAME is not set")?;
    let principal = env::var("USERDOMAIN")
        .ok()
        .filter(|domain| !domain.is_empty())
        .map(|domain| format!("{domain}\\{username}"))
        .unwrap_or(username);
    let status = Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{principal}:(F)"))
        .status()
        .context("failed to execute icacls.exe")?;
    if status.success() {
        Ok(())
    } else {
        bail!("icacls.exe exited with {status}")
    }
}

#[cfg(all(not(unix), not(windows)))]
pub fn set_owner_only_permissions(_path: &std::path::Path) -> Result<()> {
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
mod tests {
    use super::{executable_name, ssh_binary};

    #[test]
    fn executable_names_follow_the_host_platform() {
        let expected = if cfg!(windows) {
            "mutagen.exe"
        } else {
            "mutagen"
        };
        assert_eq!(executable_name("mutagen"), expected);
    }

    #[test]
    fn ssh_binary_follows_the_host_platform() {
        let expected = if cfg!(windows) { "ssh.exe" } else { "ssh" };
        assert_eq!(
            ssh_binary().file_name().and_then(|value| value.to_str()),
            Some(expected)
        );
    }
}
