use std::env;
use std::fmt;
use std::fs;
#[cfg(all(unix, not(target_os = "macos")))]
use std::io::Write;
#[cfg(unix)]
use std::process::Command;
#[cfg(all(unix, not(target_os = "macos")))]
use std::process::Stdio;

#[cfg(not(windows))]
use anyhow::anyhow;
use anyhow::{Context, Result};

use crate::config::AppPaths;

const SERVICE: &str = "agent-remote";

#[derive(Clone)]
pub struct SecretStore {
    paths: AppPaths,
    prefer_system: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretBackend {
    System,
    File,
}

impl fmt::Display for SecretBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => write!(formatter, "system credential store"),
            Self::File => write!(formatter, "file fallback"),
        }
    }
}

impl SecretStore {
    pub fn new(paths: AppPaths) -> Self {
        let prefer_system = env::var("AGENT_REMOTE_SECRET_BACKEND")
            .map(|value| value != "file")
            .unwrap_or(true);
        Self {
            paths,
            prefer_system,
        }
    }

    #[cfg(test)]
    pub fn file_only(paths: AppPaths) -> Self {
        Self {
            paths,
            prefer_system: false,
        }
    }

    pub fn set_secret(&self, key: &str, value: &str) -> Result<SecretBackend> {
        if self.prefer_system && set_system_secret(key, value).is_ok() {
            let _ = self.delete_file_secret(key);
            return Ok(SecretBackend::System);
        }
        self.set_file_secret(key, value)?;
        Ok(SecretBackend::File)
    }

    pub fn get_secret(&self, key: &str) -> Result<Option<String>> {
        if self.prefer_system {
            match get_system_secret(key) {
                Ok(Some(value)) => return Ok(Some(value)),
                Ok(None) => {}
                Err(_) => {}
            }
        }
        self.get_file_secret(key)
    }

    pub fn delete_secret(&self, key: &str) -> Result<()> {
        if self.prefer_system {
            let _ = delete_system_secret(key);
        }
        self.delete_file_secret(key)
    }

    fn secret_path(&self, key: &str) -> std::path::PathBuf {
        self.paths
            .secrets_dir()
            .join(format!("{}.secret", sanitize_key(key)))
    }

    fn set_file_secret(&self, key: &str, value: &str) -> Result<()> {
        self.paths.ensure_base_dirs()?;
        let path = self.secret_path(key);
        fs::write(&path, value).with_context(|| format!("failed to write {}", path.display()))?;
        crate::platform::set_owner_only_permissions(&path)?;
        Ok(())
    }

    fn get_file_secret(&self, key: &str) -> Result<Option<String>> {
        let path = self.secret_path(key);
        if !path.exists() {
            return Ok(None);
        }
        let value = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok(Some(value))
    }

    fn delete_file_secret(&self, key: &str) -> Result<()> {
        let path = self.secret_path(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("failed to remove {}", path.display()))
            }
        }
    }
}

pub fn user_token_key(server_url: &str) -> String {
    format!("user-token:{server_url}")
}

pub fn device_token_key(server_url: &str, device_id: &str) -> String {
    format!("device-token:{server_url}:{device_id}")
}

pub fn wireguard_private_key_key(server_url: &str, device_id: &str) -> String {
    format!("wireguard-private-key:{server_url}:{device_id}")
}

fn sanitize_key(key: &str) -> String {
    key.chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => character,
            _ => '_',
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn set_system_secret(key: &str, value: &str) -> Result<()> {
    let status = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            SERVICE,
            "-a",
            key,
            "-w",
            value,
        ])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("security add-generic-password failed"))
    }
}

#[cfg(target_os = "macos")]
fn get_system_secret(key: &str) -> Result<Option<String>> {
    let output = Command::new("security")
        .args(["find-generic-password", "-s", SERVICE, "-a", key, "-w"])
        .output()?;
    if output.status.success() {
        Ok(Some(
            String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_string(),
        ))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
fn delete_system_secret(key: &str) -> Result<()> {
    let output = Command::new("security")
        .args(["delete-generic-password", "-s", SERVICE, "-a", key])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!("security delete-generic-password failed"))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn set_system_secret(key: &str, value: &str) -> Result<()> {
    let mut child = Command::new("secret-tool")
        .args([
            "store", "--label", SERVICE, "service", SERVICE, "account", key,
        ])
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .context("failed to open secret-tool stdin")?
        .write_all(value.as_bytes())?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("secret-tool store failed"))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn get_system_secret(key: &str) -> Result<Option<String>> {
    let output = Command::new("secret-tool")
        .args(["lookup", "service", SERVICE, "account", key])
        .output()?;
    if output.status.success() {
        Ok(Some(
            String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_string(),
        ))
    } else {
        Ok(None)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn delete_system_secret(key: &str) -> Result<()> {
    let status = Command::new("secret-tool")
        .args(["clear", "service", SERVICE, "account", key])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("secret-tool clear failed"))
    }
}

#[cfg(windows)]
fn set_system_secret(key: &str, value: &str) -> Result<()> {
    use windows_sys::Win32::Security::Credentials::{
        CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    let mut target = windows_target(key);
    let mut blob = value.as_bytes().to_vec();
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: blob
            .len()
            .try_into()
            .context("secret is too large for Windows Credential Manager")?,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..CREDENTIALW::default()
    };
    let written = unsafe { CredWriteW(&credential, 0) };
    if written == 0 {
        Err(std::io::Error::last_os_error()).context("CredWriteW failed")
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn get_system_secret(key: &str) -> Result<Option<String>> {
    use std::ptr;
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    let target = windows_target(key);
    let mut raw: *mut CREDENTIALW = ptr::null_mut();
    let read = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
    if read == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(1168) {
            return Ok(None);
        }
        return Err(error).context("CredReadW failed");
    }
    let result = unsafe {
        let credential = &*raw;
        let blob = std::slice::from_raw_parts(
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        );
        String::from_utf8(blob.to_vec()).context("stored credential is not valid UTF-8")
    };
    unsafe { CredFree(raw.cast()) };
    result.map(Some)
}

#[cfg(windows)]
fn delete_system_secret(key: &str) -> Result<()> {
    use windows_sys::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};

    let target = windows_target(key);
    let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if deleted == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(1168) {
            return Err(error).context("CredDeleteW failed");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_target(key: &str) -> Vec<u16> {
    format!("{SERVICE}/{key}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(all(not(unix), not(windows)))]
fn set_system_secret(_key: &str, _value: &str) -> Result<()> {
    Err(anyhow!("platform credential store is not supported"))
}

#[cfg(all(not(unix), not(windows)))]
fn get_system_secret(_key: &str) -> Result<Option<String>> {
    Err(anyhow!("platform credential store is not supported"))
}

#[cfg(all(not(unix), not(windows)))]
fn delete_system_secret(_key: &str) -> Result<()> {
    Err(anyhow!("platform credential store is not supported"))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::config::AppPaths;

    use super::{device_token_key, wireguard_private_key_key, SecretBackend, SecretStore};

    #[test]
    fn file_secret_roundtrip() {
        let dir = tempdir().unwrap();
        let paths = AppPaths::from_home(dir.path().join("agent-remote"));
        let store = SecretStore::file_only(paths);
        let key = device_token_key("https://example.test", "dev_1");
        let backend = store.set_secret(&key, "token-value").unwrap();
        assert_eq!(backend, SecretBackend::File);
        assert_eq!(
            store.get_secret(&key).unwrap().as_deref(),
            Some("token-value")
        );
        store.delete_secret(&key).unwrap();
        assert!(store.get_secret(&key).unwrap().is_none());
    }

    #[test]
    fn wireguard_private_key_is_scoped_to_server_and_device() {
        assert_ne!(
            wireguard_private_key_key("https://one.test", "device-1"),
            wireguard_private_key_key("https://two.test", "device-1")
        );
        assert_ne!(
            wireguard_private_key_key("https://one.test", "device-1"),
            wireguard_private_key_key("https://one.test", "device-2")
        );
    }
}
