#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::config::AppPaths;

const STATE_VERSION: u8 = 2;
const STATE_FILENAME: &str = "node-install-exchange.json";
const MAX_STATE_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeInstallStage {
    Prepared,
    ReleaseInstalled,
    Issued,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInstallExchangeState {
    pub version: u8,
    pub server_url: String,
    pub node_id: String,
    pub node_fingerprint_sha256: String,
    pub exchange_id: String,
    pub enable_ego_browser: bool,
    pub release_version: String,
    pub release_target: String,
    pub release_sha256: Option<String>,
    pub stage: NodeInstallStage,
    pub created_at_unix: u64,
    pub expires_at: Option<String>,
}

impl NodeInstallExchangeState {
    pub fn prepared(
        server_url: String,
        node_id: String,
        node_fingerprint_sha256: String,
        enable_ego_browser: bool,
        release_version: String,
        release_target: String,
        created_at_unix: u64,
    ) -> Result<Self> {
        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        let exchange_id = hex_lower(&random);
        let state = Self {
            version: STATE_VERSION,
            server_url,
            node_id,
            node_fingerprint_sha256,
            exchange_id,
            enable_ego_browser,
            release_version,
            release_target,
            release_sha256: None,
            stage: NodeInstallStage::Prepared,
            created_at_unix,
            expires_at: None,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn mark_release_installed(&mut self, release_sha256: String) -> Result<()> {
        self.stage = NodeInstallStage::ReleaseInstalled;
        self.release_sha256 = Some(release_sha256);
        self.expires_at = None;
        self.validate()
    }

    pub fn mark_issued(&mut self, expires_at: String) -> Result<()> {
        self.stage = NodeInstallStage::Issued;
        self.expires_at = Some(expires_at);
        self.validate()
    }

    pub fn matches(
        &self,
        server_url: &str,
        node_id: &str,
        node_fingerprint_sha256: &str,
        enable_ego_browser: bool,
        release_version: &str,
        release_target: &str,
    ) -> bool {
        self.server_url == server_url
            && self.node_id == node_id
            && self.node_fingerprint_sha256 == node_fingerprint_sha256
            && self.enable_ego_browser == enable_ego_browser
            && self.release_version == release_version
            && self.release_target == release_target
    }

    fn validate(&self) -> Result<()> {
        if self.version != STATE_VERSION
            || self.server_url.is_empty()
            || self.server_url.len() > 2048
            || self.node_id.is_empty()
            || self.node_id.len() > 128
            || !is_lower_hex(&self.node_fingerprint_sha256, 64)
            || !is_lower_hex(&self.exchange_id, 32)
            || !valid_release_version(&self.release_version)
            || !valid_release_target(&self.release_target)
            || self.created_at_unix == 0
            || self
                .expires_at
                .as_deref()
                .is_some_and(|value| value.is_empty() || value.len() > 64 || !value.is_ascii())
            || (self.stage == NodeInstallStage::Prepared && self.expires_at.is_some())
            || (self.stage == NodeInstallStage::Prepared && self.release_sha256.is_some())
            || (self.stage == NodeInstallStage::ReleaseInstalled
                && (self.release_sha256.is_none() || self.expires_at.is_some()))
            || (self.stage == NodeInstallStage::Issued
                && (self.release_sha256.is_none() || self.expires_at.is_none()))
            || self
                .release_sha256
                .as_deref()
                .is_some_and(|value| !is_lower_hex(value, 64))
        {
            bail!("local Node installation exchange state is invalid")
        }
        Ok(())
    }
}

fn valid_release_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
}

fn valid_release_target(value: &str) -> bool {
    matches!(
        value,
        "linux-amd64-glibc" | "linux-amd64-musl" | "linux-arm64-glibc" | "linux-arm64-musl"
    )
}

pub fn load(paths: &AppPaths) -> Result<Option<NodeInstallExchangeState>> {
    let path = state_path(paths);
    let bytes = match read_owner_only_file(&path, MAX_STATE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("local Node installation exchange state is unsafe")
        }
    };
    let state: NodeInstallExchangeState = serde_json::from_slice(&bytes)
        .context("local Node installation exchange state is malformed")?;
    state.validate()?;
    Ok(Some(state))
}

pub fn save(paths: &AppPaths, state: &NodeInstallExchangeState) -> Result<()> {
    state.validate()?;
    prepare_state_directory(paths)?;
    let destination = state_path(paths);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            let _ = read_owner_only_file(&destination, MAX_STATE_BYTES)
                .context("local Node installation exchange state is unsafe")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let bytes = serde_json::to_vec(state)?;
    let temporary = paths.home().join(format!(
        ".node-install-exchange-{}-{}.tmp",
        std::process::id(),
        random_suffix()
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &destination)
            .with_context(|| format!("failed to replace {}", destination.display()))?;
        let _ = read_owner_only_file(&destination, MAX_STATE_BYTES)
            .context("written Node installation exchange state is unsafe")?;
        sync_directory(paths.home())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn clear(paths: &AppPaths) -> Result<()> {
    let path = state_path(paths);
    match read_owner_only_file(&path, MAX_STATE_BYTES) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).context("local Node installation exchange state is unsafe")
        }
    }
    fs::remove_file(&path).context("failed to clear local Node installation exchange state")?;
    sync_directory(paths.home())
}

fn state_path(paths: &AppPaths) -> PathBuf {
    paths.home().join(STATE_FILENAME)
}

fn prepare_state_directory(paths: &AppPaths) -> Result<()> {
    match fs::symlink_metadata(paths.home()) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("Agent Remote state directory is unsafe")
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(paths.home())?;
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(paths.home())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("Agent Remote state directory is unsafe")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!("Agent Remote state directory has unsafe ownership")
        }
        fs::set_permissions(paths.home(), fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn read_owner_only_file(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    validate_owner_only_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let after = file.metadata()?;
    validate_owner_only_metadata(&after)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "owner-only state changed while opening",
            ));
        }
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "owner-only state is oversized",
        ));
    }
    Ok(bytes)
}

fn validate_owner_only_metadata(metadata: &fs::Metadata) -> std::io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "owner-only state is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "owner-only state has unsafe ownership, links, or permissions",
            ));
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn random_suffix() -> String {
    let mut random = [0_u8; 12];
    OsRng.fill_bytes(&mut random);
    hex_lower(&random)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[path = "../tests/unit/src/node_install_state.rs"]
mod tests;
