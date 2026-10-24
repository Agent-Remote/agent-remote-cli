//! Shared login publication for human CLI and desktop callers.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::{ApiClient, AuthToken, RegisterDeviceRequest};
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManager;
use crate::local_state::{LocalDevice, LocalState};
use crate::{platform, secrets::SecretBackend};

pub struct RegistrationOptions {
    pub device_name: Option<String>,
    pub ssh_public_key: Option<PathBuf>,
    pub wireguard_public_key: Option<String>,
    pub skip_device_registration: bool,
}

/// Registration input captured before authentication starts. Paths are resolved
/// once; final publication cannot reread a changed public-key file.
pub struct PreparedRegistration(Option<PreparedDevice>);

struct PreparedDevice {
    name: String,
    platform: String,
    ssh_public_key: String,
    wireguard_public_key: Option<String>,
    request_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PendingRegistration {
    server_url: String,
    request_id: String,
    name: String,
    platform: String,
    cli_version: String,
    ssh_public_key: String,
    wireguard_public_key: Option<String>,
    existing_device_id: Option<String>,
}

fn pending_registration_key(server: &str) -> String {
    format!("device_registration.pending.v1:{}", server)
}

impl RegistrationOptions {
    pub fn prepare(self) -> Result<PreparedRegistration> {
        if self.skip_device_registration {
            return Ok(PreparedRegistration(None));
        }
        Ok(PreparedRegistration(Some(PreparedDevice {
            name: self
                .device_name
                .unwrap_or_else(platform::default_device_name),
            platform: platform::current_platform()?,
            ssh_public_key: read_ssh_public_key(self.ssh_public_key.as_deref())?,
            wireguard_public_key: self.wireguard_public_key,
            request_id: Uuid::new_v4().to_string(),
        })))
    }
}

pub struct LoginOutcome {
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub backend: SecretBackend,
    pub expires_in: u64,
}

#[derive(Debug)]
pub enum LoginStage {
    AuthenticationUnknown,
    ContextChanged,
    RegistrationRejected,
    RegistrationUnknown,
    Persistence,
}

impl std::fmt::Display for LoginStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AuthenticationUnknown => {
                "authentication returned an invalid credential receipt; inspect current status"
            }
            Self::ContextChanged => "configuration changed before login publication",
            Self::RegistrationRejected => "device registration was rejected",
            Self::RegistrationUnknown => {
                "device registration outcome is unknown; inspect server devices before retrying"
            }
            Self::Persistence => {
                "login was accepted but local publication is incomplete; inspect current status"
            }
        })
    }
}

/// Serializes login publication and logout across CLI/desktop processes.
pub struct LoginLock {
    _file: File,
    home: PathBuf,
}

impl LoginLock {
    pub(super) fn protects(&self, paths: &AppPaths) -> Result<bool> {
        Ok(self.home
            == std::path::absolute(paths.home())?
                .components()
                .collect::<PathBuf>())
    }
}

pub async fn lock(paths: &AppPaths) -> Result<LoginLock> {
    Ok(LoginLock {
        _file: super::user_session::user_credential_lock(paths, "client-login-publication-v1")
            .await?,
        home: std::path::absolute(paths.home())?.components().collect(),
    })
}

/// Existing-state workflows must not initialize publication directories or files.
#[allow(dead_code)] // Used by the library verified-sync foundation.
pub(crate) async fn lock_existing(paths: &AppPaths) -> Result<LoginLock> {
    Ok(LoginLock {
        _file: super::user_session::user_credential_lock_existing(
            paths,
            "client-login-publication-v1",
        )
        .await?,
        home: std::path::absolute(paths.home())?.components().collect(),
    })
}

/// Only public-key records are accepted; private keys never enter registration.
pub fn read_ssh_public_key(explicit: Option<&Path>) -> Result<String> {
    let path = explicit
        .map(Path::to_path_buf)
        .or_else(platform::default_ssh_public_key_path)
        .context(
            "missing SSH public key; pass --ssh-public-key or use --skip-device-registration",
        )?;
    let mut bytes = Vec::new();
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        bail!("SSH public key must be a regular file")
    }
    file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 {
        bail!("SSH public key is too large")
    }
    let value = String::from_utf8(bytes)?.trim().to_owned();
    if value.contains(['\n', '\r']) {
        bail!("expected one SSH public key record")
    }
    let mut parts = value.split_whitespace();
    let kind = parts.next().context("SSH public key is empty")?;
    if !matches!(
        kind,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) {
        bail!("expected an SSH public key, not private-key material")
    }
    let decoded = STANDARD.decode(parts.next().context("SSH public key data is missing")?)?;
    let length = decoded
        .get(..4)
        .context("SSH public key data is truncated")?;
    let length = u32::from_be_bytes([length[0], length[1], length[2], length[3]]) as usize;
    if decoded.get(4..4usize.saturating_add(length)) != Some(kind.as_bytes())
        || decoded.len() <= 4 + length
    {
        bail!("SSH public key type does not match its data")
    }
    Ok(value)
}

/// Publish existing authentication through the same storage used by CLI commands.
/// Expected context is supplied by desktop confirmation; human CLI loads it here.
pub async fn finalize(
    paths: &AppPaths,
    server: &str,
    token: &AuthToken,
    registration: PreparedRegistration,
    expected: Option<&Config>,
) -> Result<LoginOutcome> {
    if token.access_token.is_empty() || token.expires_in == 0 {
        return Err(anyhow::Error::msg(LoginStage::AuthenticationUnknown));
    }
    let _guard = lock(paths).await?;
    let before = Config::load(paths)?;
    if expected.is_some_and(|expected| *expected != before) {
        return Err(anyhow::Error::msg(LoginStage::ContextChanged));
    }
    let mut config = before.clone();
    let existing_device_id = before
        .server_url
        .as_deref()
        .filter(|url| url.trim().trim_end_matches('/') == server)
        .and(before.active_device_id.clone());
    config.server_url = Some(server.to_owned());
    // A user-only login must not retain a device from a different server.
    config.active_device_id = existing_device_id.clone();
    DependencyManager::new(paths.clone()).ensure_manifest()?;
    let Some(mut prepared) = registration.0 else {
        let backend = super::store_user_token(paths, server, token)
            .await
            .context(LoginStage::Persistence)?;
        publish_mode(paths, "user_token").context(LoginStage::Persistence)?;
        config
            .save_if_unchanged(paths, &before)
            .context(LoginStage::Persistence)?;
        return Ok(LoginOutcome {
            device_id: None,
            device_name: None,
            backend,
            expires_in: token.expires_in,
        });
    };
    // Reuse an unfinished request only when its complete public intent matches.
    // A stale or malformed record blocks publication rather than being replaced
    // by a new key that would make the original outcome unrecoverable.
    let state = LocalState::open(paths).context(LoginStage::Persistence)?;
    state.init_schema().context(LoginStage::Persistence)?;
    let pending_key = pending_registration_key(server);
    if let Some(raw) = state
        .get_kv(&pending_key)
        .context(LoginStage::Persistence)?
    {
        let previous: PendingRegistration = serde_json::from_str(&raw)
            .map_err(|_| anyhow::Error::msg(LoginStage::RegistrationUnknown))?;
        if previous.server_url != server
            || previous.name != prepared.name
            || previous.platform != prepared.platform
            || previous.cli_version != crate::cli::VERSION
            || previous.ssh_public_key != prepared.ssh_public_key
            || previous.wireguard_public_key != prepared.wireguard_public_key
            || previous.existing_device_id != existing_device_id
            || Uuid::parse_str(&previous.request_id)
                .ok()
                .is_none_or(|id| id.to_string() != previous.request_id)
        {
            return Err(anyhow::Error::msg(LoginStage::RegistrationUnknown));
        }
        prepared.request_id = previous.request_id;
    }
    let request = RegisterDeviceRequest {
        name: prepared.name.clone(),
        platform: prepared.platform.clone(),
        cli_version: crate::cli::VERSION.to_owned(),
        ssh_public_key: prepared.ssh_public_key.clone(),
        wireguard_public_key: prepared.wireguard_public_key.clone(),
        existing_device_id,
        request_id: Some(prepared.request_id.clone()),
    };
    let pending = PendingRegistration {
        server_url: server.to_owned(),
        request_id: prepared.request_id.clone(),
        name: request.name.clone(),
        platform: request.platform.clone(),
        cli_version: request.cli_version.clone(),
        ssh_public_key: request.ssh_public_key.clone(),
        wireguard_public_key: request.wireguard_public_key.clone(),
        existing_device_id: request.existing_device_id.clone(),
    };
    // Persist the caller key before the first mutation. A lost response can
    // therefore be recovered by this exact key instead of guessing from the
    // device list. The record contains public registration intent only.
    state
        .set_kv(
            &pending_key,
            &serde_json::to_string(&pending).context(LoginStage::Persistence)?,
        )
        .context(LoginStage::Persistence)?;
    let client = ApiClient::new(server.to_owned())?;
    let registration = match client.register_device(&token.access_token, &request).await {
        Ok(response) => response.data,
        Err(error)
            if !error
                .status_code()
                .is_some_and(|status| (400..500).contains(&status)) =>
        {
            // The POST may have committed before its response was lost. Query
            // only the original request key; a failed lookup remains unknown.
            match client
                .get_device_registration(&token.access_token, &prepared.request_id)
                .await
            {
                Ok(response) => response.data,
                Err(_) => {
                    return Err(anyhow::Error::from(error).context(LoginStage::RegistrationUnknown))
                }
            }
        }
        Err(error) => {
            return Err(anyhow::Error::from(error).context(LoginStage::RegistrationRejected))
        }
    };
    let device = registration.device;
    if device.id.is_empty()
        || registration.device_token.access_token.is_empty()
        || registration.device_token.expires_in == 0
        || request
            .existing_device_id
            .as_ref()
            .is_some_and(|id| *id != device.id)
    {
        return Err(anyhow::Error::msg(LoginStage::RegistrationUnknown));
    }
    let backend = super::store_device_token(paths, server, &device.id, &registration.device_token)
        .context(LoginStage::Persistence)?;
    super::store_user_token(paths, server, token)
        .await
        .context(LoginStage::Persistence)?;
    let state = LocalState::open(paths).context(LoginStage::Persistence)?;
    state.init_schema().context(LoginStage::Persistence)?;
    state
        .upsert_device(&LocalDevice {
            id: device.id.clone(),
            server_url: server.to_owned(),
            name: device.name.clone(),
            platform: device.platform,
            status: device.status,
            ssh_key_id: Some(registration.ssh_key_id),
            wireguard_peer_id: registration.wireguard_peer_id,
            created_at: Some(device.created_at),
            last_seen_at: device.last_seen_at,
        })
        .context(LoginStage::Persistence)?;
    state
        .set_kv("last_login_mode", "device_token")
        .context(LoginStage::Persistence)?;
    config.active_device_id = Some(device.id.clone());
    config
        .save_if_unchanged(paths, &before)
        .context(LoginStage::Persistence)?;
    // Keep the original key until every local publication step succeeds, so
    // a retry after a crash can recover the same server receipt.
    state
        .delete_kv(&pending_key)
        .context(LoginStage::Persistence)?;
    Ok(LoginOutcome {
        device_id: Some(device.id),
        device_name: Some(device.name),
        backend,
        expires_in: registration.device_token.expires_in,
    })
}

fn publish_mode(paths: &AppPaths, mode: &str) -> Result<()> {
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    state.set_kv("last_login_mode", mode)
}
