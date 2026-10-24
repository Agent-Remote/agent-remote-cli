//! Device authentication while the caller already owns the login publication lock.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::{device_token_refresh_key, login, record_refresh_time, unix_time_seconds};
use crate::api::ApiClient;
use crate::broker_credentials::{
    broker_credential_storage_required, load_active_broker_credential_strict,
    store_active_broker_credential, BrokerCredential,
};
use crate::config::{AppPaths, Config};
use crate::local_state::{LocalState, RefreshRecord};
use crate::secrets::{device_token_key, SecretStore, SecretValue, StrictSecretError};

/// Neither this result nor its secret implements Debug or Serialize.
pub struct StrictDeviceToken {
    pub server_url: String,
    pub device_id: String,
    pub token: SecretValue,
}

pub async fn load_device_token_strict_locked(
    paths: &AppPaths,
    guard: &login::LoginLock,
    expected_config: &Config,
    cancel: &AtomicBool,
) -> Result<StrictDeviceToken> {
    load_with_store(
        paths,
        guard,
        expected_config,
        cancel,
        &SecretStore::new(paths.clone()),
    )
    .await
}

async fn load_with_store(
    paths: &AppPaths,
    guard: &login::LoginLock,
    expected_config: &Config,
    cancel: &AtomicBool,
    store: &SecretStore,
) -> Result<StrictDeviceToken> {
    load_mode(paths, guard, expected_config, cancel, store, false).await
}

/// Preserve initialized state: renewal may update only the existing refresh key.
#[allow(dead_code)] // The human binary does not expose the library foundation yet.
pub(crate) async fn load_device_token_existing_locked(
    paths: &AppPaths,
    guard: &login::LoginLock,
    expected_config: &Config,
    cancel: &AtomicBool,
) -> Result<StrictDeviceToken> {
    load_mode(
        paths,
        guard,
        expected_config,
        cancel,
        &SecretStore::new(paths.clone()),
        true,
    )
    .await
}

pub(crate) fn existing_refresh_record(paths: &AppPaths, config: &Config) -> Result<RefreshRecord> {
    for directory in [
        paths.home().to_path_buf(),
        paths.bin_dir(),
        paths.dependencies_dir(),
        paths.secrets_dir(),
        paths.wireguard_dir(),
        paths.ssh_dir(),
    ] {
        let metadata = std::fs::symlink_metadata(directory)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                bail!("existing local setup required")
            }
        }
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("existing local setup required")
        }
    }
    RefreshRecord::read(
        paths,
        device_token_refresh_key(
            config.server_url.as_deref().context("server missing")?,
            config
                .active_device_id
                .as_deref()
                .context("device missing")?,
        ),
    )
}

async fn load_mode(
    paths: &AppPaths,
    guard: &login::LoginLock,
    expected_config: &Config,
    cancel: &AtomicBool,
    store: &SecretStore,
    existing_only: bool,
) -> Result<StrictDeviceToken> {
    check_cancel(cancel)?;
    if !guard.protects(paths)? {
        bail!("login lock does not protect this home")
    }
    let config = Config::load_strict(paths)?;
    if &config != expected_config {
        bail!("login configuration changed")
    }
    let existing = if existing_only {
        Some(existing_refresh_record(paths, &config)?)
    } else {
        None
    };
    let server_url = config
        .server_url
        .context("not logged in: server URL is missing")?;
    let device_id = config
        .active_device_id
        .context("not logged in with a registered device")?;
    let key = device_token_key(&server_url, &device_id);
    let broker = crate::secrets::blocking_credential_operation(|| {
        load_active_broker_credential_strict(paths)
    })?;
    check_cancel(cancel)?;
    let mut token = match broker {
        Some(value) => {
            if value.server_url != server_url || value.device_id != device_id {
                bail!("shared Network Broker credential binding does not match login state")
            }
            SecretValue::new(value.access_token)?
        }
        None if broker_credential_storage_required() => {
            bail!("shared Network Broker credential is missing")
        }
        None => store
            .read_strict(&key, cancel)
            .await?
            .context("device token is missing; run agent-remote login")?,
    };
    let refresh_at = if let Some(record) = &existing {
        Some(record.at)
    } else {
        let state = LocalState::open(paths)?;
        state.init_schema()?;
        state
            .get_kv(&device_token_refresh_key(&server_url, &device_id))?
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("device token refresh metadata is invalid")?
    };
    let now = unix_time_seconds()?;
    if refresh_at.is_none_or(|at| at <= now) {
        let api = ApiClient::new(server_url.clone())?;
        let refreshed = tokio::select! {
            result = api.refresh_token(token.as_str()) => result.context("device token refresh failed; run agent-remote login")?,
            _ = canceled(cancel) => return Err(StrictSecretError::Canceled.into()),
        };
        check_cancel(cancel)?;
        let next_token = SecretValue::new(refreshed.access_token.clone())?;
        if broker_credential_storage_required() {
            let credential = BrokerCredential::new(
                &server_url,
                &device_id,
                &refreshed.access_token,
                refreshed.expires_in,
            )?;
            if !crate::secrets::blocking_credential_operation(|| {
                store_active_broker_credential(paths, &credential)
            })? {
                bail!("production Network Broker credential storage is unavailable")
            }
        } else {
            store.write_strict(&key, &next_token, cancel).await?;
        }
        check_cancel(cancel)?;
        if let Some(record) = existing {
            let next = unix_time_seconds()?
                .checked_add((refreshed.expires_in / 2).max(1))
                .context("invalid refresh interval")?;
            record.update(paths, next)?;
        } else {
            record_refresh_time(paths, &server_url, &device_id, refreshed.expires_in)?;
        }
        token = next_token;
    }
    check_cancel(cancel)?;
    Ok(StrictDeviceToken {
        server_url,
        device_id,
        token,
    })
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Acquire) {
        return Err(StrictSecretError::Canceled.into());
    }
    Ok(())
}

async fn canceled(cancel: &AtomicBool) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/strict_device.rs"]
mod tests;
