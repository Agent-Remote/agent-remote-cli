use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::api::{ApiClient, AuthToken};
use crate::broker_credentials::{
    broker_credential_storage_required, load_active_broker_credential,
    store_active_broker_credential, BrokerCredential,
};
use crate::config::{AppPaths, Config};
use crate::local_state::LocalState;
use crate::secrets::{device_token_key, SecretBackend, SecretStore};

pub fn store_device_token(
    paths: &AppPaths,
    server_url: &str,
    device_id: &str,
    token: &AuthToken,
) -> Result<SecretBackend> {
    if broker_credential_storage_required() {
        let credential =
            BrokerCredential::new(server_url, device_id, &token.access_token, token.expires_in)?;
        if !store_active_broker_credential(paths, &credential)? {
            anyhow::bail!("production Network Broker credential storage is unavailable")
        }
        let store = SecretStore::new(paths.clone());
        store.delete_secret(&device_token_key(server_url, device_id))?;
        record_refresh_time(paths, server_url, device_id, token.expires_in)?;
        return Ok(SecretBackend::System);
    }
    let store = SecretStore::new(paths.clone());
    let backend = store.set_secret(
        &device_token_key(server_url, device_id),
        &token.access_token,
    )?;
    record_refresh_time(paths, server_url, device_id, token.expires_in)?;
    Ok(backend)
}

pub fn has_device_token(paths: &AppPaths, server_url: &str, device_id: &str) -> Result<bool> {
    if let Some(credential) = load_active_broker_credential(paths)? {
        return Ok(credential.server_url == server_url && credential.device_id == device_id);
    }
    Ok(SecretStore::new(paths.clone())
        .get_secret(&device_token_key(server_url, device_id))?
        .is_some())
}

pub async fn load_device_token(paths: &AppPaths) -> Result<(String, String, String)> {
    let config = Config::load(paths)?;
    let server_url = config
        .server_url
        .context("not logged in: server URL is missing")?;
    let device_id = config
        .active_device_id
        .context("not logged in with a registered device")?;
    let key = device_token_key(&server_url, &device_id);
    let broker_credential = load_active_broker_credential(paths)?;
    let mut token = match broker_credential {
        Some(credential) => {
            if credential.server_url != server_url || credential.device_id != device_id {
                anyhow::bail!("shared Network Broker credential binding does not match login state")
            }
            credential.access_token
        }
        None if broker_credential_storage_required() => {
            anyhow::bail!("shared Network Broker credential is missing; run agent-remote login")
        }
        None => SecretStore::new(paths.clone())
            .get_secret(&key)?
            .context("device token is missing; run agent-remote login")?,
    };

    let state = LocalState::open(paths)?;
    state.init_schema()?;
    let refresh_at = state
        .get_kv(&device_token_refresh_key(&server_url, &device_id))?
        .and_then(|value| value.parse::<u64>().ok());
    let now = unix_time_seconds()?;
    if refresh_at.is_none_or(|refresh_at| refresh_at <= now) {
        let refreshed = ApiClient::new(server_url.clone())?
            .refresh_token(&token)
            .await
            .context("device token refresh failed; run agent-remote login")?;
        let backend = store_device_token(paths, &server_url, &device_id, &refreshed)?;
        if backend == SecretBackend::File && broker_credential_storage_required() {
            anyhow::bail!("production device credential unexpectedly used file storage")
        }
        token = refreshed.access_token;
    }

    Ok((server_url, device_id, token))
}

pub fn clear_device_token_refresh(
    paths: &AppPaths,
    server_url: &str,
    device_id: &str,
) -> Result<()> {
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    state.delete_kv(&device_token_refresh_key(server_url, device_id))
}

fn record_refresh_time(
    paths: &AppPaths,
    server_url: &str,
    device_id: &str,
    expires_in: u64,
) -> Result<()> {
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    let refresh_at = unix_time_seconds()? + (expires_in / 2).max(1);
    state.set_kv(
        &device_token_refresh_key(server_url, device_id),
        &refresh_at.to_string(),
    )
}

fn device_token_refresh_key(server_url: &str, device_id: &str) -> String {
    format!("device-token-refresh-at:{server_url}:{device_id}")
}

fn unix_time_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::config::AppPaths;
    use crate::local_state::LocalState;

    use crate::secrets::{device_token_key, SecretStore};

    use super::{device_token_refresh_key, has_device_token, record_refresh_time};

    #[test]
    fn stores_non_secret_refresh_time() {
        let dir = tempdir().unwrap();
        let paths = AppPaths::from_home(dir.path().join("agent-remote"));
        record_refresh_time(&paths, "https://example.test", "device-1", 3600).unwrap();

        let state = LocalState::open(&paths).unwrap();
        state.init_schema().unwrap();
        assert!(state
            .get_kv(&device_token_refresh_key(
                "https://example.test",
                "device-1"
            ))
            .unwrap()
            .is_some());
    }

    #[test]
    fn detects_a_device_token_in_the_standard_secret_store() {
        let dir = tempdir().unwrap();
        let paths = AppPaths::from_home(dir.path().join("agent-remote"));
        SecretStore::new(paths.clone())
            .set_secret(
                &device_token_key("https://example.test", "device-1"),
                "device-token",
            )
            .unwrap();

        assert!(has_device_token(&paths, "https://example.test", "device-1").unwrap());
        assert!(!has_device_token(&paths, "https://example.test", "device-2").unwrap());
    }
}
