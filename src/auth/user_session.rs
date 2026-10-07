use std::fs::{File, OpenOptions};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::{ApiClient, ApiError, AuthToken};
use crate::config::AppPaths;
use crate::secrets::{user_token_key, SecretBackend, SecretStore};

#[derive(Serialize, Deserialize)]
struct UserSession {
    version: u8,
    token: AuthToken,
    refresh_at: u64,
    expires_at: u64,
    session_expires_at: u64,
}

pub fn user_login_error() -> anyhow::Error {
    anyhow::anyhow!("error_code=login_required state=installed admission=unknown next_action=login next_command=agent-remote login stale=false")
}

async fn user_credential_lock(paths: &AppPaths, server_url: &str) -> Result<File> {
    paths.ensure_base_dirs()?;
    let name = format!(
        "user-session-{:x}.lock",
        Sha256::digest(server_url.as_bytes())
    );
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(paths.secrets_dir().join(name))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            bail!("user credential lock has unsafe ownership or permissions")
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => bail!("user credential is busy or unavailable; retry the command"),
        }
    }
}

pub async fn store_user_token(
    paths: &AppPaths,
    server_url: &str,
    token: &AuthToken,
) -> Result<SecretBackend> {
    let _lock = user_credential_lock(paths, server_url).await?;
    let store = SecretStore::new(paths.clone());
    let backend = store.set_secret(&user_token_key(server_url), &token.access_token)?;
    load_locked(&store, server_url).await?;
    Ok(backend)
}

pub async fn load_user_token(paths: &AppPaths, server_url: &str) -> Result<Option<String>> {
    let _lock = user_credential_lock(paths, server_url).await?;
    let store = SecretStore::new(paths.clone());
    load_locked(&store, server_url).await
}

async fn load_locked(store: &SecretStore, server_url: &str) -> Result<Option<String>> {
    let key = user_token_key(server_url);
    let Some(raw) = store.get_secret(&key)? else {
        return Ok(None);
    };
    let client = ApiClient::new(server_url.to_owned())?;
    let now = super::unix_time_seconds()?;
    let token = if raw.starts_with('{') {
        let session: UserSession = serde_json::from_str(&raw).map_err(|_| {
            anyhow::anyhow!("stored user credential is malformed; run agent-remote login")
        })?;
        if session.version != 1 || session.session_expires_at <= now {
            return Err(user_login_error());
        }
        if session.refresh_at > now && session.expires_at > now {
            return Ok(Some(session.token.access_token));
        }
        let refresh = session
            .token
            .refresh_token
            .as_deref()
            .context("stored refresh credential is missing; run agent-remote login")?;
        client
            .refresh_cli_session(refresh)
            .await
            .map_err(refresh_error)?
    } else {
        match client.create_cli_session(&raw).await {
            Ok(token) => token,
            Err(error) if error.status_code() == Some(404) => return Ok(Some(raw)),
            Err(error) => return Err(refresh_error(error)),
        }
    };
    let session_ttl = token
        .refresh_expires_in
        .filter(|ttl| *ttl > 0)
        .context("Server returned an invalid CLI session lifetime")?;
    if token.access_token.is_empty()
        || token.expires_in == 0
        || token
            .refresh_token
            .as_ref()
            .is_none_or(|value| value.is_empty())
    {
        bail!("Server returned an incomplete CLI credential pair")
    }
    let result = token.access_token.clone();
    let session = UserSession {
        version: 1,
        refresh_at: now.saturating_add((token.expires_in / 2).max(1)),
        expires_at: now.saturating_add(token.expires_in),
        session_expires_at: now.saturating_add(session_ttl),
        token,
    };
    store.set_secret(&key, &serde_json::to_string(&session)?)?;
    Ok(Some(result))
}

pub async fn logout_user(paths: &AppPaths, server_url: &str, revoke: bool) -> Result<()> {
    let _lock = user_credential_lock(paths, server_url).await?;
    let store = SecretStore::new(paths.clone());
    let result = if revoke {
        match load_locked(&store, server_url).await {
            Ok(Some(token)) => ApiClient::new(server_url.to_owned())?
                .logout(&token)
                .await
                .map_err(anyhow::Error::from),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        }
    } else {
        Ok(())
    };
    store.delete_secret(&user_token_key(server_url))?;
    result
}

fn refresh_error(error: ApiError) -> anyhow::Error {
    if matches!(error.status_code(), Some(401 | 403)) {
        user_login_error()
    } else {
        anyhow::anyhow!(
            "CLI credential renewal failed; retry when the server is reachable (HTTP {:?})",
            error.status_code()
        )
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/auth/user_session.rs"]
mod tests;
