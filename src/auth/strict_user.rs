//! Read-only user credentials for administrator recovery. Never refreshes or migrates.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::{
    api::AuthToken,
    config::AppPaths,
    secrets::{user_token_key, SecretStore, SecretValue},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    version: u8,
    token: AuthToken,
    refresh_at: u64,
    expires_at: u64,
    session_expires_at: u64,
}

/// Reads only the explicit user slot; an active device never supplies authority.
pub async fn read(paths: &AppPaths, server: &str, cancel: &AtomicBool) -> Result<SecretValue> {
    let raw = SecretStore::new(paths.clone())
        .read_strict(&user_token_key(server), cancel)
        .await?
        .context("administrator user login is required")?;
    if cancel.load(Ordering::Acquire) {
        bail!("credential operation canceled");
    }
    access_token(raw, super::unix_time_seconds()?)
}

/// Mutation callers serialize with legacy user refresh after the home login lock.
pub(crate) async fn lock(paths: &AppPaths, server: &str) -> Result<std::fs::File> {
    super::user_session::user_credential_lock(paths, server).await
}

fn access_token(raw: SecretValue, now: u64) -> Result<SecretValue> {
    if !raw.as_str().trim_start().starts_with('{') {
        if raw.as_str().chars().any(char::is_whitespace) {
            bail!("stored user credential is invalid");
        }
        return Ok(raw);
    }
    let session: Session = serde_json::from_str(raw.as_str())
        .map_err(|_| anyhow::anyhow!("stored user credential is invalid"))?;
    // A refresh deadline is scheduling metadata, not expiration. Queries may use
    // a still-valid access credential without writing its replacement.
    if session.version != 1
        || session.expires_at <= now
        || session.session_expires_at <= now
        || session.refresh_at > session.expires_at
    {
        return Err(super::user_login_error());
    }
    Ok(SecretValue::new(session.token.access_token)?)
}

#[cfg(test)]
#[path = "../../tests/unit/src/strict_user.rs"]
mod tests;
