//! Shared logout orchestration with separate local and remote outcomes.

use anyhow::Result;
use serde::Serialize;

use crate::api::ApiClient;
use crate::broker_credentials::delete_broker_credential_if_matches;
use crate::config::{AppPaths, Config};
use crate::secrets::{device_token_key, SecretStore};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Revocation {
    NotRequested,
    NotPresent,
    Confirmed,
    Unconfirmed,
}

#[derive(Debug, Serialize)]
pub struct CredentialLogout {
    pub local_removed: bool,
    pub remote: Revocation,
}

#[derive(Debug, Serialize)]
pub struct LogoutOutcome {
    pub server_url: Option<String>,
    pub active_device_id: Option<String>,
    pub user: CredentialLogout,
    pub device: CredentialLogout,
    pub broker_removed: bool,
    pub refresh_metadata_removed: bool,
    pub config_cleared: bool,
}

impl LogoutOutcome {
    pub fn local_complete(&self) -> bool {
        self.user.local_removed
            && self.device.local_removed
            && self.broker_removed
            && self.refresh_metadata_removed
            && self.config_cleared
    }
}

#[derive(Debug)]
pub struct ContextChanged;

impl std::fmt::Display for ContextChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("configuration changed before logout")
    }
}

impl std::error::Error for ContextChanged {}

/// Serialize with login and device renewal. A receipt describes partial cleanup;
/// remote revocation never implies that local deletion succeeded, or vice versa.
pub async fn execute(
    paths: &AppPaths,
    revoke: bool,
    expected: Option<&Config>,
) -> Result<LogoutOutcome> {
    let initial = Config::load(paths)?;
    if expected.is_some_and(|value| value != &initial) {
        return Err(ContextChanged.into());
    }
    let empty = || CredentialLogout {
        local_removed: true,
        remote: if revoke {
            Revocation::NotPresent
        } else {
            Revocation::NotRequested
        },
    };
    let mut outcome = LogoutOutcome {
        server_url: initial.server_url.clone(),
        active_device_id: initial.active_device_id.clone(),
        user: empty(),
        device: empty(),
        broker_removed: true,
        refresh_metadata_removed: true,
        config_cleared: initial.active_device_id.is_none(),
    };
    let Some(server) = initial.server_url.as_deref() else {
        return Ok(outcome);
    };
    let guard = super::login::lock(paths).await?;
    if Config::load(paths)? != initial {
        return Err(ContextChanged.into());
    }
    if let Some(device) = initial.active_device_id.as_deref() {
        if revoke {
            outcome.device.remote = match super::load_device_token_locked(paths, &guard).await {
                Ok((bound_server, bound_device, token))
                    if bound_server == server && bound_device == device =>
                {
                    match revoke_token(server, &token).await {
                        Ok(()) => Revocation::Confirmed,
                        Err(_) => Revocation::Unconfirmed,
                    }
                }
                _ => Revocation::Unconfirmed,
            };
        }
        outcome.broker_removed = delete_broker_credential_if_matches(paths, server, device).is_ok();
        outcome.device.local_removed = SecretStore::new(paths.clone())
            .delete_secret_confirmed(&device_token_key(server, device));
        outcome.refresh_metadata_removed =
            super::clear_device_token_refresh(paths, server, device).is_ok();
    }
    outcome.user = super::user_session::logout_with_status(paths, server, revoke)
        .await
        .unwrap_or(CredentialLogout {
            local_removed: false,
            remote: if revoke {
                Revocation::Unconfirmed
            } else {
                Revocation::NotRequested
            },
        });
    let next = Config {
        server_url: initial.server_url.clone(),
        active_device_id: None,
    };
    // Keep the selected device reachable for explicit cleanup if its local secrets
    // could not be removed. Clearing the pointer would strand those credentials.
    outcome.config_cleared = outcome.device.local_removed
        && outcome.broker_removed
        && outcome.refresh_metadata_removed
        && next.save_if_unchanged(paths, &initial).is_ok();
    Ok(outcome)
}

pub(super) async fn revoke_token(server: &str, token: &str) -> Result<()> {
    ApiClient::new(server.to_owned())?.logout(token).await?;
    Ok(())
}
