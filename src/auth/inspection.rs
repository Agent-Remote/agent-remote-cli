//! Credential inspection without token refresh or secret-bearing output.
use crate::broker_credentials::{
    broker_credential_storage_required, load_active_broker_credential,
};
use crate::config::{AppPaths, Config};
use crate::secrets::{device_token_key, user_token_key, SecretStore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialInspection {
    Present,
    Missing,
    BindingMismatch,
    Unavailable,
}

/// Inspect the same Broker/legacy stores as doctor. Presence is not proof that
/// the server will authorize an operation; this never refreshes a credential.
pub fn inspect_credential(
    paths: &AppPaths,
    config: &Config,
    canceled: &std::sync::atomic::AtomicBool,
) -> CredentialInspection {
    let Some(server) = config.server_url.as_deref() else {
        return CredentialInspection::Missing;
    };
    let key = if let Some(device) = config.active_device_id.as_deref() {
        match load_active_broker_credential(paths) {
            Ok(Some(credential)) => {
                return if credential.server_url == server && credential.device_id == device {
                    CredentialInspection::Present
                } else {
                    CredentialInspection::BindingMismatch
                };
            }
            Ok(None) if broker_credential_storage_required() => {
                return CredentialInspection::Missing
            }
            Err(_) => return CredentialInspection::Unavailable,
            Ok(None) => {}
        }
        device_token_key(server, device)
    } else {
        user_token_key(server)
    };
    match SecretStore::new(paths.clone()).contains_secret_cancellable(&key, canceled) {
        Ok(true) => CredentialInspection::Present,
        Ok(_) => CredentialInspection::Missing,
        Err(_) => CredentialInspection::Unavailable,
    }
}
