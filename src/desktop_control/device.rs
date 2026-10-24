//! Device-specific desktop control operations.
//!
//! The human `device` commands are deliberately not launched through a generic
//! argv form.  This module freezes the selected home/server/device context,
//! requires the user credential for destructive control-plane operations, and
//! returns a secret-free receipt.  Device tokens never cross this boundary.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    api::ApiClient,
    auth::{self, clear_device_token_refresh},
    broker_credentials::delete_broker_credential_if_matches,
    config::{AppPaths, Config},
    local_state::LocalState,
    secrets::{device_token_key, SecretStore},
};

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    #[serde(rename = "home", alias = "expected_home")]
    expected_home: PathBuf,
    server_url: Option<String>,
    active_device_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    expected_context: Context,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    confirmed: bool,
    expected_context: Context,
    device_id: String,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    match request.method.as_str() {
        "device.status" => status(request).await,
        "device.revoke" => revoke(request).await,
        "device.rotate_token" => rotate_token(request).await,
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn status(request: &Request) -> Result<Value, Failure> {
    let input: StatusRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    let (paths, config, server, device_id) = checked_context(input.expected_context)?;
    let device_id = device_id.ok_or_else(|| Failure::new("device_required"))?;
    let token = auth::load_device_token(&paths)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .2;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let remote = client
        .get_device(&token, &device_id)
        .await
        .map_err(Failure::api)?;
    Ok(json!({
        "context": {"home": paths.home(), "server_url": server, "active_device_id": config.active_device_id},
        "device": {
            "id": remote.id,
            "name": remote.name,
            "platform": remote.platform,
            "status": remote.status,
            "last_seen_at": remote.last_seen_at,
            "created_at": remote.created_at
        }
    }))
}

async fn revoke(request: &Request) -> Result<Value, Failure> {
    let input: ActionRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    let (paths, config, server, active) = checked_context(input.expected_context)?;
    validate_device_id(&input.device_id)?;
    let user = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    client
        .revoke_device(&user, &input.device_id)
        .await
        .map_err(Failure::api)?;

    // Remote revocation is authoritative.  Cleanup is reported in the receipt
    // so a partial local failure is visible without pretending the request was
    // rejected or safe to replay with another request ID.
    let mut cleanup_complete = true;
    if active.as_deref() == Some(input.device_id.as_str()) {
        let store = SecretStore::new(paths.clone());
        cleanup_complete &=
            delete_broker_credential_if_matches(&paths, &server, &input.device_id).is_ok();
        cleanup_complete &= store
            .delete_secret(&device_token_key(&server, &input.device_id))
            .is_ok();
        cleanup_complete &= clear_device_token_refresh(&paths, &server, &input.device_id).is_ok();
        cleanup_complete &= clear_active_device(&paths, &config).is_ok();
        cleanup_complete &= mark_local_device_revoked(&paths, &input.device_id).is_ok();
    }
    Ok(json!({
        "operation_id": request.request_id,
        "context": {"home": paths.home(), "server_url": server, "active_device_id": active},
        "device_id": input.device_id,
        "remote_status": "revoked",
        "local_cleanup_complete": cleanup_complete
    }))
}

async fn rotate_token(request: &Request) -> Result<Value, Failure> {
    let input: ActionRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    let (paths, _config, server, active) = checked_context(input.expected_context)?;
    validate_device_id(&input.device_id)?;
    if active.as_deref() != Some(input.device_id.as_str()) {
        return Err(Failure::new("device_context_mismatch"));
    }
    let user = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let rotated = client
        .rotate_device_token(&user, &input.device_id)
        .await
        .map_err(Failure::api)?;
    let backend = auth::store_device_token(&paths, &server, &input.device_id, &rotated)
        .map_err(|_| Failure::new("device_token_persistence_incomplete"))?;
    Ok(json!({
        "operation_id": request.request_id,
        "context": {"home": paths.home(), "server_url": server, "active_device_id": active},
        "device_id": input.device_id,
        "remote_status": "rotated",
        "local_credential_complete": true,
        "credential_backend": match backend { crate::secrets::SecretBackend::System => "system", crate::secrets::SecretBackend::File => "file" },
        "expires_in": rotated.expires_in
    }))
}

fn checked_context(input: Context) -> Result<(AppPaths, Config, String, Option<String>), Failure> {
    if !valid_home(&input.expected_home)
        || input.server_url.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 8192 || value.chars().any(char::is_control)
        })
        || input
            .active_device_id
            .as_ref()
            .is_some_and(|value| validate_device_id(value).is_err())
    {
        return Err(Failure::new("invalid_params"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if paths.home() != input.expected_home {
        return Err(Failure::new("configuration_changed"));
    }
    let config = Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    if config.server_url != input.server_url || config.active_device_id != input.active_device_id {
        return Err(Failure::new("configuration_changed"));
    }
    let server = input
        .server_url
        .ok_or_else(|| Failure::new("authentication_required"))?;
    Ok((paths, config, server, input.active_device_id))
}

fn clear_active_device(paths: &AppPaths, config: &Config) -> anyhow::Result<()> {
    let mut next = config.clone();
    next.active_device_id = None;
    next.save(paths)
}

fn mark_local_device_revoked(paths: &AppPaths, device_id: &str) -> anyhow::Result<()> {
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    if let Some(mut device) = state.get_device(device_id)? {
        device.status = "revoked".to_string();
        state.upsert_device(&device)?;
    }
    Ok(())
}

fn validate_device_id(value: &str) -> Result<(), Failure> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return Err(Failure::new("invalid_params"));
    }
    Ok(())
}

fn valid_home(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}
