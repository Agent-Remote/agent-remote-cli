//! Structured ego-browser request inspection and cancellation for desktop.
//!
//! Request identifiers are deliberately resolved against a fresh server list
//! inside the CLI.  The desktop only sends the reviewed binding/request
//! references and generation values; it never receives browser payload data.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    api::{ApiClient, EgoBrowserRequestData},
    auth,
    config::{AppPaths, Config},
};

use super::{Failure, Request};

const MAX_ITEMS: usize = 128;

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
struct ListRequest {
    expected_context: Context,
    binding_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelRequest {
    confirmed: bool,
    expected_context: Context,
    binding_id: String,
    request_id: String,
    binding_generation: u64,
    generation: u64,
    sequence: u64,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    match request.method.as_str() {
        "ego_browser.requests" => list(request).await,
        "ego_browser.request.cancel" => cancel(request).await,
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn list(request: &Request) -> Result<Value, Failure> {
    let input: ListRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    let (paths, _config, server, active) = checked_context(input.expected_context)?;
    validate_id(&input.binding_id)?;
    let token = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let bindings = client
        .list_ego_browser_bindings(&token)
        .await
        .map_err(Failure::api)?;
    let binding = bindings
        .iter()
        .find(|binding| binding.id == input.binding_id)
        .ok_or_else(|| Failure::new("binding_not_found"))?;
    let generation = binding.binding_generation.unwrap_or(binding.generation);
    let requests = client
        .list_ego_browser_requests(&token, &input.binding_id)
        .await
        .map_err(Failure::api)?;
    validate_requests(&requests, &input.binding_id)?;
    Ok(json!({
        "schema_version": 1,
        "operation": "ego_browser.requests",
        "context": context_json(&paths, &server, active),
        "binding_id": input.binding_id,
        "binding_generation": generation,
        "items": requests.into_iter().map(request_json).collect::<Vec<_>>(),
    }))
}

async fn cancel(request: &Request) -> Result<Value, Failure> {
    let input: CancelRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed || input.binding_generation == 0 || input.generation == 0 {
        return Err(Failure::new("confirmation_required"));
    }
    let (paths, _config, server, active) = checked_context(input.expected_context)?;
    validate_id(&input.binding_id)?;
    validate_id(&input.request_id)?;
    let token = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let bindings = client
        .list_ego_browser_bindings(&token)
        .await
        .map_err(Failure::api)?;
    let binding = bindings
        .iter()
        .find(|binding| binding.id == input.binding_id)
        .ok_or_else(|| Failure::new("binding_not_found"))?;
    let current_binding_generation = binding.binding_generation.unwrap_or(binding.generation);
    if current_binding_generation != input.binding_generation {
        return Err(Failure::new("binding_generation_changed"));
    }
    let requests = client
        .list_ego_browser_requests(&token, &input.binding_id)
        .await
        .map_err(Failure::api)?;
    validate_requests(&requests, &input.binding_id)?;
    let selected = requests
        .iter()
        .find(|item| item.id == input.request_id)
        .ok_or_else(|| Failure::new("request_not_active"))?;
    if selected.generation != input.generation
        || selected.binding_generation.unwrap_or(selected.generation) != input.binding_generation
        || selected.sequence != input.sequence
    {
        return Err(Failure::new("request_generation_changed"));
    }
    let result = client
        .cancel_ego_browser_request(
            &token,
            &input.binding_id,
            &selected.request_id,
            input.binding_generation,
            input.sequence,
        )
        .await
        .map_err(Failure::api)?;
    validate_request(&result, &input.binding_id)?;
    Ok(json!({
        "operation_id": request.request_id,
        "schema_version": 1,
        "operation": "ego_browser.request.cancel",
        "context": context_json(&paths, &server, active),
        "binding_id": input.binding_id,
        "request_id": input.request_id,
        "status": result.status,
        "item": request_json(result),
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
            .is_some_and(|value| !valid_id(value))
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

fn context_json(paths: &AppPaths, server: &str, active: Option<String>) -> Value {
    json!({"home": paths.home(), "server_url": server, "active_device_id": active})
}

fn request_json(item: EgoBrowserRequestData) -> Value {
    json!({
        "id": item.id,
        "binding_id": item.binding_id,
        "generation": item.generation,
        "binding_generation": item.binding_generation.unwrap_or(item.generation),
        "request_id": item.request_id,
        "sequence": item.sequence,
        "message_type": item.message_type,
        "payload_bytes": item.payload_bytes,
        "status": item.status,
        "created_at": item.created_at,
    })
}

fn validate_requests(items: &[EgoBrowserRequestData], binding_id: &str) -> Result<(), Failure> {
    if items.len() > MAX_ITEMS {
        return Err(Failure::new("server_unavailable"));
    }
    for item in items {
        validate_request(item, binding_id)?;
    }
    Ok(())
}

fn validate_request(item: &EgoBrowserRequestData, binding_id: &str) -> Result<(), Failure> {
    if item.binding_id != binding_id
        || !valid_id(&item.id)
        || !valid_id(&item.request_id)
        || item.generation == 0
        || item.binding_generation.unwrap_or(item.generation) == 0
        || item.message_type.is_empty()
        || item.message_type.len() > 128
        || item.message_type.chars().any(char::is_control)
        || item.status.is_empty()
        || item.status.len() > 32
        || item.status.chars().any(char::is_control)
        || item.created_at.is_empty()
        || item.created_at.len() > 128
        || item.created_at.chars().any(char::is_control)
    {
        return Err(Failure::new("server_unavailable"));
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), Failure> {
    if valid_id(value) {
        Ok(())
    } else {
        Err(Failure::new("invalid_params"))
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

fn valid_home(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}
