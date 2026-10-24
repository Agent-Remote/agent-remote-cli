//! Exact, context-bound ego-browser binding lifecycle controls for desktop.
//!
//! The desktop receives only bounded binding metadata. Lifecycle mutations are
//! generation-bound and use the user credential; no browser payloads or local
//! credentials cross this boundary.

use std::path::{Component, Path};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    account_defaults::Context,
    api::{ApiClient, EgoBrowserBindingData},
    auth,
    config::{AppPaths, Config},
};

use super::{Failure, Request};

const PLAN: &str = "ego_browser.binding.plan";
const CONTROL: &str = "ego_browser.binding.control";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    expected_context: Context,
    binding_id: String,
    binding_generation: u64,
    generation: u64,
    action: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlInput {
    confirmed: bool,
    expected_context: Context,
    binding_id: String,
    binding_generation: u64,
    generation: u64,
    action: String,
    #[serde(default)]
    reason: Option<String>,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    match request.method.as_str() {
        PLAN => {
            let input: Input = serde_json::from_value(request.params.clone())
                .map_err(|_| Failure::new("invalid_params"))?;
            validate_input(
                &input.expected_context,
                &input.binding_id,
                input.binding_generation,
                input.generation,
                &input.action,
            )?;
            let (paths, config, token, client) = context(&input.expected_context).await?;
            let binding = client
                .get_ego_browser_binding(&token, &input.binding_id)
                .await
                .map_err(Failure::api)?;
            validate_binding(&binding, &input.binding_id)?;
            if binding.binding_generation.unwrap_or(0) != input.binding_generation
                || binding.generation != input.generation
            {
                return Err(Failure::new("ego_browser_generation_conflict"));
            }
            let allowed = action_allowed(&binding.status, &input.action);
            Ok(json!({
                "schema_version": 1,
                "operation": PLAN,
                "context": input.expected_context,
                "binding": projection(&binding),
                "action": input.action,
                "allowed": allowed,
                "requires_confirmation": true,
                "generation": binding.generation,
                "binding_generation": binding.binding_generation,
                "home": paths.home(),
                "server_url": config.server_url,
            }))
        }
        CONTROL => {
            let input: ControlInput = serde_json::from_value(request.params.clone())
                .map_err(|_| Failure::new("invalid_params"))?;
            validate_input(
                &input.expected_context,
                &input.binding_id,
                input.binding_generation,
                input.generation,
                &input.action,
            )?;
            if !input.confirmed {
                return Err(Failure::new("confirmation_required"));
            }
            let (_paths, _config, token, client) = context(&input.expected_context).await?;
            let binding = client
                .control_ego_browser_binding(
                    &token,
                    &input.binding_id,
                    input.binding_generation,
                    &input.action,
                    input.reason.as_deref().unwrap_or("desktop_user_request"),
                )
                .await
                .map_err(Failure::api)?;
            validate_binding(&binding, &input.binding_id)?;
            Ok(json!({
                "operation_id": request.request_id,
                "schema_version": 1,
                "operation": CONTROL,
                "context": input.expected_context,
                "binding": projection(&binding),
                "action": input.action,
                "status": binding.status,
                "generation": binding.generation,
                "binding_generation": binding.binding_generation,
            }))
        }
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn context(expected: &Context) -> Result<(AppPaths, Config, String, ApiClient), Failure> {
    if !valid_home(&expected.home)
        || expected
            .server_url
            .as_deref()
            .is_none_or(|v| v.is_empty() || v.len() > 8192 || v.chars().any(char::is_control))
        || expected
            .active_device_id
            .as_deref()
            .is_some_and(|v| !super::valid_id(v))
    {
        return Err(Failure::new("invalid_params"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if paths.home() != Path::new(&expected.home) {
        return Err(Failure::new("configuration_changed"));
    }
    let config =
        Config::load_strict(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    if config.server_url != expected.server_url
        || config.active_device_id != expected.active_device_id
    {
        return Err(Failure::new("configuration_changed"));
    }
    let server = config
        .server_url
        .clone()
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let token = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client = ApiClient::new(server).map_err(|_| Failure::new("configuration_unavailable"))?;
    Ok((paths, config, token, client))
}

fn validate_input(
    context: &Context,
    binding_id: &str,
    binding_generation: u64,
    generation: u64,
    action: &str,
) -> Result<(), Failure> {
    if !valid_id(binding_id)
        || binding_generation == 0
        || generation == 0
        || !matches!(action, "pause" | "resume" | "stop" | "revoke")
    {
        return Err(Failure::new("invalid_params"));
    }
    if !valid_home(&context.home)
        || context
            .server_url
            .as_deref()
            .is_none_or(|v| v.is_empty() || v.len() > 8192 || v.chars().any(char::is_control))
        || context
            .active_device_id
            .as_deref()
            .is_some_and(|v| !valid_id(v))
    {
        return Err(Failure::new("invalid_params"));
    }
    Ok(())
}

fn action_allowed(status: &str, action: &str) -> bool {
    match action {
        "pause" => matches!(status, "active" | "connected" | "running"),
        "resume" => matches!(status, "paused" | "awaiting_bridge"),
        "stop" => matches!(
            status,
            "active" | "connected" | "running" | "paused" | "awaiting_bridge"
        ),
        "revoke" => status != "revoked" && status != "deleted",
        _ => false,
    }
}

fn validate_binding(binding: &EgoBrowserBindingData, expected: &str) -> Result<(), Failure> {
    if binding.id != expected
        || !valid_id(&binding.id)
        || !valid_id(&binding.ego_browser_device_id)
        || !valid_id(&binding.tool_session_id)
        || !valid_id(&binding.node_id)
        || binding.status.is_empty()
        || binding.status.len() > 32
        || binding.binding_generation.unwrap_or(0) == 0
        || binding.generation == 0
    {
        return Err(Failure::new("server_unavailable"));
    }
    Ok(())
}

fn projection(binding: &EgoBrowserBindingData) -> Value {
    json!({
        "id": binding.id,
        "device_id": binding.ego_browser_device_id,
        "tool_session_id": binding.tool_session_id,
        "node_id": binding.node_id,
        "status": binding.status,
        "lease_health": binding.lease_health,
        "generation": binding.generation,
        "binding_generation": binding.binding_generation,
        "lease_until": binding.lease_until,
        "stop_reason": binding.stop_reason,
    })
}

fn valid_home(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
