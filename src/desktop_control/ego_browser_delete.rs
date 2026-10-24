//! Exact, context-bound deletion of terminal ego-browser resources.
//!
//! `ego-browser delete-device` and `delete-binding` are destructive control
//! plane operations.  The desktop therefore receives a read-only plan first,
//! then submits an explicit confirmation carrying the target's observed
//! generation.  A changed status or generation fails closed before deletion.

use std::path::{Component, Path};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    account_defaults::Context,
    api::ApiClient,
    auth,
    config::{AppPaths, Config},
    local_state::LocalState,
};

use super::{Failure, Request};

const PLAN: &str = "ego_browser.delete.plan";
const CONTROL: &str = "ego_browser.delete.control";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    expected_context: Context,
    target: String,
    id: String,
    generation: u64,
    binding_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlInput {
    confirmed: bool,
    expected_context: Context,
    target: String,
    id: String,
    generation: u64,
    binding_generation: u64,
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
                &input.target,
                &input.id,
                input.generation,
                input.binding_generation,
            )?;
            let (_paths, _config, token, client) = context(&input.expected_context).await?;
            let target = inspect(&client, &token, &input).await?;
            Ok(json!({
                "schema_version": 1,
                "operation": PLAN,
                "context": input.expected_context,
                "target": input.target,
                "id": input.id,
                "status": target.status,
                "allowed": target.allowed,
                "requires_confirmation": true,
                "generation": input.generation,
                "binding_generation": input.binding_generation,
            }))
        }
        CONTROL => {
            let input: ControlInput = serde_json::from_value(request.params.clone())
                .map_err(|_| Failure::new("invalid_params"))?;
            validate_input(
                &input.expected_context,
                &input.target,
                &input.id,
                input.generation,
                input.binding_generation,
            )?;
            if !input.confirmed {
                return Err(Failure::new("confirmation_required"));
            }
            if input.reason.as_deref().is_some_and(|reason| {
                reason.is_empty() || reason.len() > 128 || reason.chars().any(char::is_control)
            }) {
                return Err(Failure::new("invalid_params"));
            }
            let (paths, config, token, client) = context(&input.expected_context).await?;
            let target = inspect(&client, &token, &input).await?;
            if !target.allowed {
                return Err(Failure::new("ego_browser_delete_not_allowed"));
            }
            match input.target.as_str() {
                "device" => client
                    .delete_ego_browser_device(&token, &input.id)
                    .await
                    .map_err(Failure::api)?,
                "binding" => client
                    .delete_ego_browser_binding(&token, &input.id)
                    .await
                    .map_err(Failure::api)?,
                _ => return Err(Failure::new("invalid_params")),
            }
            let local_cleanup_complete = (|| -> Result<(), Failure> {
                let state =
                    LocalState::open(&paths).map_err(|_| Failure::new("state_unavailable"))?;
                state
                    .init_schema()
                    .map_err(|_| Failure::new("state_unavailable"))?;
                match input.target.as_str() {
                    "device" => state
                        .delete_ego_browser_bindings_for_device(
                            config.server_url.as_deref().unwrap_or_default(),
                            &input.id,
                        )
                        .map_err(|_| Failure::new("state_unavailable"))?,
                    "binding" => state
                        .delete_ego_browser_binding(
                            config.server_url.as_deref().unwrap_or_default(),
                            &input.id,
                        )
                        .map_err(|_| Failure::new("state_unavailable"))?,
                    _ => unreachable!(),
                }
                Ok(())
            })()
            .is_ok();
            Ok(json!({
                "operation_id": request.request_id,
                "schema_version": 1,
                "operation": CONTROL,
                "context": input.expected_context,
                "target": input.target,
                "id": input.id,
                "status": "deleted",
                "generation": input.generation,
                "binding_generation": input.binding_generation,
                "local_cleanup_complete": local_cleanup_complete,
            }))
        }
        _ => Err(Failure::new("unsupported_method")),
    }
}

struct Inspection {
    status: String,
    allowed: bool,
}

async fn inspect<I: InputLike>(
    client: &ApiClient,
    token: &str,
    input: &I,
) -> Result<Inspection, Failure> {
    match input.target() {
        "device" => {
            let devices = client
                .list_ego_browser_devices(token, false)
                .await
                .map_err(Failure::api)?;
            if devices.len() > 128 {
                return Err(Failure::new("server_unavailable"));
            }
            let device = devices
                .into_iter()
                .find(|device| device.id == input.id())
                .ok_or_else(|| Failure::new("ego_browser_target_not_found"))?;
            if device.generation != input.generation()
                || device
                    .device_generation
                    .is_some_and(|generation| generation != input.generation())
                || input.binding_generation() != 0
            {
                return Err(Failure::new("ego_browser_generation_conflict"));
            }
            Ok(Inspection {
                allowed: device.status == "revoked",
                status: device.status,
            })
        }
        "binding" => {
            let bindings = client
                .list_ego_browser_bindings(token)
                .await
                .map_err(Failure::api)?;
            if bindings.len() > 128 {
                return Err(Failure::new("server_unavailable"));
            }
            let binding = bindings
                .into_iter()
                .find(|binding| binding.id == input.id())
                .ok_or_else(|| Failure::new("ego_browser_target_not_found"))?;
            let binding_generation = binding.binding_generation.unwrap_or(0);
            if binding.generation != input.generation()
                || binding_generation != input.binding_generation()
                || binding_generation == 0
            {
                return Err(Failure::new("ego_browser_generation_conflict"));
            }
            Ok(Inspection {
                allowed: matches!(
                    binding.status.as_str(),
                    "stopped" | "expired" | "failed" | "revoked"
                ),
                status: binding.status,
            })
        }
        _ => Err(Failure::new("invalid_params")),
    }
}

trait InputLike {
    fn target(&self) -> &str;
    fn id(&self) -> &str;
    fn generation(&self) -> u64;
    fn binding_generation(&self) -> u64;
}

impl InputLike for Input {
    fn target(&self) -> &str {
        &self.target
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn generation(&self) -> u64 {
        self.generation
    }
    fn binding_generation(&self) -> u64 {
        self.binding_generation
    }
}

impl InputLike for ControlInput {
    fn target(&self) -> &str {
        &self.target
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn generation(&self) -> u64 {
        self.generation
    }
    fn binding_generation(&self) -> u64 {
        self.binding_generation
    }
}

async fn context(expected: &Context) -> Result<(AppPaths, Config, String, ApiClient), Failure> {
    if !valid_context(expected) {
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
    target: &str,
    id: &str,
    generation: u64,
    binding_generation: u64,
) -> Result<(), Failure> {
    if !valid_context(context)
        || !valid_id(id)
        || generation == 0
        || (target == "device" && binding_generation != 0)
        || (target == "binding" && binding_generation == 0)
        || !matches!(target, "device" | "binding")
    {
        return Err(Failure::new("invalid_params"));
    }
    Ok(())
}

fn valid_context(context: &Context) -> bool {
    valid_home(&context.home)
        && context.server_url.as_deref().is_some_and(|value| {
            !value.is_empty() && value.len() <= 8192 && !value.chars().any(char::is_control)
        })
        && context.active_device_id.as_deref().is_none_or(valid_id)
}

fn valid_home(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}
