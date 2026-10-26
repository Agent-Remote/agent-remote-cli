//! Secret-free structured status for the local ego-browser Bridge.
//!
//! The human `ego-browser status` command also renders terminal recovery
//! hints.  Desktop consumers need a bounded, versioned projection instead;
//! they must never parse that output or infer local installation from the
//! control-plane device list.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    api::{ApiClient, EgoBrowserBindingData, EgoBrowserDeviceData, EgoBrowserPolicyData},
    auth,
    config::{AppPaths, Config},
};

use super::{Failure, Request};

const MAX_ITEMS: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    #[serde(rename = "home", alias = "expected_home")]
    expected_home: std::path::PathBuf,
    server_url: Option<String>,
    active_device_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    expected_context: Context,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    if request.method != "ego_browser.status" {
        return Err(Failure::new("unsupported_method"));
    }
    let input: StatusRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    status(input.expected_context).await
}

async fn status(input: Context) -> Result<Value, Failure> {
    if !valid_home(&input.expected_home)
        || input.server_url.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 8192 || value.chars().any(char::is_control)
        })
        || input
            .active_device_id
            .as_ref()
            .is_some_and(|value| !valid_identifier(value))
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
    let token = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let devices = client
        .list_ego_browser_devices(&token, false)
        .await
        .map_err(Failure::api)?;
    let bindings = client
        .list_ego_browser_bindings(&token)
        .await
        .map_err(Failure::api)?;
    let policy = client
        .ego_browser_policy(&token)
        .await
        .map_err(Failure::api)?;
    if devices.len() > MAX_ITEMS || bindings.len() > MAX_ITEMS {
        return Err(Failure::new("server_unavailable"));
    }
    for device in &devices {
        if !valid_device(device) {
            return Err(Failure::new("server_unavailable"));
        }
    }
    for binding in &bindings {
        if !valid_binding(binding) {
            return Err(Failure::new("server_unavailable"));
        }
    }
    let local = local_projection(&paths);
    Ok(json!({
        "schema_version": 1,
        "operation": "ego_browser.status",
        "context": {
            "home": paths.home(),
            "server_url": server,
            "active_device_id": config.active_device_id,
        },
        "local": local,
        "policy": policy_projection(&policy),
        "devices": devices.into_iter().map(device_projection).collect::<Vec<_>>(),
        "bindings": bindings.into_iter().map(binding_projection).collect::<Vec<_>>(),
    }))
}

fn local_projection(paths: &AppPaths) -> Value {
    let installed = local_bridge_installation_exists(paths);
    json!({
        "installation": if installed { "installed" } else { "missing" },
        "store": local_device_store_status(paths),
        "admission": "unknown",
    })
}

fn local_bridge_installation_exists(paths: &AppPaths) -> bool {
    let mut candidates = vec![
        paths.home().join("bin/ego-browser-device"),
        paths.home().join("bin/ego-browser-install"),
    ];
    let is_default_home = crate::platform::default_app_home()
        .ok()
        .is_some_and(|default| default == paths.home());
    if is_default_home {
        if let Some(path) = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE") {
            candidates.push(PathBuf::from(path));
        }
        if let Some(root) = std::env::var_os("EGO_BROWSER_INSTALL_ROOT") {
            candidates.push(PathBuf::from(root).join("current/bin/ego-browser-device"));
        }
        if let Some(home) = crate::platform::user_home_dir() {
            candidates.push(home.join(
                "Library/Application Support/Agent Remote Ego Browser/current/bin/ego-browser-device",
            ));
        }
    }
    candidates
        .iter()
        .any(|path| private_regular_file_exists(path))
}

fn local_device_store_status(paths: &AppPaths) -> &'static str {
    let is_default_home = crate::platform::default_app_home()
        .ok()
        .is_some_and(|default| default == paths.home());
    let canonical = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            is_default_home
                .then(|| {
                    crate::platform::user_home_dir()
                        .map(|home| home.join(".config/agent-remote-ego-browser"))
                })
                .flatten()
        })
        .unwrap_or_else(|| paths.home().join("ego-browser-device"));
    if private_directory_exists(&canonical) {
        return "present";
    }
    if is_default_home {
        if let Some(home) = crate::platform::user_home_dir() {
            let legacy = home.join(".config/agent-remote/ego-browser-device");
            if private_directory_exists(&legacy) {
                return "legacy";
            }
        }
    }
    "missing"
}

fn private_regular_file_exists(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn private_directory_exists(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn policy_projection(policy: &EgoBrowserPolicyData) -> Value {
    json!({
        "enabled": policy.enabled,
        "enrollment": if policy.enrollment_is_admitted() { "allowed" } else { "denied" },
        "execution": if policy.execution_is_admitted() { "allowed" } else { "denied" },
        "protocol": policy.protocol,
    })
}

fn device_projection(device: EgoBrowserDeviceData) -> Value {
    json!({
        "id": device.id,
        "generation": device.generation,
        "device_generation": device.device_generation,
        "status": device.status,
        "release_profile": device.release_profile,
        "bridge_version": device.bridge_version,
        "runtime_version": device.local_ego_browser_runtime_version.or(device.ego_lite_runtime_version),
        "skill_version": device.skill_version,
    })
}

fn binding_projection(binding: EgoBrowserBindingData) -> Value {
    json!({
        "id": binding.id,
        "device_id": binding.ego_browser_device_id,
        "tool_session_id": binding.tool_session_id,
        "node_id": binding.node_id,
        "status": binding.status,
        "relay_binding_kind": binding.relay_binding_kind,
        "authorization_mode": binding.authorization_mode,
        "release_profile": binding.release_profile,
        "bridge_protocol_version": binding.bridge_protocol_version,
        "lease_health": binding.lease_health,
        "generation": binding.generation,
        "binding_generation": binding.binding_generation,
        "connected_at": binding.connected_at,
        "lease_until": binding.lease_until,
        "stop_reason": binding.stop_reason,
    })
}

fn valid_device(device: &EgoBrowserDeviceData) -> bool {
    valid_identifier(&device.id)
        && valid_text(&device.status, 32)
        && valid_text(&device.release_profile, 128)
        && optional_text(device.bridge_version.as_deref(), 128)
        && optional_text(device.local_ego_browser_runtime_version.as_deref(), 128)
        && optional_text(device.ego_lite_runtime_version.as_deref(), 128)
        && optional_text(device.skill_version.as_deref(), 128)
}

fn valid_binding(binding: &EgoBrowserBindingData) -> bool {
    valid_identifier(&binding.id)
        && valid_identifier(&binding.ego_browser_device_id)
        && valid_identifier(&binding.tool_session_id)
        && valid_identifier(&binding.node_id)
        && valid_text(&binding.status, 32)
        && valid_text(&binding.relay_binding_kind, 64)
        && valid_text(&binding.authorization_mode, 64)
        && valid_text(&binding.release_profile, 128)
        && valid_text(&binding.bridge_protocol_version, 64)
        && valid_text(&binding.lease_health, 32)
        && optional_text(binding.connected_at.as_deref(), 128)
        && optional_text(binding.lease_until.as_deref(), 128)
        && optional_text(binding.stop_reason.as_deref(), 256)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.chars().all(|c| !c.is_control())
}

fn optional_text(value: Option<&str>, max: usize) -> bool {
    value.is_none_or(|value| valid_text(value, max))
}

fn valid_home(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn local_projection_uses_the_selected_custom_home() {
        let temp = tempdir().unwrap();
        let paths = AppPaths::from_home(temp.path().join("agent-remote"));
        std::fs::create_dir_all(paths.home().join("bin")).unwrap();
        std::fs::write(paths.home().join("bin/ego-browser-device"), b"device").unwrap();
        std::fs::create_dir_all(paths.home().join("ego-browser-device")).unwrap();
        let projection = local_projection(&paths);
        assert_eq!(projection["installation"], "installed");
        assert_eq!(projection["store"], "present");
    }
}
