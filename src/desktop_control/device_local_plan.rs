//! Structured, read-only plans for the local macOS Device lifecycle.
//!
//! Installation, removal, launch, and diagnostics still execute through the
//! reviewed native CLI terminal.  This contract lets the desktop render the
//! exact lifecycle stages and confirmation boundary before handing control to
//! that terminal.  It never performs a local mutation and never reads a
//! credential.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
    expected_home: PathBuf,
    action: String,
    #[serde(default)]
    source: Option<PathBuf>,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    if request.method != "device.local.plan" {
        return Err(Failure::new("unsupported_method"));
    }
    let input: PlanRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !valid_home(&input.expected_home) {
        return Err(Failure::new("invalid_params"));
    }
    let (requires_confirmation, destructive, stages) = match input.action.as_str() {
        "install" => {
            let source = input
                .source
                .as_ref()
                .ok_or_else(|| Failure::new("invalid_params"))?;
            if !valid_source(source) {
                return Err(Failure::new("invalid_params"));
            }
            (
                true,
                true,
                vec![
                    stage("validate_source", "read"),
                    stage("stage_bundle", "write"),
                    stage("replace_destination", "write"),
                    stage("verify_installation", "read"),
                    stage("cleanup_staging", "write"),
                ],
            )
        }
        "uninstall" => {
            if input.source.is_some() {
                return Err(Failure::new("invalid_params"));
            }
            (
                true,
                true,
                vec![
                    stage("stop_process", "write"),
                    stage("remove_bundle", "write"),
                    stage("clear_local_data", "write"),
                    stage("verify_removal", "read"),
                ],
            )
        }
        "launch" => {
            if input.source.is_some() {
                return Err(Failure::new("invalid_params"));
            }
            (
                true,
                false,
                vec![
                    stage("verify_installation", "read"),
                    stage("verify_credential", "read"),
                    stage("launch_process", "write"),
                ],
            )
        }
        "diagnose" => {
            if input.source.is_some() {
                return Err(Failure::new("invalid_params"));
            }
            (
                false,
                false,
                vec![
                    stage("inspect_bundle", "read"),
                    stage("inspect_platform", "read"),
                    stage("inspect_runtime", "read"),
                ],
            )
        }
        _ => return Err(Failure::new("invalid_params")),
    };

    let mut result = json!({
        "schema_version": 1,
        "operation": "device.local.plan",
        "home": input.expected_home,
        "platform": "macos",
        "action": input.action,
        "terminal_method": format!("agent-remote device {}", input.action),
        "requires_confirmation": requires_confirmation,
        "destructive": destructive,
        "resume_policy": "inspect_before_retry",
        "stages": stages,
    });
    if let Some(source) = input.source {
        result["source"] = Value::String(source.to_string_lossy().into_owned());
    }
    Ok(result)
}

fn stage(id: &'static str, effect: &'static str) -> Value {
    json!({"id": id, "effect": effect, "state": "planned"})
}

fn valid_home(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

fn valid_source(path: &Path) -> bool {
    let value = path.to_string_lossy();
    path.is_absolute()
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}
