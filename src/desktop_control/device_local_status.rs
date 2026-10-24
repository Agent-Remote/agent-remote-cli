//! Read-only projection of the locally installed macOS Device app.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::device;

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    expected_home: PathBuf,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    if request.method != "device.local.status" {
        return Err(Failure::new("unsupported_method"));
    }
    let input: StatusRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !valid_home(&input.expected_home) {
        return Err(Failure::new("invalid_params"));
    }
    let status = device::desktop_status(&input.expected_home).map_err(|error| {
        let detail = error.to_string();
        if detail.contains("only supported on macOS") {
            Failure::new("platform_unsupported")
        } else if detail.contains("configuration changed") {
            Failure::new("configuration_changed")
        } else {
            Failure::new("local_status_unavailable")
        }
    })?;
    Ok(json!({
        "schema_version": 1,
        "operation": "device.local.status",
        "home": input.expected_home,
        "platform": "macos",
        "app": status,
    }))
}

fn valid_home(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}
