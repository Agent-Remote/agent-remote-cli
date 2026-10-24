use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use crate::config::AppPaths;
use crate::setup;

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupRequest {
    confirmed: bool,
    expected_home: String,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    let input: SetupRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    let expected = Path::new(&input.expected_home);
    if !expected.is_absolute() || input.expected_home.contains('\0') {
        return Err(Failure::new("invalid_params"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let actual =
        setup::absolute_home(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    if expected != actual {
        return Err(Failure::new("configuration_changed"));
    }
    let paths =
        AppPaths::new(Some(actual)).map_err(|_| Failure::new("configuration_unavailable"))?;
    let report = tokio::task::spawn_blocking(move || setup::initialize(&paths))
        .await
        .map_err(|_| Failure::new("setup_outcome_unknown"))?
        .map_err(|_| Failure::new("setup_outcome_unknown"))?;
    let mut value =
        serde_json::to_value(report).map_err(|_| Failure::new("setup_outcome_unknown"))?;
    value["operation_id"] = Value::String(request.request_id.clone());
    Ok(value)
}
