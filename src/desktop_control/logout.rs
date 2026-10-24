use serde::Deserialize;
use serde_json::Value;

use crate::{
    auth::logout,
    config::{AppPaths, Config},
};

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutRequest {
    confirmed: bool,
    revoke_remote: bool,
    expected_context: ExpectedContext,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedContext {
    server_url: Option<String>,
    active_device_id: Option<String>,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    let input: LogoutRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let expected = Config {
        server_url: input.expected_context.server_url,
        active_device_id: input.expected_context.active_device_id,
    };
    let outcome = logout::execute(&paths, input.revoke_remote, Some(&expected))
        .await
        .map_err(|error| {
            Failure::new(if error.is::<logout::ContextChanged>() {
                "configuration_changed"
            } else {
                "logout_outcome_unknown"
            })
        })?;
    let mut result =
        serde_json::to_value(&outcome).map_err(|_| Failure::new("logout_outcome_unknown"))?;
    result["operation_id"] = Value::String(request.request_id.clone());
    result["local_complete"] = Value::Bool(outcome.local_complete());
    Ok(result)
}
