use std::path::{Component, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use super::{Failure, Request};
use crate::{
    account_defaults::{self, Context, Snapshot},
    config::AppPaths,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Get {
    expected_home: PathBuf,
    tool: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Set {
    confirmed: bool,
    expected_context: Context,
    #[serde(deserialize_with = "account_defaults::required_nullable")]
    expected_account_id: Option<String>,
    tool: String,
    account_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Clear {
    confirmed: bool,
    expected_context: Context,
    #[serde(deserialize_with = "account_defaults::required_nullable")]
    expected_account_id: Option<String>,
    tool: String,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| Failure::new("configuration_unavailable"))?;
        tokio::select! {
            biased;
            _ = terminate.recv() => Err(Failure::new(if request.method == "accounts.default.get" { "canceled" } else { "default_outcome_unknown" })),
            result = execute_inner(request) => result,
        }
    }
    #[cfg(not(unix))]
    execute_inner(request).await
}

async fn execute_inner(request: &Request) -> Result<Value, Failure> {
    if request.method == "accounts.default.get" {
        let input: Get = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !super::valid_id(&input.tool) || !valid_home(&input.expected_home) {
            return Err(Failure::new("invalid_params"));
        }
        let paths = paths(&input.expected_home)?;
        let result = account_defaults::get(&paths, &input.tool).map_err(failure)?;
        return serde_json::to_value(result).map_err(|_| Failure::new("state_unavailable"));
    }
    let (confirmed, expected, account_id) = if request.method == "accounts.default.set" {
        let input: Set = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !super::valid_id(&input.account_id) {
            return Err(Failure::new("invalid_params"));
        }
        (
            input.confirmed,
            Snapshot {
                context: input.expected_context,
                tool: input.tool,
                account_id: input.expected_account_id,
            },
            Some(input.account_id),
        )
    } else {
        let input: Clear = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        (
            input.confirmed,
            Snapshot {
                context: input.expected_context,
                tool: input.tool,
                account_id: input.expected_account_id,
            },
            None,
        )
    };
    if !super::valid_id(&expected.tool)
        || !valid_home(&expected.context.home)
        || expected
            .account_id
            .as_ref()
            .is_some_and(|id| !super::valid_id(id))
        || expected
            .context
            .active_device_id
            .as_ref()
            .is_some_and(|id| !super::valid_id(id))
        || expected.context.server_url.as_ref().is_some_and(|url| {
            url.is_empty() || url.len() > 8192 || url.chars().any(char::is_control)
        })
    {
        return Err(Failure::new("invalid_params"));
    }
    if !confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    let paths = paths(&expected.context.home)?;
    let outcome = if let Some(account_id) = account_id {
        account_defaults::set(&paths, &expected.tool, &account_id, Some(&expected), false).await
    } else {
        account_defaults::clear(&paths, &expected.tool, Some(&expected)).await
    }
    .map_err(failure)?;
    let mut result =
        serde_json::to_value(outcome).map_err(|_| Failure::new("default_outcome_unknown"))?;
    result["operation_id"] = Value::String(request.request_id.clone());
    Ok(result)
}

fn valid_home(path: &std::path::Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
}
fn paths(expected_home: &std::path::Path) -> Result<AppPaths, Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if paths.home() != expected_home {
        return Err(Failure::new("configuration_changed"));
    }
    Ok(paths)
}
fn failure(error: anyhow::Error) -> Failure {
    if let Some(error) = error.downcast_ref::<account_defaults::Error>() {
        return Failure::new(error.0);
    }
    match error.downcast::<crate::api::ApiError>() {
        Ok(error) => Failure::api(error),
        Err(_) => Failure::new("default_outcome_unknown"),
    }
}
