use std::path::{Component, Path};

use serde::Deserialize;
use serde_json::Value;

use super::{Failure, Request};
use crate::{
    account_defaults::Context,
    account_operations::{self, Mutation},
    config::AppPaths,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    expected_context: Context,
    account_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    confirmed: bool,
    expected_context: Context,
    account_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    confirmed: bool,
    expected_context: Context,
    tool: String,
    name: String,
    region: String,
    timezone: String,
    locale: String,
    tags: Vec<String>,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| Failure::new("configuration_unavailable"))?;
        tokio::select! {
            biased;
            _=terminate.recv()=>Err(Failure::new(if request.method=="accounts.status" { "canceled" } else { "account_outcome_unknown" })),
            result=execute_inner(request)=>result,
        }
    }
    #[cfg(not(unix))]
    execute_inner(request).await
}

async fn execute_inner(request: &Request) -> Result<Value, Failure> {
    if request.method == "accounts.status" {
        let input: StatusRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !valid_context(&input.expected_context)
            || !account_operations::valid_id(&input.account_id)
        {
            return Err(Failure::new("invalid_params"));
        }
        let paths = paths(&input.expected_context)?;
        let result = account_operations::status(&paths, input.expected_context, &input.account_id)
            .await
            .map_err(failure)?;
        return serde_json::to_value(result).map_err(|_| Failure::new("account_response_invalid"));
    }
    let (confirmed, context, action) = if request.method == "accounts.create" {
        let input: CreateRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        let create = account_operations::Create {
            tool: input.tool,
            name: input.name,
            region: input.region,
            timezone: input.timezone,
            locale: input.locale,
            tags: input.tags,
        };
        if !create.valid() {
            return Err(Failure::new("invalid_params"));
        }
        (
            input.confirmed,
            input.expected_context,
            Mutation::Create(create),
        )
    } else {
        let input: ActionRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !account_operations::valid_id(&input.account_id) {
            return Err(Failure::new("invalid_params"));
        }
        let action = match request.method.as_str() {
            "accounts.bind" => Mutation::Bind(input.account_id),
            "accounts.verify" => Mutation::Verify(input.account_id),
            "accounts.disable" => Mutation::Disable(input.account_id),
            _ => return Err(Failure::new("unsupported_method")),
        };
        (input.confirmed, input.expected_context, action)
    };
    if !valid_context(&context) {
        return Err(Failure::new("invalid_params"));
    }
    if !confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    let paths = paths(&context)?;
    let receipt = account_operations::mutate(&paths, context, action)
        .await
        .map_err(failure)?;
    let mut result =
        serde_json::to_value(receipt).map_err(|_| Failure::new("account_outcome_unknown"))?;
    result["operation_id"] = Value::String(request.request_id.clone());
    Ok(result)
}

fn valid_context(context: &Context) -> bool {
    let home = &context.home;
    home.is_absolute()
        && home.as_os_str().len() <= 32768
        && !home
            .components()
            .any(|v| matches!(v, Component::ParentDir | Component::CurDir))
        && home
            .to_str()
            .is_some_and(|v| !v.chars().any(char::is_control))
        && context
            .server_url
            .as_deref()
            .is_none_or(|v| account_operations::valid_text(v, 8192))
        && context
            .active_device_id
            .as_deref()
            .is_none_or(account_operations::valid_id)
}
fn paths(context: &Context) -> Result<AppPaths, Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if paths.home() != Path::new(&context.home) {
        return Err(Failure::new("configuration_changed"));
    }
    if context.server_url.is_none() || context.active_device_id.is_none() {
        return Err(Failure::new("authentication_required"));
    }
    Ok(paths)
}
fn failure(error: account_operations::Error) -> Failure {
    Failure {
        code: error.code,
        retryable: false,
        http_status: error.http_status,
    }
}
