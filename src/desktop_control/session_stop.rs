//! Exact caller-key session stop operations for the desktop bridge.

use crate::{
    account_defaults::Context,
    api::ApiClient,
    auth,
    config::{AppPaths, Config},
    session_stop,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stop {
    confirmed: bool,
    schema_version: u8,
    expected_context: Context,
    session_id: String,
    expected_node_id: String,
    expected_runtime_backend: String,
    #[serde(default)]
    expected_stop_task_id: Option<String>,
    #[serde(default = "default_reason")]
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observe {
    request_id: String,
    expected_context: Context,
    #[serde(default)]
    wait: bool,
    #[serde(default = "default_timeout")]
    timeout: u64,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    match request.method.as_str() {
        "sessions.stop" => stop(request).await,
        "sessions.stop.request" | "sessions.stop.status" => observe(request).await,
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn stop(request: &Request) -> Result<Value, Failure> {
    let input: Stop = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed
        || input.schema_version != 1
        || input.reason != "user_requested"
        || !valid_context(&input.expected_context)
        || !canonical_uuid(&input.session_id)
        || !canonical_uuid(&input.expected_node_id)
        || input.expected_runtime_backend.is_empty()
        || input.expected_runtime_backend.len() > 64
        || input.expected_runtime_backend.chars().any(char::is_control)
        || input
            .expected_stop_task_id
            .as_deref()
            .is_some_and(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
    {
        return Err(Failure::new("invalid_params"));
    }
    let (paths, server, token) = authenticated(&input.expected_context).await?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let session = client
        .get_tool_session(&token, &input.session_id)
        .await
        .map_err(Failure::api)?;
    if session.id != input.session_id
        || session.node_id != input.expected_node_id
        || session.runtime_backend != input.expected_runtime_backend
        || input
            .expected_stop_task_id
            .as_ref()
            .is_some_and(|expected| session.stop_task_id.as_ref() != Some(expected))
    {
        return Err(Failure::new("session_binding_changed"));
    }
    match session_stop::submit(&paths, &client, &server, &token, &session).await {
        Ok((receipt, _)) => receipt_json(receipt, &input.expected_context),
        Err(error) => {
            if let Some(unknown) = error.downcast_ref::<session_stop::StopSubmissionUnknown>() {
                let record = crate::local_state::LocalState::session_stop_records(&paths)
                    .map_err(|_| Failure::new("session_stop_journal_unavailable"))?
                    .into_iter()
                    .find(|record| record.request_id == unknown.0)
                    .ok_or_else(|| Failure::new("session_stop_outcome_unknown"))?;
                return Ok(json!({
                    "schema_version": 1,
                    "request_id": record.request_id,
                    "phase": "unknown",
                    "session_id": record.session_id,
                    "node_id": record.node_id,
                    "runtime_backend": record.runtime_backend,
                    "runtime_resource_id": record.runtime_resource_id,
                    "stop_task_id": record.stop_task_id,
                    "stop_task_record_id": record.stop_task_record_id,
                    "stop_task_status": record.stop_task_status,
                    "session_status": record.session_status,
                    "skill_finalization_operation_id": record.skill_finalization_operation_id,
                    "session_deleted": record.session_deleted,
                    "error_code": "SESSION_STOP_SUBMISSION_UNKNOWN",
                    "intent_fingerprint": record.intent_fingerprint,
                    "reason": record.reason,
                    "result_status": record.result_status,
                    "process_stopped": record.process_stopped,
                    "save_status": record.save_status,
                    "context": input.expected_context,
                }));
            }
            Err(failure_from_error(error))
        }
    }
}

async fn observe(request: &Request) -> Result<Value, Failure> {
    let input: Observe = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !valid_context(&input.expected_context)
        || !canonical_uuid(&input.request_id)
        || !(1..=86400).contains(&input.timeout)
    {
        return Err(Failure::new("invalid_params"));
    }
    let (paths, server, token) = authenticated(&input.expected_context).await?;
    let client = ApiClient::new(server).map_err(|_| Failure::new("configuration_unavailable"))?;
    let receipt = session_stop::observe(
        &paths,
        &client,
        &token,
        &input.request_id,
        input.wait,
        input.timeout,
    )
    .await
    .map_err(failure_from_error)?;
    receipt_json(receipt, &input.expected_context)
}

async fn authenticated(expected: &Context) -> Result<(AppPaths, String, String), Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if paths.home() != expected.home {
        return Err(Failure::new("configuration_changed"));
    }
    let config = Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    let server = config
        .server_url
        .clone()
        .ok_or_else(|| Failure::new("authentication_required"))?;
    if expected.server_url.as_deref() != Some(server.as_str())
        || expected.active_device_id.as_deref() != config.active_device_id.as_deref()
    {
        return Err(Failure::new("configuration_changed"));
    }
    let (_device, device_id, token) = auth::load_device_token(&paths)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?;
    if expected.active_device_id.as_deref() != Some(device_id.as_str()) {
        return Err(Failure::new("configuration_changed"));
    }
    Ok((paths, server, token))
}

fn receipt_json(
    receipt: crate::api::session_stop::SessionStopReceipt,
    context: &Context,
) -> Result<Value, Failure> {
    let mut value =
        serde_json::to_value(receipt).map_err(|_| Failure::new("session_stop_response_invalid"))?;
    value["context"] =
        serde_json::to_value(context).map_err(|_| Failure::new("session_stop_response_invalid"))?;
    Ok(value)
}

fn failure_from_error(error: anyhow::Error) -> Failure {
    if error
        .downcast_ref::<session_stop::StopExit>()
        .is_some_and(|exit| exit.0 == 130)
    {
        return Failure::new("canceled");
    }
    if error
        .downcast_ref::<session_stop::StopExit>()
        .is_some_and(|exit| exit.0 != 0)
    {
        return Failure::new("session_stop_pending");
    }
    if let Ok(api) = error.downcast::<crate::api::ApiError>() {
        if let Some(code) = api.code() {
            let stable = match code {
                "SESSION_STOP_REQUEST_CONFLICT" => Some("SESSION_STOP_REQUEST_CONFLICT"),
                "SESSION_STOP_INTENT_MISMATCH" => Some("SESSION_STOP_INTENT_MISMATCH"),
                "SESSION_STOP_INTENT_DIGEST_INVALID" => Some("SESSION_STOP_INTENT_DIGEST_INVALID"),
                "SESSION_STOP_UNRESOLVED" => Some("SESSION_STOP_UNRESOLVED"),
                "SESSION_STOP_REQUEST_NOT_FOUND" => Some("SESSION_STOP_REQUEST_NOT_FOUND"),
                "SESSION_STOP_BINDING_MISMATCH" => Some("SESSION_STOP_BINDING_MISMATCH"),
                "SESSION_STOP_SCHEMA_UNSUPPORTED" => Some("SESSION_STOP_SCHEMA_UNSUPPORTED"),
                "SESSION_STOP_REASON_INVALID" => Some("SESSION_STOP_REASON_INVALID"),
                _ => None,
            };
            if let Some(code) = stable {
                return Failure {
                    code,
                    retryable: false,
                    http_status: api.status_code(),
                };
            }
        }
        return Failure::api(api);
    }
    Failure::new("session_stop_status_unavailable")
}

fn canonical_uuid(value: &str) -> bool {
    crate::api::runtime_recovery::canonical_uuid(value)
}

fn valid_context(context: &Context) -> bool {
    context.home.is_absolute()
        && context.server_url.as_deref().is_some_and(|url| {
            (url.starts_with("http://") || url.starts_with("https://"))
                && !url.chars().any(char::is_control)
        })
        && context
            .active_device_id
            .as_deref()
            .is_some_and(canonical_uuid)
}

fn default_reason() -> String {
    "user_requested".into()
}

fn default_timeout() -> u64 {
    60
}
