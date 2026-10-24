//! Exact caller-key session collection deletion for the desktop bridge.

use crate::{
    account_defaults::Context,
    api::{session_delete::CallerKeySessionDeleteRequest, ApiClient},
    auth,
    config::{AppPaths, Config},
    session_delete,
};
use serde::Deserialize;
use serde_json::Value;

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delete {
    confirmed: bool,
    schema_version: u8,
    expected_context: Context,
    tool_type: String,
    session_ids: Vec<String>,
    selection: session_delete::SessionDeleteSelection,
    selection_digest: String,
    intent_fingerprint: String,
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
        "sessions.delete" => delete(request).await,
        "sessions.delete.request" | "sessions.delete.status" => observe(request).await,
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn delete(request: &Request) -> Result<Value, Failure> {
    let input: Delete = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed
        || input.schema_version != 1
        || input.reason != "user_requested"
        || !valid_context(&input.expected_context)
        || input.tool_type != "claude"
        || input.session_ids.is_empty()
        || input.session_ids.len() > 256
        || input.session_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || input.session_ids.iter().any(|id| !canonical_uuid(id))
        || !valid_digest(&input.selection_digest)
        || !valid_digest(&input.intent_fingerprint)
        || input.selection.tool_type != input.tool_type
        || input.selection.statuses.is_empty()
        || input.selection.statuses.len() > 16
        || input
            .selection
            .statuses
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || input
            .selection
            .statuses
            .iter()
            .any(|status| !session_delete::deletable_statuses().contains(status))
        || input.selection.project_key.as_deref().is_some_and(|value| {
            value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
        })
        || input.selection_digest
            != selection_digest(&input.tool_type, &input.session_ids, &input.selection)
        || input.intent_fingerprint
            != intent_fingerprint(&input.tool_type, &input.session_ids, &input.selection)
    {
        return Err(Failure::new("invalid_params"));
    }
    let (paths, server, token) = authenticated(&input.expected_context).await?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let sessions = client
        .list_sessions(&token, Some(&input.tool_type), &input.selection.statuses)
        .await
        .map_err(Failure::api)?;
    let selected: Vec<_> = sessions
        .into_iter()
        .filter(|session| {
            input.session_ids.iter().any(|id| id == &session.id)
                && input
                    .selection
                    .project_key
                    .as_deref()
                    .is_none_or(|project| session.project_key == project)
        })
        .collect();
    if selected.len() != input.session_ids.len() {
        return Err(Failure::new("session_binding_changed"));
    }
    // Preserve the exact collection reviewed by desktop, including its
    // status/project selection and canonical fingerprints.  The generic CLI
    // helper intentionally builds the default `--all` selection, so it cannot
    // be used here.
    let caller = CallerKeySessionDeleteRequest {
        schema_version: input.schema_version,
        request_id: session_delete::new_request_id(),
        tool_type: input.tool_type.clone(),
        session_ids: input.session_ids.clone(),
        selection: input.selection.clone(),
        selection_digest: input.selection_digest.clone(),
        intent_fingerprint: input.intent_fingerprint.clone(),
        reason: input.reason.clone(),
    };
    let (receipt, _) =
        match session_delete::submit_request(&paths, &client, &server, &token, caller).await {
            Ok(value) => value,
            Err(error) => {
                if let Some(unknown) =
                    error.downcast_ref::<session_delete::DeleteSubmissionUnknown>()
                {
                    let record = crate::local_state::LocalState::session_delete_records(&paths)
                        .map_err(|_| Failure::new("session_delete_journal_unavailable"))?
                        .into_iter()
                        .find(|record| record.request_id == unknown.0)
                        .ok_or_else(|| Failure::new("session_delete_outcome_unknown"))?;
                    return receipt_json(
                        session_delete::receipt_from_record(&record),
                        &input.expected_context,
                    );
                }
                return Err(failure_from_error(error));
            }
        };
    receipt_json(receipt, &input.expected_context)
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
    let receipt = session_delete::observe(
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
    receipt: session_delete::SessionDeleteReceipt,
    context: &Context,
) -> Result<Value, Failure> {
    let mut value = serde_json::to_value(receipt)
        .map_err(|_| Failure::new("session_delete_response_invalid"))?;
    value["context"] = serde_json::to_value(context)
        .map_err(|_| Failure::new("session_delete_response_invalid"))?;
    Ok(value)
}

fn failure_from_error(error: anyhow::Error) -> Failure {
    if error
        .downcast_ref::<session_delete::DeleteExit>()
        .is_some_and(|exit| exit.0 == 130)
    {
        return Failure::new("canceled");
    }
    if error
        .downcast_ref::<session_delete::DeleteExit>()
        .is_some_and(|exit| exit.0 != 0)
    {
        return Failure::new("session_delete_pending");
    }
    if let Ok(api) = error.downcast::<crate::api::ApiError>() {
        if let Some(code) = api.code().map(str::to_owned) {
            let stable = match code.as_str() {
                "SESSION_DELETE_REQUEST_CONFLICT" => Some("SESSION_DELETE_REQUEST_CONFLICT"),
                "SESSION_DELETE_COLLECTION_MISMATCH" => Some("SESSION_DELETE_COLLECTION_MISMATCH"),
                "SESSION_DELETE_CONTEXT_MISMATCH" => Some("SESSION_DELETE_CONTEXT_MISMATCH"),
                "SESSION_DELETE_UNRESOLVED" => Some("SESSION_DELETE_UNRESOLVED"),
                "SESSION_STOP_UNRESOLVED" => Some("SESSION_STOP_UNRESOLVED"),
                "SESSION_DELETE_REQUEST_NOT_FOUND" => Some("SESSION_DELETE_REQUEST_NOT_FOUND"),
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
    Failure::new("session_delete_status_unavailable")
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

fn canonical_uuid(value: &str) -> bool {
    crate::api::runtime_recovery::canonical_uuid(value)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn selection_digest(
    tool: &str,
    ids: &[String],
    selection: &session_delete::SessionDeleteSelection,
) -> String {
    session_delete::selection_digest_for_control(tool, ids, selection)
}

fn intent_fingerprint(
    tool: &str,
    ids: &[String],
    selection: &session_delete::SessionDeleteSelection,
) -> String {
    session_delete::intent_fingerprint_for_control(tool, ids, selection)
}

fn default_reason() -> String {
    "user_requested".into()
}
fn default_timeout() -> u64 {
    60
}
