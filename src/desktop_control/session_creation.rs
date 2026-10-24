use crate::{
    account_defaults::Context,
    api::{self, session_creation::CallerKeySessionCreateRequest, ApiClient, CreateSessionRequest},
    auth,
    config::{AppPaths, Config},
    local_state::{LocalState, SessionCreateRecord},
    session_creation,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    confirmed: bool,
    schema_version: u8,
    expected_context: Context,
    tool_type: String,
    tool_account_id: String,
    workspace_id: String,
    project_key: String,
    argv_digest: String,
    #[serde(default)]
    intent_fingerprint: Option<String>,
    #[serde(default)]
    replacement: Option<Replacement>,
    #[serde(default)]
    sync_target: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    session_id: String,
    tool_account_id: String,
    workspace_id: String,
    project_key: String,
    node_id: String,
    runtime_backend: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observe {
    request_id: String,
    expected_context: Context,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    match request.method.as_str() {
        "sessions.create" => create(request).await,
        "sessions.create.request" => observe(request).await,
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn create(request: &Request) -> Result<Value, Failure> {
    let input: Create = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed
        || input.schema_version != 1
        || !crate::api::runtime_recovery::canonical_uuid(&input.tool_account_id)
        || !crate::api::runtime_recovery::canonical_uuid(&input.workspace_id)
        || !valid_digest(&input.argv_digest)
        || !input.sync_target.is_object()
        || input.sync_target == Value::Null
        || input.replacement.as_ref().is_some_and(|v| {
            !crate::api::runtime_recovery::canonical_uuid(&v.session_id)
                || !crate::api::runtime_recovery::canonical_uuid(&v.tool_account_id)
                || !crate::api::runtime_recovery::canonical_uuid(&v.workspace_id)
                || !crate::api::runtime_recovery::canonical_uuid(&v.node_id)
                || v.project_key.is_empty()
                || v.runtime_backend.is_empty()
        })
    {
        return Err(Failure::new("invalid_params"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let config = Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    let server = config
        .server_url
        .clone()
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let (_device, device_id, token) = auth::load_device_token(&paths)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?;
    if input.expected_context.home != *paths.home()
        || input.expected_context.server_url.as_deref() != Some(server.as_str())
        || input.expected_context.active_device_id.as_deref() != Some(device_id.as_str())
    {
        return Err(Failure::new("configuration_changed"));
    }
    let request_id = session_creation::new_request_id();
    let digest = input.argv_digest.clone();
    let replacement_session_id = input.replacement.as_ref().map(|v| v.session_id.clone());
    let sync_target_digest = input
        .sync_target
        .get("target_digest")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let intent_fingerprint = input.intent_fingerprint.unwrap_or_else(|| {
        session_creation::intent_fingerprint_wire(
            &input.tool_type,
            &input.tool_account_id,
            &input.workspace_id,
            &input.project_key,
            &digest,
            replacement_session_id.as_deref(),
            &input.sync_target,
        )
    });
    let user_scope = session_creation::authenticated_scope(&token);
    let original = SessionCreateRecord {
        home: paths.home().to_path_buf(),
        server_url: server.clone(),
        user_id: user_scope,
        request_id: request_id.clone(),
        tool_type: input.tool_type.clone(),
        tool_account_id: input.tool_account_id.clone(),
        workspace_id: input.workspace_id.clone(),
        project_key: input.project_key.clone(),
        argv_digest: digest.clone(),
        replacement_session_id: replacement_session_id.clone(),
        sync_target_digest: sync_target_digest.clone(),
        prepare_task_id: None,
        prepare_task_record_id: None,
        phase: "prepared".into(),
        session_id: None,
        create_task_id: None,
        task_record_id: None,
        last_observation: None,
    };
    let state =
        LocalState::open(&paths).map_err(|_| Failure::new("session_create_journal_unavailable"))?;
    state
        .init_schema()
        .map_err(|_| Failure::new("session_create_journal_unavailable"))?;
    if !state
        .reserve_session_create(&original)
        .map_err(|_| Failure::new("session_create_journal_unavailable"))?
    {
        return Err(Failure::new("session_create_pending"));
    }
    let client = ApiClient::new(server).map_err(|_| Failure::new("configuration_unavailable"))?;
    let payload = CallerKeySessionCreateRequest {
        session: CreateSessionRequest {
            tool_type: input.tool_type,
            tool_account_id: input.tool_account_id,
            workspace_id: input.workspace_id,
            project_key: input.project_key,
            argv: Vec::new(),
            replaces_session_id: replacement_session_id,
        },
        request_id,
        argv_digest: digest,
        schema_version: 1,
        intent_fingerprint,
        sync_target: Some(input.sync_target),
        sync_target_digest,
        prepare_task_id: None,
        prepare_task_record_id: None,
    };
    match client
        .create_tool_session_with_caller_key(&token, &payload)
        .await
    {
        Ok(receipt) => {
            let next = record_from_receipt(&original, &receipt, "accepted");
            state
                .update_session_create(&original, &next)
                .map_err(|_| Failure::new("session_create_outcome_unknown"))?;
            Ok(receipt_json(receipt, &input.expected_context))
        }
        Err(error) => {
            let code = api::session_creation::map_caller_key_error(&error);
            if code != "SESSION_CREATE_SUBMISSION_UNKNOWN" {
                let mut next = original.clone();
                next.phase = if code == "SESSION_CREATE_ADMISSION_PENDING" {
                    "admission_pending"
                } else {
                    "rejected"
                }
                .into();
                next.last_observation = Some(code.into());
                let _ = state.update_session_create(&original, &next);
            } else {
                // The POST outcome is unknown, but the CLI already owns the
                // durable caller key. Project that safe journal identity so
                // desktop can offer an exact GET recovery after a lost
                // response; never generate a replacement key or replay POST.
                if let Ok(records) = LocalState::session_create_records(&paths) {
                    if let Some(record) = records.into_iter().find(|value| {
                        value.request_id == original.request_id && same_identity(value, &original)
                    }) {
                        return Ok(unknown_receipt_json(&record, &input.expected_context));
                    }
                }
            }
            Err(Failure {
                code,
                retryable: code == "SESSION_CREATE_SUBMISSION_UNKNOWN",
                http_status: error.status_code(),
            })
        }
    }
}

fn same_identity(left: &SessionCreateRecord, right: &SessionCreateRecord) -> bool {
    left.home == right.home
        && left.server_url == right.server_url
        && left.user_id == right.user_id
        && left.request_id == right.request_id
        && left.tool_type == right.tool_type
        && left.tool_account_id == right.tool_account_id
        && left.workspace_id == right.workspace_id
        && left.project_key == right.project_key
        && left.argv_digest == right.argv_digest
        && left.replacement_session_id == right.replacement_session_id
        && left.sync_target_digest == right.sync_target_digest
        && left.prepare_task_id == right.prepare_task_id
        && left.prepare_task_record_id == right.prepare_task_record_id
}

fn unknown_receipt_json(record: &SessionCreateRecord, context: &Context) -> Value {
    json!({
        "schema_version": 1,
        "request_id": record.request_id,
        "tool_type": record.tool_type,
        "tool_account_id": record.tool_account_id,
        "workspace_id": record.workspace_id,
        "project_key": record.project_key,
        "argv_digest": record.argv_digest,
        "phase": "unknown",
        "session_id": record.session_id,
        "task_id": record.create_task_id,
        "task_record_id": record.task_record_id,
        "error_code": "SESSION_CREATE_SUBMISSION_UNKNOWN",
        "context": serde_json::to_value(context).unwrap_or(Value::Null),
    })
}

async fn observe(request: &Request) -> Result<Value, Failure> {
    let input: Observe = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !crate::api::runtime_recovery::canonical_uuid(&input.request_id)
        || !valid_context(&input.expected_context)
    {
        return Err(Failure::new("invalid_params"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let config = Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    let server = config
        .server_url
        .clone()
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let (_device, _id, token) = auth::load_device_token(&paths)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?;
    let context = crate::account_defaults::Context {
        home: paths.home().to_path_buf(),
        server_url: config.server_url.clone(),
        active_device_id: config.active_device_id.clone(),
    };
    if context != input.expected_context {
        return Err(Failure::new("configuration_changed"));
    }
    let receipt = ApiClient::new(server)
        .map_err(|_| Failure::new("configuration_unavailable"))?
        .get_tool_session_request(&token, &input.request_id)
        .await
        .map_err(|error| Failure {
            code: api::session_creation::map_caller_key_error(&error),
            retryable: false,
            http_status: error.status_code(),
        })?;
    Ok(receipt_json(receipt, &context))
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
            .is_some_and(crate::api::runtime_recovery::canonical_uuid)
}

fn record_from_receipt(
    original: &SessionCreateRecord,
    receipt: &api::session_creation::SessionCreateReceipt,
    phase: &str,
) -> SessionCreateRecord {
    let mut result = original.clone();
    result.phase = phase.into();
    result.session_id = receipt.session_id.clone();
    result.create_task_id = receipt.create_task_id.clone();
    result.task_record_id = receipt.task_record_id.clone();
    result.last_observation = receipt
        .result_status
        .clone()
        .or(receipt.phase.clone().into());
    result
}

fn receipt_json(receipt: api::session_creation::SessionCreateReceipt, context: &Context) -> Value {
    let mut value = serde_json::to_value(receipt).unwrap_or_else(|_| json!({"phase":"unknown"}));
    value["context"] = serde_json::to_value(context).unwrap_or(Value::Null);
    value
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_hexdigit())
}
