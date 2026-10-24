//! Caller-key session creation transport.
//!
//! A caller key is an idempotency identity owned by the CLI.  The POST and
//! owner-scoped GET are intentionally separate methods so recovery can never
//! accidentally submit a second creation request.

use super::{url_encode, ApiClient, ApiError, CreateSessionRequest, Envelope, SessionData};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize)]
pub struct CallerKeySessionCreateRequest {
    #[serde(flatten)]
    pub session: CreateSessionRequest,
    pub request_id: String,
    pub schema_version: u8,
    pub argv_digest: String,
    pub intent_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_target: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_target_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepare_task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepare_task_record_id: Option<String>,
}

/// Immutable acceptance identity plus a bounded, mutable observation.
/// Unknown future fields are ignored for forward compatibility; callers only
/// expose the fields below to desktop and human output.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionCreateReceipt {
    pub schema_version: u32,
    pub request_id: String,
    pub tool_type: String,
    pub tool_account_id: String,
    pub workspace_id: String,
    pub project_key: String,
    pub argv_digest: String,
    #[serde(default)]
    pub intent_fingerprint: Option<String>,
    #[serde(default)]
    pub replacement_session_id: Option<String>,
    #[serde(default)]
    pub sync_target_digest: Option<String>,
    #[serde(default)]
    pub sync_target: Option<Value>,
    pub phase: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub create_task_id: Option<String>,
    #[serde(default)]
    pub task_record_id: Option<String>,
    #[serde(default)]
    pub task_status: Option<String>,
    #[serde(default)]
    pub session_status: Option<String>,
    #[serde(default)]
    pub result_status: Option<String>,
    #[serde(default)]
    pub session_deleted: bool,
    #[serde(default)]
    pub observed_at: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
}

impl ApiClient {
    /// Submit exactly one caller-key creation request.
    pub async fn create_tool_session_with_caller_key(
        &self,
        token: &str,
        request: &CallerKeySessionCreateRequest,
    ) -> Result<SessionCreateReceipt, ApiError> {
        validate_request(request)?;
        let response: Envelope<SessionData> =
            self.post("/api/v1/sessions", Some(token), request).await?;
        let receipt = receipt_from_session(response.data, request);
        validate_receipt(&receipt, request)?;
        Ok(receipt)
    }

    /// Observe an exact owner-scoped caller key.  This method is GET-only.
    pub async fn get_tool_session_request(
        &self,
        token: &str,
        request_id: &str,
    ) -> Result<SessionCreateReceipt, ApiError> {
        if !canonical_uuid(request_id) {
            return Err(invalid_request());
        }
        let response: Envelope<SessionCreateReceipt> = self
            .get(
                &format!("/api/v1/sessions/requests/{}", url_encode(request_id)),
                Some(token),
            )
            .await?;
        if response.data.request_id != request_id || response.data.schema_version != 1 {
            return Err(invalid_request());
        }
        Ok(response.data)
    }
}

fn validate_request(request: &CallerKeySessionCreateRequest) -> Result<(), ApiError> {
    if !canonical_uuid(&request.request_id)
        || request.schema_version != 1
        || !valid_digest(&request.argv_digest)
        || !valid_digest(&request.intent_fingerprint)
        || !request
            .sync_target_digest
            .as_deref()
            .is_none_or(valid_digest)
        || request
            .prepare_task_record_id
            .as_deref()
            .is_some_and(|value| !canonical_uuid(value))
        || request
            .prepare_task_id
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 256)
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn receipt_from_session(
    session: SessionData,
    request: &CallerKeySessionCreateRequest,
) -> SessionCreateReceipt {
    SessionCreateReceipt {
        schema_version: 1,
        request_id: request.request_id.clone(),
        tool_type: session.tool_type,
        tool_account_id: session.tool_account_id,
        workspace_id: session.workspace_id,
        project_key: session.project_key,
        argv_digest: request.argv_digest.clone(),
        intent_fingerprint: Some(request.intent_fingerprint.clone()),
        replacement_session_id: session.replaces_session_id,
        sync_target_digest: request.sync_target_digest.clone(),
        sync_target: request.sync_target.clone(),
        phase: "accepted".into(),
        session_id: Some(session.id),
        create_task_id: session.create_task_id,
        task_record_id: None,
        task_status: None,
        session_status: Some(session.status),
        result_status: None,
        session_deleted: false,
        observed_at: Some(session.updated_at),
        error_code: None,
    }
}

fn validate_receipt(
    receipt: &SessionCreateReceipt,
    request: &CallerKeySessionCreateRequest,
) -> Result<(), ApiError> {
    if receipt.schema_version != 1
        || receipt.request_id != request.request_id
        || receipt.tool_type != request.session.tool_type
        || receipt.tool_account_id != request.session.tool_account_id
        || receipt.workspace_id != request.session.workspace_id
        || receipt.project_key != request.session.project_key
        || receipt.argv_digest != request.argv_digest
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value && id != uuid::Uuid::nil())
}

fn invalid_request() -> ApiError {
    ApiError::local(
        "SESSION_CREATE_RESPONSE_INVALID",
        "caller-key request or response is invalid",
    )
}

/// Stable mapping used by CLI and desktop.  Transport errors remain unknown so
/// callers retain the key and issue GET rather than replaying POST.
pub fn map_caller_key_error(error: &ApiError) -> &'static str {
    match (error.status_code(), error.code()) {
        (Some(409), Some("SESSION_CREATE_REQUEST_CONFLICT")) => "SESSION_CREATE_REQUEST_CONFLICT",
        (Some(409), Some("SESSION_CREATE_SYNC_TARGET_CHANGED")) => {
            "SESSION_CREATE_SYNC_TARGET_CHANGED"
        }
        (Some(409), Some("SESSION_CREATE_SYNC_NOT_READY")) => "SESSION_CREATE_SYNC_NOT_READY",
        (Some(409), Some("SESSION_CREATE_PREPARE_UNPROVEN")) => "SESSION_CREATE_PREPARE_UNPROVEN",
        (Some(409), Some("SESSION_CREATE_NODE_MISMATCH")) => "SESSION_CREATE_NODE_MISMATCH",
        (Some(409), Some("SESSION_CREATE_REPLACEMENT_INVALID")) => {
            "SESSION_CREATE_REPLACEMENT_INVALID"
        }
        (Some(409), Some("SESSION_CREATE_ADMISSION_PENDING")) => "SESSION_CREATE_ADMISSION_PENDING",
        (Some(404), Some("SESSION_CREATE_REQUEST_NOT_FOUND")) => "SESSION_CREATE_REQUEST_NOT_FOUND",
        (Some(401), _) => "AUTHENTICATION_REQUIRED",
        (Some(403), _) => "PERMISSION_DENIED",
        (Some(status), _) if (400..500).contains(&status) && status != 408 && status != 429 => {
            "SESSION_CREATE_REJECTED"
        }
        _ => "SESSION_CREATE_SUBMISSION_UNKNOWN",
    }
}
