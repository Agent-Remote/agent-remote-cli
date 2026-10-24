//! Caller-key transport for exact remote session stops.
//!
//! A stop request freezes the complete runtime binding observed by the caller.
//! The POST and owner-scoped GET are deliberately separate methods: after a
//! transport failure callers may inspect the original key, but they must not
//! submit a second stop with a new identity.

use super::{url_encode, ApiClient, ApiError, Envelope, SessionData};
use serde::{Deserialize, Serialize};

/// The public binding sent with a caller-key stop request.
#[derive(Clone, Debug, Serialize)]
pub struct CallerKeySessionStopRequest {
    pub schema_version: u8,
    pub request_id: String,
    pub expected_session_id: String,
    pub expected_node_id: String,
    pub expected_runtime_backend: String,
    pub reason: String,
    pub intent_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_stop_task_id: Option<String>,
}

/// Immutable acceptance identity and bounded stop observation.
///
/// The server owns the lifecycle state; this receipt is only an exact
/// projection used by CLI and desktop recovery.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionStopReceipt {
    pub schema_version: u32,
    pub request_id: String,
    pub phase: String,
    pub session_id: String,
    pub node_id: String,
    pub runtime_backend: String,
    #[serde(default)]
    pub runtime_resource_id: Option<String>,
    #[serde(default)]
    pub stop_task_id: Option<String>,
    #[serde(default)]
    pub stop_task_record_id: Option<String>,
    #[serde(default)]
    pub stop_task_status: Option<String>,
    #[serde(default)]
    pub session_status: Option<String>,
    #[serde(default)]
    pub skill_finalization_operation_id: Option<String>,
    #[serde(default)]
    pub session_deleted: bool,
    #[serde(default)]
    pub observed_at: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub intent_fingerprint: String,
    #[serde(default = "default_stop_reason")]
    pub reason: String,
    #[serde(default)]
    pub result_status: Option<String>,
    #[serde(default)]
    pub process_stopped: Option<bool>,
    #[serde(default)]
    pub save_status: Option<String>,
}

impl ApiClient {
    /// Submit one caller-key stop.  This is the only method that can mutate.
    pub async fn stop_tool_session_with_caller_key(
        &self,
        token: &str,
        session_id: &str,
        request: &CallerKeySessionStopRequest,
    ) -> Result<SessionStopReceipt, ApiError> {
        validate_request(session_id, request)?;
        let response: Envelope<serde_json::Value> = self
            .post(
                &format!("/api/v1/sessions/{}/stop", url_encode(session_id)),
                Some(token),
                request,
            )
            .await?;
        if let Ok(receipt) = serde_json::from_value::<SessionStopReceipt>(response.data.clone()) {
            validate_receipt(&receipt, request)?;
            return Ok(receipt);
        }
        // Older servers returned the mutable session row directly. Preserve
        // compatibility while marking the receipt as legacy; callers never
        // retry a legacy or otherwise uncertain submission automatically.
        let session: SessionData =
            serde_json::from_value(response.data).map_err(|_| invalid_request())?;
        if session.id != request.expected_session_id
            || session.node_id != request.expected_node_id
            || session.runtime_backend != request.expected_runtime_backend
            || request
                .expected_stop_task_id
                .as_ref()
                .is_some_and(|expected| session.stop_task_id.as_ref() != Some(expected))
        {
            return Err(invalid_request());
        }
        Ok(SessionStopReceipt {
            schema_version: 1,
            request_id: request.request_id.clone(),
            phase: "legacy".into(),
            session_id: session.id,
            node_id: session.node_id,
            runtime_backend: session.runtime_backend,
            runtime_resource_id: session.runtime_resource_id,
            stop_task_id: session.stop_task_id,
            stop_task_record_id: None,
            stop_task_status: None,
            session_status: Some(session.status),
            skill_finalization_operation_id: session.skill_finalization_operation_id,
            session_deleted: false,
            observed_at: Some(session.updated_at),
            error_code: None,
            intent_fingerprint: request.intent_fingerprint.clone(),
            reason: request.reason.clone(),
            result_status: None,
            process_stopped: None,
            save_status: None,
        })
    }

    /// Observe an exact owner-scoped stop caller key.  This method is GET-only.
    pub async fn get_tool_session_stop_request(
        &self,
        token: &str,
        request_id: &str,
    ) -> Result<SessionStopReceipt, ApiError> {
        if !canonical_uuid(request_id) {
            return Err(invalid_request());
        }
        let response: Envelope<SessionStopReceipt> = self
            .get(
                &format!("/api/v1/sessions/stop-requests/{}", url_encode(request_id)),
                Some(token),
            )
            .await?;
        if response.data.request_id != request_id || response.data.schema_version != 1 {
            return Err(invalid_request());
        }
        Ok(response.data)
    }
}

fn validate_request(
    session_id: &str,
    request: &CallerKeySessionStopRequest,
) -> Result<(), ApiError> {
    if request.schema_version != 1
        || !canonical_uuid(session_id)
        || request.expected_session_id != session_id
        || !canonical_uuid(&request.request_id)
        || !canonical_uuid(&request.expected_session_id)
        || !canonical_uuid(&request.expected_node_id)
        || request.expected_runtime_backend.is_empty()
        || request.expected_runtime_backend.len() > 64
        || request
            .expected_runtime_backend
            .chars()
            .any(char::is_control)
        || request.reason != "user_requested"
        || !valid_digest(&request.intent_fingerprint)
        || request
            .expected_stop_task_id
            .as_deref()
            .is_some_and(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn validate_receipt(
    receipt: &SessionStopReceipt,
    request: &CallerKeySessionStopRequest,
) -> Result<(), ApiError> {
    if receipt.schema_version != 1
        || receipt.request_id != request.request_id
        || receipt.session_id != request.expected_session_id
        || receipt.node_id != request.expected_node_id
        || receipt.runtime_backend != request.expected_runtime_backend
        || receipt.intent_fingerprint != request.intent_fingerprint
        || receipt.reason != request.reason
        || request
            .expected_stop_task_id
            .as_ref()
            .is_some_and(|expected| receipt.stop_task_id.as_ref() != Some(expected))
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == value)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn default_stop_reason() -> String {
    "user_requested".into()
}

fn invalid_request() -> ApiError {
    ApiError::local(
        "SESSION_STOP_INVALID_REQUEST",
        "invalid caller-key session stop request",
    )
}
