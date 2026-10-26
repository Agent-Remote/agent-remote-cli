//! Caller-key transport for exact session deletion.
//!
//! A delete request freezes the complete set selected by the caller.  The
//! server may never expand that set while processing a request; a lost POST
//! response is recovered with the same owner-scoped caller key.

use super::{url_encode, ApiClient, ApiError, Envelope};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Public runtime identity captured at deletion acceptance. It lets desktop
/// bind a receipt to the reviewed node/backend without exposing credentials.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionDeleteContext {
    pub session_id: String,
    pub tool_account_id: String,
    pub workspace_id: String,
    pub project_key: String,
    pub node_id: String,
    pub runtime_backend: String,
    #[serde(default)]
    pub runtime_resource_id: Option<String>,
}

/// Public, non-secret summary of the selection reviewed by the caller.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionDeleteSelection {
    pub tool_type: String,
    pub statuses: Vec<String>,
    #[serde(default)]
    pub project_key: Option<String>,
}

/// One immutable deletion request body.
#[derive(Clone, Debug, Serialize)]
pub struct CallerKeySessionDeleteRequest {
    pub schema_version: u8,
    pub request_id: String,
    pub tool_type: String,
    pub session_ids: Vec<String>,
    pub selection: SessionDeleteSelection,
    pub selection_digest: String,
    pub intent_fingerprint: String,
    pub reason: String,
}

/// Immutable acceptance identity plus current bounded deletion observation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionDeleteReceipt {
    pub schema_version: u32,
    pub request_id: String,
    pub phase: String,
    pub tool_type: String,
    pub session_ids: Vec<String>,
    pub selection: SessionDeleteSelection,
    pub selection_digest: String,
    pub intent_fingerprint: String,
    /// Deletion reason echoed by the Server's immutable receipt.
    pub reason: String,
    #[serde(default)]
    pub delete_task_id: Option<String>,
    #[serde(default)]
    pub delete_task_record_id: Option<String>,
    #[serde(default)]
    pub task_status: Option<String>,
    #[serde(default)]
    pub deleted_session_ids: Vec<String>,
    #[serde(default)]
    pub session_statuses: BTreeMap<String, String>,
    #[serde(default)]
    pub session_contexts: Vec<SessionDeleteContext>,
    #[serde(default)]
    pub session_deleted: bool,
    #[serde(default)]
    pub observed_at: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub result_status: Option<String>,
    #[serde(default)]
    pub collection_mismatch: bool,
    #[serde(default)]
    pub retention_blockers: Vec<String>,
}

impl ApiClient {
    /// Submit exactly one frozen deletion collection.  This is the only
    /// mutating operation in this module.
    pub async fn delete_tool_sessions_with_caller_key(
        &self,
        token: &str,
        request: &CallerKeySessionDeleteRequest,
    ) -> Result<SessionDeleteReceipt, ApiError> {
        validate_request(request)?;
        let response: Envelope<SessionDeleteReceipt> = self
            .post("/api/v1/sessions/delete-requests", Some(token), request)
            .await?;
        validate_receipt(&response.data, request)?;
        Ok(response.data)
    }

    /// Observe one owner-scoped deletion request.  This method is GET-only.
    pub async fn get_tool_session_delete_request(
        &self,
        token: &str,
        request_id: &str,
    ) -> Result<SessionDeleteReceipt, ApiError> {
        if !canonical_uuid(request_id) {
            return Err(invalid_request());
        }
        let response: Envelope<SessionDeleteReceipt> = self
            .get(
                &format!(
                    "/api/v1/sessions/delete-requests/{}",
                    url_encode(request_id)
                ),
                Some(token),
            )
            .await?;
        if response.data.request_id != request_id
            || response.data.schema_version != 1
            || !valid_receipt_shape(&response.data)
        {
            return Err(invalid_request());
        }
        Ok(response.data)
    }
}

fn validate_request(request: &CallerKeySessionDeleteRequest) -> Result<(), ApiError> {
    if request.schema_version != 1
        || !canonical_uuid(&request.request_id)
        || request.tool_type.is_empty()
        || request.tool_type.len() > 64
        || request.tool_type.chars().any(char::is_control)
        || request.session_ids.is_empty()
        || request.session_ids.len() > 256
        || request
            .session_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || request.session_ids.iter().any(|id| !canonical_uuid(id))
        || request.selection.tool_type != request.tool_type
        || request.selection.statuses.is_empty()
        || request.selection.statuses.len() > 16
        || request.selection.statuses.iter().any(|status| {
            status.is_empty() || status.len() > 32 || status.chars().any(char::is_control)
        })
        || request.selection.project_key.as_deref().is_some_and(|key| {
            key.is_empty() || key.len() > 512 || key.chars().any(char::is_control)
        })
        || !valid_digest(&request.selection_digest)
        || !valid_digest(&request.intent_fingerprint)
        || request.reason != "user_requested"
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn validate_receipt(
    receipt: &SessionDeleteReceipt,
    request: &CallerKeySessionDeleteRequest,
) -> Result<(), ApiError> {
    if !valid_receipt_shape(receipt)
        || receipt.request_id != request.request_id
        || receipt.tool_type != request.tool_type
        || receipt.session_ids != request.session_ids
        || receipt.selection != request.selection
        || receipt.selection_digest != request.selection_digest
        || receipt.intent_fingerprint != request.intent_fingerprint
        || receipt.reason != request.reason
        || receipt
            .deleted_session_ids
            .iter()
            .any(|id| !request.session_ids.contains(id))
        || receipt
            .session_statuses
            .keys()
            .any(|id| !request.session_ids.contains(id))
        || !valid_contexts(&receipt.session_contexts, &request.session_ids)
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn valid_receipt_shape(receipt: &SessionDeleteReceipt) -> bool {
    receipt.schema_version == 1
        && canonical_uuid(&receipt.request_id)
        && !receipt.tool_type.is_empty()
        && receipt.tool_type.len() <= 64
        && !receipt.tool_type.chars().any(char::is_control)
        && !receipt.session_ids.is_empty()
        && receipt.session_ids.len() <= 256
        && receipt.session_ids.windows(2).all(|pair| pair[0] < pair[1])
        && receipt.session_ids.iter().all(|id| canonical_uuid(id))
        && receipt.selection.tool_type == receipt.tool_type
        && receipt.selection.statuses.len() <= 16
        && receipt.selection.statuses.iter().all(|status| {
            !status.is_empty() && status.len() <= 32 && !status.chars().any(char::is_control)
        })
        && receipt.selection.project_key.as_deref().is_none_or(|key| {
            !key.is_empty() && key.len() <= 512 && !key.chars().any(char::is_control)
        })
        && valid_digest(&receipt.selection_digest)
        && valid_digest(&receipt.intent_fingerprint)
        && valid_reason(&receipt.reason)
        && receipt
            .deleted_session_ids
            .iter()
            .all(|id| receipt.session_ids.contains(id))
        && receipt
            .session_statuses
            .keys()
            .all(|id| receipt.session_ids.contains(id))
        && valid_contexts(&receipt.session_contexts, &receipt.session_ids)
}

fn valid_contexts(contexts: &[SessionDeleteContext], session_ids: &[String]) -> bool {
    contexts.len() == session_ids.len()
        && contexts.iter().all(|context| {
            canonical_uuid(&context.session_id)
                && canonical_uuid(&context.tool_account_id)
                && canonical_uuid(&context.workspace_id)
                && canonical_uuid(&context.node_id)
                && context.project_key.len() <= 512
                && !context.project_key.chars().any(char::is_control)
                && !context.runtime_backend.is_empty()
                && context.runtime_backend.len() <= 64
                && !context.runtime_backend.chars().any(char::is_control)
                && context.runtime_resource_id.as_deref().is_none_or(|value| {
                    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
                })
                && session_ids.contains(&context.session_id)
        })
        && contexts
            .iter()
            .map(|context| context.session_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == session_ids.len()
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == value)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_reason(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && !value.chars().any(char::is_control)
}

fn invalid_request() -> ApiError {
    ApiError::local(
        "SESSION_DELETE_INVALID_REQUEST",
        "invalid caller-key session delete request",
    )
}
