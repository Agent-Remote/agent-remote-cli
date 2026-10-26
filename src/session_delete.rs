//! Exact caller-key deletion of a frozen session collection.
//!
//! Collection selection happens once, before the POST.  A lost response is
//! observed through the original request ID; the CLI never recomputes
//! `--all`, asks for the latest session, or silently submits a replacement
//! key.

use crate::api::session_delete::CallerKeySessionDeleteRequest;
use crate::api::{ApiClient, SessionData};
use crate::config::AppPaths;
use crate::identifiers::IdMatch;
use crate::local_state::{LocalState, SessionDeleteRecord};
use crate::terminal::{self, Details};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tokio::time::{sleep, timeout_at, Duration, Instant};
use uuid::Uuid;

const DELETABLE_STATUSES: [&str; 3] = ["failed", "interrupted", "stopped"];

pub use crate::api::session_delete::{SessionDeleteReceipt, SessionDeleteSelection};

/// Control-plane deletion eligibility. The CLI never widens this set.
pub fn deletable_statuses() -> Vec<String> {
    DELETABLE_STATUSES
        .iter()
        .map(|status| (*status).to_string())
        .collect()
}

/// Stable launcher error for a deletion submission whose acceptance is unknown.
#[derive(Debug)]
pub struct DeleteSubmissionUnknown(pub String);

impl std::fmt::Display for DeleteSubmissionUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session deletion acceptance is unknown; query the original request with `fclaude delete-status {}`.",
            self.0
        )
    }
}

impl std::error::Error for DeleteSubmissionUnknown {}

/// Stable launcher error for a bounded deletion observation.
#[derive(Debug)]
pub struct DeleteExit(pub i32);

impl std::fmt::Display for DeleteExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            130 => "Session deletion wait interrupted; the original request remains available.",
            _ => "Session deletion remains pending; query the original request again.",
        })
    }
}

impl std::error::Error for DeleteExit {}

pub fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn authenticated_scope(access_token: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(access_token.as_bytes()))
}

/// Select a fixed, sorted collection from one list response.
pub fn freeze_selection(
    sessions: Vec<SessionData>,
    tool_type: &str,
    reference: Option<&str>,
) -> Result<Vec<SessionData>> {
    let mut selected: Vec<SessionData> = if let Some(reference) = reference {
        let session_id = resolve_id(
            reference,
            sessions.iter().map(|session| session.id.as_str()),
        )?;
        sessions
            .into_iter()
            .filter(|session| session.id == session_id)
            .collect()
    } else {
        sessions
    };
    if selected.is_empty() {
        bail!("no deletable Claude sessions were found")
    }
    if selected.iter().any(|session| {
        session.tool_type != tool_type || !DELETABLE_STATUSES.contains(&session.status.as_str())
    }) {
        bail!("session is not in a deletable state")
    }
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    selected.dedup_by(|left, right| left.id == right.id);
    if selected.len() > 256 {
        bail!("session deletion collection is too large")
    }
    Ok(selected)
}

/// Submit exactly one frozen collection.  The journal is written before POST.
pub async fn submit(
    paths: &AppPaths,
    client: &ApiClient,
    server_url: &str,
    token: &str,
    tool_type: &str,
    sessions: &[SessionData],
) -> Result<(SessionDeleteReceipt, SessionDeleteRecord)> {
    if sessions.is_empty() {
        bail!("session deletion collection cannot be empty")
    }
    let mut ids: Vec<String> = sessions.iter().map(|session| session.id.clone()).collect();
    ids.sort();
    ids.dedup();
    if ids.len() != sessions.len() || ids.len() > 256 {
        bail!("session deletion collection is invalid")
    }
    if sessions.iter().any(|session| {
        session.tool_type != tool_type || !DELETABLE_STATUSES.contains(&session.status.as_str())
    }) {
        bail!("session deletion collection contains a non-deletable session")
    }
    let selection = SessionDeleteSelection {
        tool_type: tool_type.to_string(),
        statuses: DELETABLE_STATUSES
            .iter()
            .map(|status| (*status).to_string())
            .collect(),
        project_key: None,
    };
    let selection_digest = selection_digest(tool_type, &ids, &selection);
    let intent_fingerprint = intent_fingerprint(tool_type, &ids, &selection, "user_requested");
    let request_id = new_request_id();
    let request = CallerKeySessionDeleteRequest {
        schema_version: 1,
        request_id,
        tool_type: tool_type.to_string(),
        session_ids: ids,
        selection,
        selection_digest,
        intent_fingerprint,
        reason: "user_requested".into(),
    };
    submit_request(paths, client, server_url, token, request).await
}

/// Submit an already reviewed request supplied by desktop-control.  The
/// caller must provide the full frozen set and both matching fingerprints.
pub async fn submit_request(
    paths: &AppPaths,
    client: &ApiClient,
    server_url: &str,
    token: &str,
    request: CallerKeySessionDeleteRequest,
) -> Result<(SessionDeleteReceipt, SessionDeleteRecord)> {
    let original = SessionDeleteRecord {
        home: paths.home().to_path_buf(),
        server_url: server_url.to_string(),
        user_id: authenticated_scope(token),
        request_id: request.request_id.clone(),
        tool_type: request.tool_type.clone(),
        session_ids: request.session_ids.clone(),
        selection: request.selection.clone(),
        selection_digest: request.selection_digest.clone(),
        intent_fingerprint: request.intent_fingerprint.clone(),
        reason: request.reason.clone(),
        phase: "prepared".into(),
        delete_task_id: None,
        delete_task_record_id: None,
        task_status: None,
        deleted_session_ids: Vec::new(),
        session_statuses: BTreeMap::new(),
        session_contexts: Vec::new(),
        session_deleted: false,
        result_status: None,
        last_observation: None,
    };
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    if !state.reserve_session_delete(&original)? {
        bail!("a session deletion request for this caller key is already recorded")
    }
    match client
        .delete_tool_sessions_with_caller_key(token, &request)
        .await
    {
        Ok(receipt) => {
            let next = record_from_receipt(&original, &receipt);
            if !state.update_session_delete(&original, &next)? {
                bail!("session deletion journal changed while submitting")
            }
            Ok((receipt, next))
        }
        Err(error) => {
            let definite = error.code() == Some("SESSION_DELETE_INVALID_REQUEST")
                || error.status_code().is_some_and(|status| {
                    (400..500).contains(&status) && status != 408 && status != 429
                });
            let mut next = original.clone();
            next.phase = if definite { "rejected" } else { "unknown" }.into();
            next.last_observation = Some(
                error
                    .code()
                    .unwrap_or("SESSION_DELETE_SUBMISSION_UNKNOWN")
                    .to_string(),
            );
            let _ = state.update_session_delete(&original, &next);
            if definite {
                Err(error.into())
            } else {
                Err(DeleteSubmissionUnknown(original.request_id).into())
            }
        }
    }
}

/// Observe one deletion caller key through GET only.
pub async fn observe(
    paths: &AppPaths,
    client: &ApiClient,
    token: &str,
    request_id: &str,
    wait: bool,
    timeout: u64,
) -> Result<SessionDeleteReceipt> {
    if !canonical_uuid(request_id) {
        bail!("delete request ID must be a canonical non-zero UUID")
    }
    let original = LocalState::session_delete_records(paths)?
        .into_iter()
        .find(|record| record.request_id == request_id);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let signal = tokio::signal::ctrl_c();
    tokio::pin!(signal);
    let mut latest = None;
    let code = loop {
        let response = tokio::select! {
            biased;
            _ = &mut signal => break 130,
            response = timeout_at(deadline, client.get_tool_session_delete_request(token, request_id)) => response,
        };
        match response {
            Err(_) => break 3,
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(receipt)) => {
                if let Some(record) = &original {
                    validate_record_binding(record, &receipt)?;
                    let state = LocalState::open(paths)?;
                    let next = record_from_receipt(record, &receipt);
                    let _ = state.update_session_delete(record, &next)?;
                }
                let terminal = is_terminal(&receipt);
                let failed = is_failed(&receipt);
                latest = Some(receipt);
                if !wait || terminal || failed {
                    break if !wait || terminal { 0 } else { 1 };
                }
            }
        }
        tokio::select! {
            biased;
            _ = &mut signal => break 130,
            _ = sleep(deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(500))) => {}
        }
    };
    let receipt = latest.ok_or_else(|| anyhow::Error::from(DeleteExit(code)))?;
    if code != 0 {
        return Err(DeleteExit(code).into());
    }
    Ok(receipt)
}

pub fn render(receipt: &SessionDeleteReceipt) {
    terminal::section("Claude Session Delete");
    Details::new()
        .field("Request ID", &receipt.request_id)
        .field("Sessions", receipt.session_ids.len().to_string())
        .status("Phase", &receipt.phase)
        .field(
            "Delete task",
            receipt.delete_task_id.as_deref().unwrap_or("-"),
        )
        .field(
            "Task status",
            receipt.task_status.as_deref().unwrap_or("unknown"),
        )
        .field("Deleted", receipt.deleted_session_ids.len().to_string())
        .render();
}

/// Convert a journal record into the stable bridge receipt shape after a lost
/// submission response. The local record contains no credentials or private
/// payload, so this projection is safe for desktop recovery.
pub fn receipt_from_record(record: &SessionDeleteRecord) -> SessionDeleteReceipt {
    SessionDeleteReceipt {
        schema_version: 1,
        request_id: record.request_id.clone(),
        phase: record.phase.clone(),
        tool_type: record.tool_type.clone(),
        session_ids: record.session_ids.clone(),
        selection: record.selection.clone(),
        selection_digest: record.selection_digest.clone(),
        intent_fingerprint: record.intent_fingerprint.clone(),
        reason: record.reason.clone(),
        delete_task_id: record.delete_task_id.clone(),
        delete_task_record_id: record.delete_task_record_id.clone(),
        task_status: record.task_status.clone(),
        deleted_session_ids: record.deleted_session_ids.clone(),
        session_statuses: record.session_statuses.clone(),
        session_contexts: record.session_contexts.clone(),
        session_deleted: record.session_deleted,
        observed_at: None,
        error_code: record.last_observation.clone(),
        result_status: record.result_status.clone(),
        collection_mismatch: false,
        retention_blockers: Vec::new(),
    }
}

pub fn is_terminal(receipt: &SessionDeleteReceipt) -> bool {
    receipt.session_deleted
        || receipt.phase == "deleted"
        || (receipt.session_ids.len() == receipt.deleted_session_ids.len()
            && receipt
                .session_ids
                .iter()
                .all(|id| receipt.deleted_session_ids.contains(id)))
}

fn is_failed(receipt: &SessionDeleteReceipt) -> bool {
    matches!(receipt.phase.as_str(), "failed" | "rejected")
        || receipt
            .task_status
            .as_deref()
            .is_some_and(|status| matches!(status, "failed" | "cancelled" | "expired"))
        || receipt.collection_mismatch
        || !receipt.retention_blockers.is_empty()
}

fn record_from_receipt(
    original: &SessionDeleteRecord,
    receipt: &SessionDeleteReceipt,
) -> SessionDeleteRecord {
    let mut next = original.clone();
    next.phase = receipt.phase.clone();
    next.delete_task_id = receipt.delete_task_id.clone();
    next.delete_task_record_id = receipt.delete_task_record_id.clone();
    next.task_status = receipt.task_status.clone();
    next.deleted_session_ids = receipt.deleted_session_ids.clone();
    next.session_statuses = receipt.session_statuses.clone();
    next.session_contexts = receipt.session_contexts.clone();
    next.session_deleted = receipt.session_deleted;
    next.result_status = receipt.result_status.clone();
    next.last_observation = receipt.error_code.clone().or(receipt.observed_at.clone());
    next
}

fn validate_record_binding(
    record: &SessionDeleteRecord,
    receipt: &SessionDeleteReceipt,
) -> Result<()> {
    if receipt.schema_version != 1
        || receipt.request_id != record.request_id
        || receipt.tool_type != record.tool_type
        || receipt.session_ids != record.session_ids
        || receipt.selection != record.selection
        || receipt.selection_digest != record.selection_digest
        || receipt.intent_fingerprint != record.intent_fingerprint
        || receipt.reason != record.reason
        || receipt
            .deleted_session_ids
            .iter()
            .any(|id| !record.session_ids.contains(id))
        || receipt
            .session_statuses
            .keys()
            .any(|id| !record.session_ids.contains(id))
        || !valid_contexts(&receipt.session_contexts, &record.session_ids)
    {
        bail!("session deletion response differs from the frozen collection")
    }
    Ok(())
}

fn valid_contexts(
    contexts: &[crate::api::session_delete::SessionDeleteContext],
    session_ids: &[String],
) -> bool {
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

fn resolve_id<'a, I>(reference: &str, ids: I) -> Result<String>
where
    I: IntoIterator<Item = &'a str>,
{
    match crate::identifiers::match_id(reference, "Claude session", ids.into_iter())? {
        IdMatch::Unique(id) => Ok(id.to_string()),
        IdMatch::NotFound => bail!("no Claude session matches `{reference}`"),
        IdMatch::Ambiguous => bail!("Claude session reference `{reference}` is ambiguous"),
    }
}

fn selection_digest(
    tool_type: &str,
    session_ids: &[String],
    selection: &SessionDeleteSelection,
) -> String {
    digest(json!({
        "schema_version": 1,
        "tool_type": tool_type,
        "session_ids": session_ids,
        "selection": selection,
    }))
}

/// Compute the canonical selection digest for desktop-control validation.
pub fn selection_digest_for_control(
    tool_type: &str,
    session_ids: &[String],
    selection: &SessionDeleteSelection,
) -> String {
    selection_digest(tool_type, session_ids, selection)
}

fn intent_fingerprint(
    tool_type: &str,
    session_ids: &[String],
    selection: &SessionDeleteSelection,
    reason: &str,
) -> String {
    digest(json!({
        "schema_version": 1,
        "tool_type": tool_type,
        "session_ids": session_ids,
        "selection": selection,
        "reason": reason,
    }))
}

/// Compute the canonical intent fingerprint for desktop-control validation.
pub fn intent_fingerprint_for_control(
    tool_type: &str,
    session_ids: &[String],
    selection: &SessionDeleteSelection,
) -> String {
    intent_fingerprint(tool_type, session_ids, selection, "user_requested")
}

fn digest(value: Value) -> String {
    let canonical = canonical_json(value);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        other => other,
    }
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == value)
}

#[cfg(test)]
#[path = "../tests/unit/src/session_delete.rs"]
mod tests;
