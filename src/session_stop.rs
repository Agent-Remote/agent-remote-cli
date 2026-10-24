//! Exact caller-key stop submission and GET-only recovery.
//!
//! A stop request is bound to the complete session/runtime identity observed
//! immediately before submission. Transport failures preserve an `unknown`
//! journal phase and expose the original key for status recovery; they never
//! submit a replacement stop.

use crate::api::session_stop::{CallerKeySessionStopRequest, SessionStopReceipt};
use crate::api::{ApiClient, SessionData};
use crate::config::AppPaths;
use crate::local_state::{LocalState, SessionStopRecord};
use crate::terminal::{self, Details};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout_at, Duration, Instant};
use uuid::Uuid;

/// Stable launcher exit code for a stop submission whose acceptance is unknown.
#[derive(Debug)]
pub struct StopSubmissionUnknown(pub String);

impl std::fmt::Display for StopSubmissionUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session stop acceptance is unknown; query the original request with `fclaude stop-status {}`.",
            self.0
        )
    }
}

impl std::error::Error for StopSubmissionUnknown {}

/// Stable launcher exit code for a bounded stop observation.
#[derive(Debug)]
pub struct StopExit(pub i32);

impl std::fmt::Display for StopExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            130 => "Session stop wait interrupted; the original request remains available.",
            _ => "Session stop remains pending; query the original request again.",
        })
    }
}

impl std::error::Error for StopExit {}

/// Generate the only caller identity accepted by the stop protocol.
pub fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

/// Keep local journal partitioning opaque and independent of user content.
pub fn authenticated_scope(access_token: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(access_token.as_bytes()))
}

/// Submit exactly one stop for the frozen session binding.
pub async fn submit(
    paths: &AppPaths,
    client: &ApiClient,
    server_url: &str,
    token: &str,
    session: &SessionData,
) -> Result<(SessionStopReceipt, SessionStopRecord)> {
    validate_session(session)?;
    let request_id = new_request_id();
    let original = SessionStopRecord {
        home: paths.home().to_path_buf(),
        server_url: server_url.to_string(),
        user_id: authenticated_scope(token),
        request_id: request_id.clone(),
        session_id: session.id.clone(),
        node_id: session.node_id.clone(),
        runtime_backend: session.runtime_backend.clone(),
        runtime_resource_id: session.runtime_resource_id.clone(),
        expected_stop_task_id: session.stop_task_id.clone(),
        intent_fingerprint: intent_fingerprint(session, "user_requested"),
        reason: "user_requested".into(),
        phase: "prepared".into(),
        stop_task_id: None,
        stop_task_record_id: None,
        stop_task_status: None,
        session_status: Some(session.status.clone()),
        skill_finalization_operation_id: session.skill_finalization_operation_id.clone(),
        session_deleted: false,
        result_status: None,
        process_stopped: None,
        save_status: None,
        last_observation: None,
    };
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    if !state.reserve_session_stop(&original)? {
        bail!("a stop request for this caller key is already recorded")
    }
    let request = CallerKeySessionStopRequest {
        schema_version: 1,
        request_id,
        expected_session_id: session.id.clone(),
        expected_node_id: session.node_id.clone(),
        expected_runtime_backend: session.runtime_backend.clone(),
        reason: "user_requested".into(),
        intent_fingerprint: original.intent_fingerprint.clone(),
        expected_stop_task_id: session.stop_task_id.clone(),
    };
    match client
        .stop_tool_session_with_caller_key(token, &session.id, &request)
        .await
    {
        Ok(receipt) => {
            let next = record_from_receipt(&original, &receipt);
            if !state.update_session_stop(&original, &next)? {
                bail!("session stop journal changed while submitting")
            }
            Ok((receipt, next))
        }
        Err(error) => {
            let code = error.code().unwrap_or("");
            // Locally rejected requests have no HTTP status because the POST
            // was never attempted; classify them as definite failures too.
            // Only transport/server uncertainty should preserve the caller
            // key as `unknown` for GET-only recovery.
            let definite = error.code() == Some("SESSION_STOP_INVALID_REQUEST")
                || error.status_code().is_some_and(|status| {
                    (400..500).contains(&status) && status != 408 && status != 429
                });
            let mut next = original.clone();
            next.phase = if definite { "rejected" } else { "unknown" }.into();
            next.last_observation = Some(if code.is_empty() {
                "SESSION_STOP_SUBMISSION_UNKNOWN".into()
            } else {
                code.to_string()
            });
            let _ = state.update_session_stop(&original, &next);
            if definite {
                Err(error.into())
            } else {
                Err(StopSubmissionUnknown(original.request_id).into())
            }
        }
    }
}

/// Observe one caller key using GET only. The optional journal record permits
/// recovery after a process restart without guessing a session or task.
pub async fn observe(
    paths: &AppPaths,
    client: &ApiClient,
    token: &str,
    request_id: &str,
    wait: bool,
    timeout: u64,
) -> Result<SessionStopReceipt> {
    if !canonical_uuid(request_id) {
        bail!("stop request ID must be a canonical non-zero UUID")
    }
    let original = LocalState::session_stop_records(paths)?
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
            response = timeout_at(deadline, client.get_tool_session_stop_request(token, request_id)) => response,
        };
        match response {
            Err(_) => break 3,
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(receipt)) => {
                if let Some(record) = &original {
                    validate_record_binding(record, &receipt)?;
                }
                if let Some(record) = &original {
                    let state = LocalState::open(paths)?;
                    let next = record_from_receipt(record, &receipt);
                    let _ = state.update_session_stop(record, &next)?;
                }
                let terminal = stop_terminal(&receipt);
                let failed = stop_failed(&receipt);
                latest = Some(receipt);
                if !wait || terminal || failed {
                    break if !wait || terminal {
                        0
                    } else if failed {
                        1
                    } else {
                        3
                    };
                }
            }
        }
        tokio::select! {
            biased;
            _ = &mut signal => break 130,
            _ = sleep(deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(500))) => {}
        }
    };
    let receipt = latest.ok_or_else(|| anyhow::Error::from(StopExit(code)))?;
    if code != 0 {
        return Err(StopExit(code).into());
    }
    Ok(receipt)
}

pub fn render(receipt: &SessionStopReceipt) {
    terminal::section("Claude Session Stop");
    Details::new()
        .field("Request ID", &receipt.request_id)
        .field("Session", &receipt.session_id)
        .field("Node", &receipt.node_id)
        .field("Backend", &receipt.runtime_backend)
        .status("Phase", &receipt.phase)
        .field("Stop task", receipt.stop_task_id.as_deref().unwrap_or("-"))
        .field(
            "Task status",
            receipt.stop_task_status.as_deref().unwrap_or("unknown"),
        )
        .field(
            "Session status",
            receipt.session_status.as_deref().unwrap_or("unknown"),
        )
        .render();
}

fn validate_session(session: &SessionData) -> Result<()> {
    if !canonical_uuid(&session.id)
        || !canonical_uuid(&session.node_id)
        || session.runtime_backend.is_empty()
        || session.runtime_backend.len() > 64
        || session.runtime_backend.chars().any(char::is_control)
        || session.tool_type != "claude"
        || session
            .stop_task_id
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 256)
    {
        bail!("session stop binding is incomplete or invalid")
    }
    Ok(())
}

fn validate_record_binding(record: &SessionStopRecord, receipt: &SessionStopReceipt) -> Result<()> {
    if receipt.schema_version != 1
        || receipt.request_id != record.request_id
        || receipt.session_id != record.session_id
        || receipt.node_id != record.node_id
        || receipt.runtime_backend != record.runtime_backend
        || receipt.runtime_resource_id != record.runtime_resource_id
        || receipt.intent_fingerprint != record.intent_fingerprint
        || receipt.reason != record.reason
        || record
            .expected_stop_task_id
            .as_ref()
            .or(record.stop_task_id.as_ref())
            .is_some_and(|expected| receipt.stop_task_id.as_ref() != Some(expected))
    {
        bail!("session stop response differs from the frozen request binding")
    }
    Ok(())
}

fn record_from_receipt(
    original: &SessionStopRecord,
    receipt: &SessionStopReceipt,
) -> SessionStopRecord {
    let mut next = original.clone();
    next.phase = receipt.phase.clone();
    next.stop_task_id = receipt.stop_task_id.clone();
    next.stop_task_record_id = receipt.stop_task_record_id.clone();
    next.stop_task_status = receipt.stop_task_status.clone();
    next.session_status = receipt.session_status.clone();
    next.skill_finalization_operation_id = receipt.skill_finalization_operation_id.clone();
    next.session_deleted = receipt.session_deleted;
    next.result_status = receipt.result_status.clone();
    next.process_stopped = receipt.process_stopped;
    next.save_status = receipt.save_status.clone();
    next.last_observation = receipt
        .error_code
        .clone()
        .or_else(|| receipt.observed_at.clone());
    next
}

fn stop_terminal(receipt: &SessionStopReceipt) -> bool {
    receipt.session_deleted
        || (receipt.process_stopped == Some(true)
            && (receipt.phase == "stopped"
                || receipt.phase == "deleted"
                || receipt.session_status.as_deref() == Some("stopped")))
}

fn stop_failed(receipt: &SessionStopReceipt) -> bool {
    matches!(receipt.phase.as_str(), "failed" | "rejected")
        || receipt
            .stop_task_status
            .as_deref()
            .is_some_and(|status| matches!(status, "failed" | "cancelled" | "expired"))
}

/// Whether the server has reported a terminal process-stop outcome.
pub fn is_terminal(receipt: &SessionStopReceipt) -> bool {
    stop_terminal(receipt)
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == value)
}

#[cfg(test)]
#[path = "../tests/unit/src/session_stop.rs"]
mod tests;

fn intent_fingerprint(session: &SessionData, reason: &str) -> String {
    let mut value = std::collections::BTreeMap::new();
    value.insert("schema_version", serde_json::json!(1));
    value.insert("session_id", serde_json::json!(session.id));
    value.insert("node_id", serde_json::json!(session.node_id));
    value.insert(
        "runtime_backend",
        serde_json::json!(session.runtime_backend),
    );
    value.insert(
        "runtime_resource_id",
        serde_json::json!(session.runtime_resource_id),
    );
    value.insert("reason", serde_json::json!(reason));
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(bytes))
}
