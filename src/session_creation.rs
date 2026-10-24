//! Session creation waits only on a Server receipt proving no session was created.

use crate::api::session_takeover::{SessionAdmission, TakeoverPhase};
use crate::api::{ApiClient, CreateSessionRequest, SessionData};
use crate::config::AppPaths;
use crate::local_state::SessionCreateRecord;
use crate::terminal::{self, Details};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout_at, Duration, Instant};
use uuid::Uuid;

/// Stable launcher exit code for bounded creation waits.
#[derive(Debug)]
pub struct CreationExit(pub i32);

/// Generate the only request identity accepted by the caller-key protocol.
/// UUID v4 is generated locally before any network request or preparation.
pub fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

/// Hash argv as canonical JSON (array order and UTF-8 are significant).
/// The raw values are never written to the caller-key journal.
pub fn argv_digest(argv: &[String]) -> String {
    let bytes = serde_json::to_vec(argv).expect("serializing Vec<String> cannot fail");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Return a non-secret authenticated scope for local partitioning.  Device
/// tokens are intentionally opaque, so the CLI uses a one-way digest; the
/// Server remains the authority for the actual authenticated user UUID.
pub fn authenticated_scope(access_token: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(access_token.as_bytes()))
}

/// Hash the reviewed identity fields used by the Server ledger.  Raw argv is
/// represented solely by `argv_digest`.
pub fn intent_fingerprint(
    tool_type: &str,
    tool_account_id: &str,
    workspace_id: &str,
    project_key: &str,
    argv_digest: &str,
    replacement_session_id: Option<&str>,
    sync_target_digest: Option<&str>,
) -> String {
    let value = serde_json::json!({
        "tool_type": tool_type,
        "tool_account_id": tool_account_id,
        "workspace_id": workspace_id,
        "project_key": project_key,
        "argv_digest": argv_digest,
        "replacement_session_id": replacement_session_id,
        "sync_target_digest": sync_target_digest,
    });
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Compute the Server v1 caller intent fingerprint. JSON objects are sorted
/// recursively and emitted without whitespace, matching Python's canonical
/// `json.dumps(..., sort_keys=True, separators=(',', ':'))`.
pub fn intent_fingerprint_wire(
    tool_type: &str,
    tool_account_id: &str,
    workspace_id: &str,
    project_key: &str,
    argv_digest: &str,
    replacement_session_id: Option<&str>,
    sync_target: &serde_json::Value,
) -> String {
    let value = serde_json::json!({
        "schema_version": 1,
        "tool_type": tool_type,
        "tool_account_id": tool_account_id,
        "workspace_id": workspace_id,
        "project_key": project_key,
        "argv_digest": argv_digest,
        "replacement_session_id": replacement_session_id,
        "sync_target": sync_target,
    });
    let canonical = canonical_json(value);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn canonical_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) => {
            let sorted = object
                .into_iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect::<std::collections::BTreeMap<_, _>>();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonical_json).collect())
        }
        other => other,
    }
}

/// Reserve the reviewed identity before the first caller-key POST.
pub fn reserve_caller_key(paths: &AppPaths, record: &SessionCreateRecord) -> Result<bool> {
    let state = crate::local_state::LocalState::open(paths)?;
    state.init_schema()?;
    state.reserve_session_create(record)
}

/// Update only mutable receipt/observation fields after a POST or GET.
pub fn update_caller_key(
    paths: &AppPaths,
    original: &SessionCreateRecord,
    next: &SessionCreateRecord,
) -> Result<bool> {
    let state = crate::local_state::LocalState::open(paths)?;
    state.update_session_create(original, next)
}

impl std::fmt::Display for CreationExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0 == 130 {
            "Session creation wait interrupted."
        } else {
            "Session creation wait timed out."
        })
    }
}
impl std::error::Error for CreationExit {}

/// Retain one deadline and interrupt handler across admission, observation and one resumed creation.
pub async fn create_with_takeover_wait(
    client: &ApiClient,
    token: &str,
    request: &CreateSessionRequest,
    bound: Duration,
) -> Result<SessionData> {
    let deadline = Instant::now() + bound;
    let signal = tokio::signal::ctrl_c();
    tokio::pin!(signal);
    let first = tokio::select! {
        biased;
        _ = &mut signal => return Err(CreationExit(130).into()),
        result = timeout_at(deadline, client.create_session_admission(token, request)) => result.map_err(|_| CreationExit(3))??,
    };
    let pending = match first {
        SessionAdmission::Created(session) => return Ok(*session),
        SessionAdmission::Takeover(pending) => pending,
    };
    terminal::note("Account skill takeover is pending; existing sessions may finish normally.");
    Details::new()
        .field("Takeover operation", &pending.takeover_id)
        .render();
    loop {
        let status = tokio::select! {
            biased;
            _ = &mut signal => return Err(CreationExit(130).into()),
            result = timeout_at(deadline, client.session_takeover_status(token, &pending.takeover_id, &pending.account_id)) => result.map_err(|_| CreationExit(3))??,
        };
        if status.recovery_required {
            bail!(
                "Account takeover requires recovery; retain operation {}.",
                pending.takeover_id
            );
        }
        if status.status == TakeoverPhase::Committed {
            break;
        }
        tokio::select! {
            biased;
            _ = &mut signal => return Err(CreationExit(130).into()),
            _ = sleep(deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(500))) => {}
        }
    }
    // The original request was explicitly rejected without a session. A committed takeover allows
    // one fresh creation; an uncertain response to that write must never trigger automatic replay.
    let resumed = tokio::select! {
        biased;
        _ = &mut signal => return Err(CreationExit(130).into()),
        result = timeout_at(deadline, client.create_session_admission(token, request)) => result.map_err(|_| CreationExit(3))??,
    };
    match resumed {
        SessionAdmission::Created(session) => Ok(*session),
        SessionAdmission::Takeover(_) => {
            bail!("Account admission remains pending after the original takeover committed.")
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/src/session_creation.rs"]
mod tests;
