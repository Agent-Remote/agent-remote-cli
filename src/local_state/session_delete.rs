//! Metadata-only journal for caller-key session deletion.
//!
//! Only the reviewed public collection, context and receipt identifiers are
//! retained.  The journal never stores credentials, prompts, source paths or
//! a dynamic query that could be re-evaluated after a lost response.

use super::{initialization, LocalState};
use crate::api::session_delete::{SessionDeleteContext, SessionDeleteSelection};
use crate::config::AppPaths;
use anyhow::{bail, Result};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const PREFIX: &str = "session_delete_request:";
const LIMIT: usize = 256;
const MAX_RECORD_BYTES: usize = 64 * 1024;

/// Public caller-key deletion metadata safe to persist locally.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionDeleteRecord {
    pub home: PathBuf,
    pub server_url: String,
    pub user_id: String,
    pub request_id: String,
    pub tool_type: String,
    pub session_ids: Vec<String>,
    pub selection: SessionDeleteSelection,
    pub selection_digest: String,
    pub intent_fingerprint: String,
    pub reason: String,
    pub phase: String,
    pub delete_task_id: Option<String>,
    pub delete_task_record_id: Option<String>,
    pub task_status: Option<String>,
    pub deleted_session_ids: Vec<String>,
    pub session_statuses: std::collections::BTreeMap<String, String>,
    pub session_contexts: Vec<SessionDeleteContext>,
    pub session_deleted: bool,
    pub result_status: Option<String>,
    pub last_observation: Option<String>,
}

impl LocalState {
    /// Read deletion records without creating or migrating local state.
    pub fn session_delete_records(paths: &AppPaths) -> Result<Vec<SessionDeleteRecord>> {
        match std::fs::symlink_metadata(paths.state_db_path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            value => {
                value?;
            }
        }
        let path = readonly_database_path(paths)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(3))?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='kv')",
            [],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(Vec::new());
        }
        let mut statement = connection.prepare(
            "SELECT key,substr(value,1,?) FROM kv
             WHERE key GLOB 'session_delete_request:*' ORDER BY key LIMIT ?",
        )?;
        let rows = statement.query_map([MAX_RECORD_BYTES as i64 + 1, LIMIT as i64 + 1], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (key, raw) = row?;
            if raw.len() > MAX_RECORD_BYTES || records.len() >= LIMIT {
                bail!("session deletion journal limit exceeded");
            }
            let record: SessionDeleteRecord = serde_json::from_str(&raw)?;
            validate_record(&key, &record, paths)?;
            records.push(record);
        }
        Ok(records)
    }

    /// Reserve an immutable caller key before the first mutating request.
    pub fn reserve_session_delete(&self, record: &SessionDeleteRecord) -> Result<bool> {
        validate_record_value(record, None)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let key = format!("{PREFIX}{}", record.request_id);
        if transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM kv WHERE key=?1)",
            [&key],
            |row| row.get::<_, bool>(0),
        )? {
            return Ok(false);
        }
        let count: usize = transaction.query_row(
            "SELECT COUNT(*) FROM kv WHERE key GLOB 'session_delete_request:*'",
            [],
            |row| row.get(0),
        )?;
        if count >= LIMIT {
            bail!("session deletion journal limit exceeded");
        }
        let raw = serde_json::to_string(record)?;
        if raw.len() > MAX_RECORD_BYTES {
            bail!("session deletion journal record too large");
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO kv(key,value) VALUES(?1,?2)",
            params![key, raw],
        )? == 1;
        transaction.commit()?;
        Ok(inserted)
    }

    /// Compare and swap only the mutable receipt observation fields.
    pub fn update_session_delete(
        &self,
        original: &SessionDeleteRecord,
        next: &SessionDeleteRecord,
    ) -> Result<bool> {
        validate_record_value(original, None)?;
        validate_record_value(next, Some(original))?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let key = format!("{PREFIX}{}", original.request_id);
        let raw: Option<String> = transaction
            .query_row(
                "SELECT substr(value,1,?) FROM kv WHERE key=?2",
                params![MAX_RECORD_BYTES as i64 + 1, key.clone()],
                |row| row.get(0),
            )
            .optional()?;
        let current: Option<SessionDeleteRecord> =
            raw.map(|value| serde_json::from_str(&value)).transpose()?;
        if current.as_ref() != Some(original) {
            return Ok(false);
        }
        let encoded = serde_json::to_string(next)?;
        if encoded.len() > MAX_RECORD_BYTES {
            bail!("session deletion journal record too large");
        }
        transaction.execute(
            "UPDATE kv SET value=?2,updated_at=CURRENT_TIMESTAMP WHERE key=?1",
            params![key, encoded],
        )?;
        transaction.commit()?;
        Ok(true)
    }
}

fn readonly_database_path(paths: &AppPaths) -> Result<PathBuf> {
    let home = initialization::checked_home(paths, false)?;
    let database = paths.state_db_path();
    let name = database
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("metadata filename missing"))?;
    let path = std::fs::canonicalize(home)?.join(name);
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        initialization::validate_file(std::path::Path::new(&value))?;
    }
    Ok(path)
}

fn validate_record(key: &str, record: &SessionDeleteRecord, paths: &AppPaths) -> Result<()> {
    if key != format!("{PREFIX}{}", record.request_id) || record.home != paths.home() {
        bail!("invalid session deletion journal record");
    }
    validate_record_value(record, None)
}

fn validate_record_value(
    record: &SessionDeleteRecord,
    original: Option<&SessionDeleteRecord>,
) -> Result<()> {
    use crate::account_import::valid_uuid;
    let valid_digest = |value: &str| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..].bytes().all(|b| b.is_ascii_hexdigit())
    };
    let valid_text = |value: &str, max: usize| {
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
    };
    let valid_phase = matches!(
        record.phase.as_str(),
        "prepared" | "accepted" | "deleting" | "deleted" | "failed" | "unknown" | "rejected"
    );
    if !record.home.is_absolute()
        || !valid_text(&record.server_url, 2048)
        || !(record.server_url.starts_with("http://") || record.server_url.starts_with("https://"))
        || !valid_digest(&record.user_id)
        || !valid_uuid(&record.request_id)
        || !valid_text(&record.tool_type, 64)
        || record.session_ids.is_empty()
        || record.session_ids.len() > 256
        || record.session_ids.iter().any(|id| !valid_uuid(id))
        || record.session_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || record.selection.tool_type != record.tool_type
        || record.selection.statuses.is_empty()
        || record.selection.statuses.len() > 16
        || record
            .selection
            .statuses
            .iter()
            .any(|status| !valid_text(status, 32))
        || record
            .selection
            .project_key
            .as_deref()
            .is_some_and(|key| !valid_text(key, 512))
        || !valid_digest(&record.selection_digest)
        || !valid_digest(&record.intent_fingerprint)
        || record.reason != "user_requested"
        || !valid_phase
        || record
            .deleted_session_ids
            .iter()
            .any(|id| !record.session_ids.iter().any(|candidate| candidate == id))
        || record
            .session_statuses
            .keys()
            .any(|id| !record.session_ids.iter().any(|candidate| candidate == id))
        || !(record.session_contexts.is_empty()
            && matches!(record.phase.as_str(), "prepared" | "unknown" | "rejected")
            || valid_contexts(&record.session_contexts, &record.session_ids))
    {
        bail!("invalid session deletion journal record");
    }
    if let Some(original) = original {
        if record.home != original.home
            || record.server_url != original.server_url
            || record.user_id != original.user_id
            || record.request_id != original.request_id
            || record.tool_type != original.tool_type
            || record.session_ids != original.session_ids
            || record.selection != original.selection
            || record.selection_digest != original.selection_digest
            || record.intent_fingerprint != original.intent_fingerprint
            || record.reason != original.reason
        {
            bail!("session deletion journal identity changed");
        }
    }
    Ok(())
}

fn valid_contexts(contexts: &[SessionDeleteContext], session_ids: &[String]) -> bool {
    contexts.len() == session_ids.len()
        && contexts.iter().all(|context| {
            valid_uuid(&context.session_id)
                && valid_uuid(&context.tool_account_id)
                && valid_uuid(&context.workspace_id)
                && valid_uuid(&context.node_id)
                && valid_context_text(&context.project_key, 512)
                && valid_context_text(&context.runtime_backend, 64)
                && context
                    .runtime_resource_id
                    .as_deref()
                    .is_none_or(|value| valid_context_text(value, 256))
                && session_ids.iter().any(|id| id == &context.session_id)
        })
        && contexts
            .iter()
            .map(|context| context.session_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == session_ids.len()
}

fn valid_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == value)
}

fn valid_context_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
