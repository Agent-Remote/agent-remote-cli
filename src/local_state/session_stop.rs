//! Metadata-only journal for caller-key session stops.
//!
//! The journal stores the reviewed public binding and immutable caller key so
//! a lost response can be recovered after a process restart. It never stores
//! command arguments, prompts, credentials, or raw task payloads.

use super::{initialization, LocalState};
use crate::config::AppPaths;
use anyhow::{bail, Result};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const PREFIX: &str = "session_stop_request:";
const LIMIT: usize = 256;
const MAX_RECORD_BYTES: usize = 32 * 1024;

/// Public, secret-free caller-key stop metadata.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionStopRecord {
    pub home: PathBuf,
    pub server_url: String,
    pub user_id: String,
    pub request_id: String,
    pub session_id: String,
    pub node_id: String,
    pub runtime_backend: String,
    pub runtime_resource_id: Option<String>,
    pub expected_stop_task_id: Option<String>,
    pub intent_fingerprint: String,
    pub reason: String,
    pub phase: String,
    pub stop_task_id: Option<String>,
    pub stop_task_record_id: Option<String>,
    pub stop_task_status: Option<String>,
    pub session_status: Option<String>,
    pub skill_finalization_operation_id: Option<String>,
    pub session_deleted: bool,
    pub result_status: Option<String>,
    pub process_stopped: Option<bool>,
    pub save_status: Option<String>,
    pub last_observation: Option<String>,
}

impl LocalState {
    /// Read existing stop records without creating local state.
    pub fn session_stop_records(paths: &AppPaths) -> Result<Vec<SessionStopRecord>> {
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
             WHERE key GLOB 'session_stop_request:*' ORDER BY key LIMIT ?",
        )?;
        let rows = statement.query_map([MAX_RECORD_BYTES as i64 + 1, LIMIT as i64 + 1], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (key, raw) = row?;
            if raw.len() > MAX_RECORD_BYTES || result.len() >= LIMIT {
                bail!("session stop journal limit exceeded");
            }
            let record: SessionStopRecord = serde_json::from_str(&raw)?;
            validate_record(&key, &record, paths)?;
            result.push(record);
        }
        Ok(result)
    }

    /// Reserve one caller key; an existing key is never replaced.
    pub fn reserve_session_stop(&self, record: &SessionStopRecord) -> Result<bool> {
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
            "SELECT COUNT(*) FROM kv WHERE key GLOB 'session_stop_request:*'",
            [],
            |row| row.get(0),
        )?;
        if count >= LIMIT {
            bail!("session stop journal limit exceeded");
        }
        let raw = serde_json::to_string(record)?;
        if raw.len() > MAX_RECORD_BYTES {
            bail!("session stop journal record too large");
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO kv(key,value) VALUES(?1,?2)",
            params![key, raw],
        )? == 1;
        transaction.commit()?;
        Ok(inserted)
    }

    /// Compare-and-swap mutable observation fields while retaining identity.
    pub fn update_session_stop(
        &self,
        original: &SessionStopRecord,
        next: &SessionStopRecord,
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
        let current: Option<SessionStopRecord> =
            raw.map(|value| serde_json::from_str(&value)).transpose()?;
        if current.as_ref() != Some(original) {
            return Ok(false);
        }
        let encoded = serde_json::to_string(next)?;
        if encoded.len() > MAX_RECORD_BYTES {
            bail!("session stop journal record too large");
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

fn validate_record(key: &str, record: &SessionStopRecord, paths: &AppPaths) -> Result<()> {
    if key != format!("{PREFIX}{}", record.request_id) || record.home != paths.home() {
        bail!("invalid session stop journal record");
    }
    validate_record_value(record, None)
}

fn validate_record_value(
    record: &SessionStopRecord,
    original: Option<&SessionStopRecord>,
) -> Result<()> {
    use crate::account_import::valid_uuid;
    let valid_text = |value: &str, max: usize| {
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
    };
    let valid_phase = matches!(
        record.phase.as_str(),
        "prepared"
            | "accepted"
            | "stopping"
            | "stopped"
            | "failed"
            | "unknown"
            | "deleted"
            | "rejected"
            | "legacy"
            | "settled"
            | "unresolved"
    );
    if !valid_uuid(&record.request_id)
        || !valid_uuid(&record.session_id)
        || !valid_uuid(&record.node_id)
        || !valid_text(&record.server_url, 8192)
        || !(record.server_url.starts_with("https://") || record.server_url.starts_with("http://"))
        || !valid_text(&record.user_id, 256)
        || !valid_text(&record.runtime_backend, 64)
        || !record
            .runtime_resource_id
            .as_deref()
            .is_none_or(|v| valid_text(v, 256))
        || record.reason != "user_requested"
        || !valid_digest(&record.intent_fingerprint)
        || !valid_phase
        || !record
            .expected_stop_task_id
            .as_deref()
            .is_none_or(|v| valid_text(v, 256))
        || !record
            .stop_task_id
            .as_deref()
            .is_none_or(|v| valid_text(v, 256))
        || !record.stop_task_record_id.as_deref().is_none_or(valid_uuid)
        || !record
            .stop_task_status
            .as_deref()
            .is_none_or(|v| valid_text(v, 64))
        || !record
            .session_status
            .as_deref()
            .is_none_or(|v| valid_text(v, 64))
        || !record
            .skill_finalization_operation_id
            .as_deref()
            .is_none_or(valid_uuid)
        || !record
            .last_observation
            .as_deref()
            .is_none_or(|v| valid_text(v, 128))
    {
        bail!("invalid session stop journal record");
    }
    if let Some(original) = original {
        if record.home != original.home
            || record.server_url != original.server_url
            || record.user_id != original.user_id
            || record.request_id != original.request_id
            || record.session_id != original.session_id
            || record.node_id != original.node_id
            || record.runtime_backend != original.runtime_backend
            || record.runtime_resource_id != original.runtime_resource_id
            || record.expected_stop_task_id != original.expected_stop_task_id
            || record.intent_fingerprint != original.intent_fingerprint
            || record.reason != original.reason
        {
            bail!("session stop caller binding changed");
        }
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_hexdigit())
}
