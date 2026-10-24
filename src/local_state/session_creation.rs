//! Metadata-only journal for caller-key session creation.
//!
//! This journal is deliberately kept in the existing `kv` table.  It stores a
//! reviewed identity and public receipt identifiers, never argv, credentials,
//! prompts, environment, or an API response body.

use super::{initialization, LocalState};
use crate::config::AppPaths;
use anyhow::{bail, Result};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const PREFIX: &str = "session_create_request:";
const LIMIT: usize = 256;
const MAX_RECORD_BYTES: usize = 32 * 1024;

/// The durable, safe subset of a caller-key session creation request.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionCreateRecord {
    pub home: PathBuf,
    pub server_url: String,
    /// Authenticated user UUID.  It partitions records across account changes.
    pub user_id: String,
    pub request_id: String,
    pub tool_type: String,
    pub tool_account_id: String,
    pub workspace_id: String,
    pub project_key: String,
    pub argv_digest: String,
    pub replacement_session_id: Option<String>,
    pub sync_target_digest: Option<String>,
    pub prepare_task_id: Option<String>,
    pub prepare_task_record_id: Option<String>,
    pub phase: String,
    pub session_id: Option<String>,
    pub create_task_id: Option<String>,
    pub task_record_id: Option<String>,
    pub last_observation: Option<String>,
}

impl LocalState {
    /// Read caller-key records without creating the local database.
    pub fn session_create_records(paths: &AppPaths) -> Result<Vec<SessionCreateRecord>> {
        match std::fs::symlink_metadata(paths.state_db_path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
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
             WHERE key GLOB 'session_create_request:*' ORDER BY key LIMIT ?",
        )?;
        let rows = statement.query_map([MAX_RECORD_BYTES as i64 + 1, LIMIT as i64 + 1], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (key, raw) = row?;
            if raw.len() > MAX_RECORD_BYTES || records.len() >= LIMIT {
                bail!("session creation journal limit exceeded");
            }
            let record: SessionCreateRecord = serde_json::from_str(&raw)?;
            validate_record(&key, &record, paths)?;
            records.push(record);
        }
        Ok(records)
    }

    /// Atomically reserve a new caller key.  Existing keys are never replaced.
    pub fn reserve_session_create(&self, record: &SessionCreateRecord) -> Result<bool> {
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
            "SELECT COUNT(*) FROM kv WHERE key GLOB 'session_create_request:*'",
            [],
            |row| row.get(0),
        )?;
        if count >= LIMIT {
            bail!("session creation journal limit exceeded");
        }
        let raw = serde_json::to_string(record)?;
        if raw.len() > MAX_RECORD_BYTES {
            bail!("session creation journal record too large");
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO kv(key,value) VALUES(?1,?2)",
            params![key, raw],
        )? == 1;
        transaction.commit()?;
        Ok(inserted)
    }

    /// Compare-and-swap a journal record, retaining immutable request identity.
    pub fn update_session_create(
        &self,
        original: &SessionCreateRecord,
        next: &SessionCreateRecord,
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
        let current: Option<SessionCreateRecord> =
            raw.map(|value| serde_json::from_str(&value)).transpose()?;
        if current.as_ref() != Some(original) {
            return Ok(false);
        }
        let encoded = serde_json::to_string(next)?;
        if encoded.len() > MAX_RECORD_BYTES {
            bail!("session creation journal record too large");
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

fn validate_record(key: &str, record: &SessionCreateRecord, paths: &AppPaths) -> Result<()> {
    if key != format!("{PREFIX}{}", record.request_id) || record.home != paths.home() {
        bail!("invalid session creation journal record");
    }
    validate_record_value(record, None)
}

fn validate_record_value(
    record: &SessionCreateRecord,
    original: Option<&SessionCreateRecord>,
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
        "prepared"
            | "admission_pending"
            | "accepted"
            | "running"
            | "failed"
            | "unknown"
            | "deleted"
            | "rejected"
    );
    if !valid_uuid(&record.request_id)
        || !valid_user_scope(&record.user_id)
        || !valid_uuid(&record.tool_account_id)
        || !valid_uuid(&record.workspace_id)
        || !record
            .replacement_session_id
            .as_deref()
            .is_none_or(valid_uuid)
        || !record.session_id.as_deref().is_none_or(valid_uuid)
        || !valid_text(&record.server_url, 8192)
        || !(record.server_url.starts_with("https://") || record.server_url.starts_with("http://"))
        || !valid_text(&record.tool_type, 64)
        || !valid_text(&record.project_key, 4096)
        || !valid_digest(&record.argv_digest)
        || !record
            .sync_target_digest
            .as_deref()
            .is_none_or(valid_digest)
        || !record.prepare_task_id.as_deref().is_none_or(valid_text_id)
        || !record
            .prepare_task_record_id
            .as_deref()
            .is_none_or(valid_uuid)
        || !record.create_task_id.as_deref().is_none_or(valid_text_id)
        || !record.task_record_id.as_deref().is_none_or(valid_uuid)
        || !valid_phase
        || record
            .last_observation
            .as_deref()
            .is_some_and(|value| !valid_text(value, 4096))
    {
        bail!("invalid session creation journal record");
    }
    if original.is_some_and(|old| {
        old.home != record.home
            || old.server_url != record.server_url
            || old.user_id != record.user_id
            || old.request_id != record.request_id
            || old.tool_type != record.tool_type
            || old.tool_account_id != record.tool_account_id
            || old.workspace_id != record.workspace_id
            || old.project_key != record.project_key
            || old.argv_digest != record.argv_digest
            || old.replacement_session_id != record.replacement_session_id
            || old.sync_target_digest != record.sync_target_digest
            || old.prepare_task_id != record.prepare_task_id
            || old.prepare_task_record_id != record.prepare_task_record_id
    }) {
        bail!("session creation journal identity changed");
    }
    Ok(())
}

fn valid_text_id(value: &str) -> bool {
    value.len() <= 256
        && !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
}

fn valid_user_scope(value: &str) -> bool {
    use crate::account_import::valid_uuid;
    valid_uuid(value)
        || (value.len() == 71
            && value.starts_with("sha256:")
            && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit()))
}
