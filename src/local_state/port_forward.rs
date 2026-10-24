//! Metadata-only journal for desktop-control port-forward creation.
//!
//! The caller key and reviewed public identity are recorded before the first
//! POST.  A transport failure therefore remains queryable/replayable with the
//! original key; the journal never stores connection tokens or credentials.

use super::{initialization, LocalState};
use crate::config::AppPaths;
use anyhow::{bail, Result};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const PREFIX: &str = "port_forward_create_request:";
const LIMIT: usize = 256;
const MAX_RECORD_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortForwardCreateRecord {
    pub home: PathBuf,
    pub server_url: String,
    pub user_id: String,
    pub request_id: String,
    pub session_id: String,
    pub node_id: String,
    pub runtime_backend: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub client_instance_id: String,
    pub ttl_seconds: Option<u64>,
    pub phase: String,
    pub forward_id: Option<String>,
    pub last_observation: Option<String>,
}

impl LocalState {
    pub fn port_forward_create_records(paths: &AppPaths) -> Result<Vec<PortForwardCreateRecord>> {
        if std::fs::symlink_metadata(paths.state_db_path()).is_err() {
            return Ok(Vec::new());
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
             WHERE key GLOB 'port_forward_create_request:*' ORDER BY key LIMIT ?",
        )?;
        let rows = statement.query_map([MAX_RECORD_BYTES as i64 + 1, LIMIT as i64 + 1], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (key, raw) = row?;
            if raw.len() > MAX_RECORD_BYTES || records.len() >= LIMIT {
                bail!("port-forward creation journal limit exceeded");
            }
            let record: PortForwardCreateRecord = serde_json::from_str(&raw)?;
            validate_record(&key, &record, paths)?;
            records.push(record);
        }
        Ok(records)
    }

    pub fn reserve_port_forward_create(&self, record: &PortForwardCreateRecord) -> Result<bool> {
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
            "SELECT COUNT(*) FROM kv WHERE key GLOB 'port_forward_create_request:*'",
            [],
            |row| row.get(0),
        )?;
        if count >= LIMIT {
            bail!("port-forward creation journal limit exceeded");
        }
        let raw = serde_json::to_string(record)?;
        if raw.len() > MAX_RECORD_BYTES {
            bail!("port-forward creation journal record too large");
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO kv(key,value) VALUES(?1,?2)",
            params![key, raw],
        )? == 1;
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn update_port_forward_create(
        &self,
        original: &PortForwardCreateRecord,
        next: &PortForwardCreateRecord,
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
        let current: Option<PortForwardCreateRecord> =
            raw.map(|v| serde_json::from_str(&v)).transpose()?;
        if current.as_ref() != Some(original) {
            return Ok(false);
        }
        let encoded = serde_json::to_string(next)?;
        if encoded.len() > MAX_RECORD_BYTES {
            bail!("port-forward creation journal record too large");
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

fn validate_record(key: &str, record: &PortForwardCreateRecord, paths: &AppPaths) -> Result<()> {
    if key != format!("{PREFIX}{}", record.request_id) || record.home != paths.home() {
        bail!("invalid port-forward creation journal record");
    }
    validate_record_value(record, None)
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn validate_record_value(
    record: &PortForwardCreateRecord,
    original: Option<&PortForwardCreateRecord>,
) -> Result<()> {
    let uuid = crate::api::runtime_recovery::canonical_uuid;
    let user_scope = |value: &str| {
        uuid(value)
            || (value.len() == 71
                && value.starts_with("sha256:")
                && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit()))
    };
    let valid_phase = matches!(
        record.phase.as_str(),
        "prepared" | "created" | "unknown" | "failed" | "settled"
    );
    if !record.home.is_absolute()
        || !valid_text(&record.server_url, 8192)
        || !(record.server_url.starts_with("http://") || record.server_url.starts_with("https://"))
        || !user_scope(&record.user_id)
        || !uuid(&record.request_id)
        || !uuid(&record.session_id)
        || !uuid(&record.node_id)
        || !valid_text(&record.runtime_backend, 64)
        || !(1..=65535).contains(&record.remote_port)
        || !(1..=65535).contains(&record.local_port)
        || !valid_text(&record.client_instance_id, 128)
        || record
            .ttl_seconds
            .is_some_and(|ttl| !(60..=604800).contains(&ttl))
        || !valid_phase
        || !record.forward_id.as_deref().is_none_or(uuid)
        || record
            .last_observation
            .as_deref()
            .is_some_and(|v| !valid_text(v, 4096))
    {
        bail!("invalid port-forward creation journal record");
    }
    if original.is_some_and(|old| {
        old.home != record.home
            || old.server_url != record.server_url
            || old.user_id != record.user_id
            || old.request_id != record.request_id
            || old.session_id != record.session_id
            || old.node_id != record.node_id
            || old.runtime_backend != record.runtime_backend
            || old.remote_port != record.remote_port
            || old.local_port != record.local_port
            || old.client_instance_id != record.client_instance_id
            || old.ttl_seconds != record.ttl_seconds
    }) {
        bail!("port-forward creation journal identity changed");
    }
    Ok(())
}
