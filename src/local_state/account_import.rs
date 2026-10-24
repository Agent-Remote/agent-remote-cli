//! Bounded metadata-only original import intent journal. Never stores source paths or bytes.
use super::{initialization, LocalState};
use crate::{account_defaults::Context, config::AppPaths};
use anyhow::{bail, Result};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "account_import_request:";
const LIMIT: usize = 256;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImportRecord {
    pub context: Context,
    pub account_id: String,
    pub request_id: String,
    pub digest: String,
    pub intent_fingerprint: String,
    pub task_id: Option<String>,
    pub phase: String,
}
impl LocalState {
    pub fn account_import_records(paths: &AppPaths) -> Result<Vec<ImportRecord>> {
        match std::fs::symlink_metadata(paths.state_db_path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            value => {
                value?;
            }
        }
        let home = initialization::checked_home(paths, false)?;
        let database = paths.state_db_path();
        let name = database
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("metadata filename missing"))?;
        let path = std::fs::canonicalize(home)?.join(name);
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            initialization::validate_file(std::path::Path::new(&name))?;
        }
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
        let mut statement=connection.prepare("SELECT key,substr(value,1,16385) FROM kv WHERE key GLOB 'account_import_request:*' ORDER BY key LIMIT 257")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (key, raw) = row?;
            if raw.len() > 16384 || result.len() >= LIMIT {
                bail!("account import journal limit exceeded");
            }
            let record: ImportRecord = serde_json::from_str(&raw)?;
            validate_record(&key, &record, paths)?;
            result.push(record);
        }
        Ok(result)
    }
    pub fn reserve_account_import(&self, record: &ImportRecord) -> Result<bool> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let existing: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM kv WHERE key=?1)",
            [format!("{PREFIX}{}", record.request_id)],
            |row| row.get(0),
        )?;
        if existing {
            return Ok(false);
        }
        let count: usize = transaction.query_row(
            "SELECT COUNT(*) FROM kv WHERE key GLOB 'account_import_request:*'",
            [],
            |row| row.get(0),
        )?;
        if count >= LIMIT {
            bail!("account import journal limit exceeded");
        }
        {
            let mut statement=transaction.prepare("SELECT key,substr(value,1,16385) FROM kv WHERE key GLOB 'account_import_request:*' LIMIT 257")?;
            for row in statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })? {
                let (key, raw) = row?;
                if raw.len() > 16384 {
                    bail!("invalid import journal record");
                }
                let prior: ImportRecord = serde_json::from_str(&raw)?;
                let paths = AppPaths::new(Some(record.context.home.clone()))?;
                validate_record(&key, &prior, &paths)?;
                if prior.context == record.context
                    && prior.account_id == record.account_id
                    && matches!(prior.phase.as_str(), "pending" | "accepted")
                {
                    return Ok(false);
                }
            }
        }
        let raw = serde_json::to_string(record)?;
        if raw.len() > 16384 {
            bail!("account import journal record too large");
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO kv(key,value) VALUES(?1,?2)",
            params![format!("{PREFIX}{}", record.request_id), raw],
        )? == 1;
        transaction.commit()?;
        Ok(inserted)
    }
    pub fn forget_account_import(&self, original: &ImportRecord) -> Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM kv WHERE key=?1 AND value=?2",
            params![
                format!("{PREFIX}{}", original.request_id),
                serde_json::to_string(original)?
            ],
        )? == 1)
    }
    pub fn update_account_import(
        &self,
        original: &ImportRecord,
        next: &ImportRecord,
    ) -> Result<bool> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let key = format!("{PREFIX}{}", original.request_id);
        let raw: Option<String> = transaction
            .query_row(
                "SELECT substr(value,1,16385) FROM kv WHERE key=?1",
                [&key],
                |row| row.get(0),
            )
            .optional()?;
        let current: Option<ImportRecord> = raw.map(|v| serde_json::from_str(&v)).transpose()?;
        if current.as_ref() != Some(original) {
            return Ok(false);
        }
        transaction.execute(
            "UPDATE kv SET value=?2,updated_at=CURRENT_TIMESTAMP WHERE key=?1",
            params![key, serde_json::to_string(next)?],
        )?;
        transaction.commit()?;
        Ok(true)
    }
}

fn validate_record(key: &str, record: &ImportRecord, paths: &AppPaths) -> Result<()> {
    use crate::account_import::{valid_digest, valid_uuid};
    let valid_task = record.task_id.as_ref().is_some_and(|v| {
        v.strip_prefix(&format!(
            "import_tool_account_config:{}:",
            record.account_id
        ))
        .is_some_and(valid_uuid)
    });
    let phase_valid = match record.phase.as_str() {
        "pending" | "rejected" => record.task_id.is_none(),
        "accepted" | "succeeded" | "failed" | "cancelled" | "expired" => valid_task,
        _ => false,
    };
    if key != format!("{PREFIX}{}", record.request_id)
        || record.context.home != paths.home()
        || !valid_uuid(&record.request_id)
        || !valid_uuid(&record.account_id)
        || !valid_digest(&record.digest)
        || !valid_digest(&record.intent_fingerprint)
        || !phase_valid
        || record.context.server_url.as_ref().is_none_or(|v| {
            v.len() > 8192
                || v.chars().any(char::is_control)
                || !(v.starts_with("https://") || v.starts_with("http://"))
        })
        || record.context.active_device_id.as_ref().is_none_or(|v| {
            v.is_empty()
                || v.len() > 128
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        })
    {
        bail!("invalid import journal record");
    }
    Ok(())
}
