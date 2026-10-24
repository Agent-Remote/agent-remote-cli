//! Public caller-key and immutable recovery receipt metadata, never backend execution state.
use super::{initialization, LocalState};
use crate::{config::AppPaths, runtime_recovery::Record};
use anyhow::{bail, Result};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

const PREFIX: &str = "runtime_recovery_request:";
const LIMIT: usize = 256;
impl LocalState {
    pub fn runtime_recovery_records(paths: &AppPaths) -> Result<Vec<Record>> {
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
        let mut statement=connection.prepare("SELECT key,substr(value,1,16385) FROM kv WHERE key GLOB 'runtime_recovery_request:*' ORDER BY key LIMIT 257")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (key, raw) = row?;
            if raw.len() > 16384 || result.len() >= LIMIT {
                bail!("runtime recovery registry limit exceeded");
            }
            let record: Record = serde_json::from_str(&raw)?;
            validate_record(&key, &record, paths)?;
            result.push(record);
        }
        Ok(result)
    }
    pub fn reserve_runtime_recovery(&self, record: &Record) -> Result<bool> {
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
            "SELECT COUNT(*) FROM kv WHERE key GLOB 'runtime_recovery_request:*'",
            [],
            |row| row.get(0),
        )?;
        if count >= LIMIT {
            bail!("runtime recovery registry limit exceeded");
        }
        {
            let mut statement=transaction.prepare("SELECT key,substr(value,1,16385) FROM kv WHERE key GLOB 'runtime_recovery_request:*' LIMIT 257")?;
            for row in statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })? {
                let (key, raw) = row?;
                if raw.len() > 16384 {
                    bail!("invalid recovery registry record");
                }
                let prior: Record = serde_json::from_str(&raw)?;
                let paths = AppPaths::new(Some(record.context.home.clone()))?;
                validate_record(&key, &prior, &paths)?;
                if prior.context == record.context
                    && prior.account_id == record.account_id
                    && matches!(prior.phase.as_str(), "unknown" | "accepted")
                {
                    return Ok(false);
                }
            }
        }
        let raw = serde_json::to_string(record)?;
        if raw.len() > 16384 {
            bail!("runtime recovery registry record too large");
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO kv(key,value) VALUES(?1,?2)",
            params![format!("{PREFIX}{}", record.request_id), raw],
        )? == 1;
        transaction.commit()?;
        Ok(inserted)
    }
    pub fn forget_runtime_recovery(&self, original: &Record) -> Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM kv WHERE key=?1 AND value=?2",
            params![
                format!("{PREFIX}{}", original.request_id),
                serde_json::to_string(original)?
            ],
        )? == 1)
    }
    pub fn update_runtime_recovery(&self, original: &Record, next: &Record) -> Result<bool> {
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
        let current: Option<Record> = raw.map(|v| serde_json::from_str(&v)).transpose()?;
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

fn validate_record(key: &str, record: &Record, paths: &AppPaths) -> Result<()> {
    use crate::api::runtime_recovery::canonical_uuid;
    use crate::runtime_recovery::{digest, valid_binding, valid_context};
    let phase = match record.phase.as_str() {
        "unknown" => record.binding.is_none() && record.rejection_code.is_none(),
        "accepted" => record.binding.is_some() && record.rejection_code.is_none(),
        "rejected" => {
            record.binding.is_none()
                && matches!(
                    record.rejection_code.as_deref(),
                    Some("runtime_recovery_rejected" | "runtime_recovery_review_changed")
                )
        }
        _ => false,
    };
    if key != format!("{PREFIX}{}", record.request_id)
        || record.context.home != paths.home()
        || !valid_context(&record.context)
        || !canonical_uuid(&record.request_id)
        || !record.original.valid(&record.account_id)
        || !phase
        || digest(
            &record.context,
            &record.account_id,
            &record.original,
            record.action,
        )? != record.digest
        || record.binding.as_ref().is_some_and(|b| {
            !valid_binding(
                b,
                &record.account_id,
                &record.request_id,
                Some((&record.original, record.action)),
            )
        })
    {
        bail!("invalid runtime recovery registry record");
    }
    Ok(())
}
