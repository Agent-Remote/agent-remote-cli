use anyhow::Result;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

use super::{initialization, LocalState};
use crate::config::AppPaths;

impl LocalState {
    pub(crate) fn read_default(paths: &AppPaths, key: &str) -> Result<Option<String>> {
        match std::fs::symlink_metadata(paths.state_db_path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            result => {
                result?;
            }
        }
        let home = initialization::checked_home(paths, false)?;
        let database = paths.state_db_path();
        let filename = database
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("metadata filename missing"))?;
        let path = std::fs::canonicalize(home)?.join(filename);
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
        Ok(connection
            .query_row(
                "SELECT substr(value, 1, 129) FROM kv WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(crate) fn compare_default(
        &self,
        key: &str,
        expected: Option<&str>,
        next: Option<&str>,
    ) -> Result<bool> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let current: Option<String> = transaction
            .query_row(
                "SELECT substr(value, 1, 129) FROM kv WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        if let Some(next) = next {
            transaction.execute("INSERT INTO kv (key,value,updated_at) VALUES (?1,?2,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP", params![key,next])?;
        } else {
            transaction.execute("DELETE FROM kv WHERE key = ?1", params![key])?;
        }
        transaction.commit()?;
        Ok(true)
    }
}
