//! Durable metadata for exact, user-bound skill mutation recovery.

use anyhow::{bail, Result};
use rusqlite::{params, OptionalExtension};

use super::LocalState;

/// Run SQLite journal work off the async runtime, without holding a connection across HTTP awaits.
pub async fn skill_command_state<T, F>(paths: crate::config::AppPaths, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&LocalState) -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let state = LocalState::open(&paths)?;
        state.init_schema()?;
        operation(&state)
    })
    .await?
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillCommandRecord {
    pub server_url: String,
    pub user_id: String,
    pub intent_digest: String,
    pub idempotency_key: String,
    pub request_json: String,
}

impl LocalState {
    pub(super) fn init_skill_commands(&self) -> Result<()> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS skill_commands (
                server_url TEXT NOT NULL,
                user_id TEXT NOT NULL,
                intent_digest TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending', 'received')),
                operation_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (server_url, user_id, idempotency_key)
             );
             CREATE UNIQUE INDEX IF NOT EXISTS skill_commands_pending_intent
                ON skill_commands(server_url, user_id, intent_digest) WHERE state = 'pending';",
        )?;
        Ok(())
    }

    pub fn pending_skill_command(
        &self,
        server: &str,
        user: &str,
        intent: &str,
    ) -> Result<Option<SkillCommandRecord>> {
        self.connection.query_row(
            "SELECT server_url, user_id, intent_digest, idempotency_key, request_json
             FROM skill_commands WHERE server_url = ?1 AND user_id = ?2 AND intent_digest = ?3 AND state = 'pending'",
            params![server, user, intent], |row| Ok(SkillCommandRecord {
                server_url: row.get(0)?, user_id: row.get(1)?, intent_digest: row.get(2)?,
                idempotency_key: row.get(3)?, request_json: row.get(4)?,
            }),
        ).optional().map_err(Into::into)
    }

    /// Enumerate bounded pending metadata so batch retries cannot drop an uncertain item.
    pub fn pending_skill_commands(
        &self,
        server: &str,
        user: &str,
    ) -> Result<Vec<SkillCommandRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT intent_digest, idempotency_key, request_json FROM skill_commands WHERE server_url = ?1 AND user_id = ?2 AND state = 'pending' ORDER BY rowid LIMIT 1001",
        )?;
        let mut rows = statement.query(params![server, user])?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        while let Some(row) = rows.next()? {
            let request_json: String = row.get(2)?;
            bytes = bytes.saturating_add(request_json.len());
            if records.len() >= 1000 || bytes > 16 * 1024 * 1024 {
                bail!("pending skill journal exceeds batch recovery bounds; recover individual commands first");
            }
            records.push(SkillCommandRecord {
                server_url: server.into(),
                user_id: user.into(),
                intent_digest: row.get(0)?,
                idempotency_key: row.get(1)?,
                request_json,
            });
        }
        Ok(records)
    }

    /// Keep exact request metadata available for choosing the original receipt protocol.
    pub fn last_skill_command_record(
        &self,
        server: &str,
        user: &str,
    ) -> Result<Option<(SkillCommandRecord, Option<String>)>> {
        self.connection.query_row(
            "SELECT intent_digest, idempotency_key, request_json, operation_id FROM skill_commands WHERE server_url = ?1 AND user_id = ?2 ORDER BY rowid DESC LIMIT 1",
            params![server, user], |row| Ok((SkillCommandRecord {
                server_url: server.to_owned(), user_id: user.to_owned(), intent_digest: row.get(0)?,
                idempotency_key: row.get(1)?, request_json: row.get(2)?,
            }, row.get(3)?)),
        ).optional().map_err(Into::into)
    }

    /// Preserve an existing uncertain request when two processes confirm the same intent.
    pub fn begin_skill_command(&self, record: &SkillCommandRecord) -> Result<SkillCommandRecord> {
        if record.request_json.len() > 4 * 1024 * 1024
            || record.idempotency_key.is_empty()
            || record.intent_digest.len() != 64
        {
            bail!("invalid skill command recovery record");
        }
        self.connection.execute(
            "INSERT INTO skill_commands(server_url, user_id, intent_digest, idempotency_key, request_json, state)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending') ON CONFLICT DO NOTHING",
            params![record.server_url, record.user_id, record.intent_digest, record.idempotency_key, record.request_json],
        )?;
        self.pending_skill_command(&record.server_url, &record.user_id, &record.intent_digest)?
            .ok_or_else(|| anyhow::anyhow!("skill command identity was already received"))
    }

    /// Retain the original operation identity even when its deployment is pending or failed.
    pub fn receive_skill_command(
        &self,
        record: &SkillCommandRecord,
        operation: Option<&str>,
    ) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE skill_commands SET state = 'received', operation_id = ?6, updated_at = CURRENT_TIMESTAMP
             WHERE server_url = ?1 AND user_id = ?2 AND intent_digest = ?3 AND idempotency_key = ?4
             AND request_json = ?5 AND (state = 'pending' OR (state = 'received' AND operation_id IS ?6))",
            params![record.server_url, record.user_id, record.intent_digest, record.idempotency_key, record.request_json, operation],
        )?;
        if changed != 1 {
            bail!("skill command receipt differs from retained input");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/local_state/skill_commands.rs"]
mod tests;
