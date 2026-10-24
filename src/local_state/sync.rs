//! Read-only sync snapshots and atomic replacement of reviewed mappings.
use super::{initialization, LocalState, LocalSyncSession, LocalWorkspace};
use crate::config::AppPaths;
use anyhow::Result;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncSnapshot {
    #[serde(deserialize_with = "super::required_sync_option")]
    pub workspace: Option<LocalWorkspace>,
    #[serde(deserialize_with = "super::required_sync_option")]
    pub sync: Option<LocalSyncSession>,
}
impl LocalState {
    pub fn sync_snapshot(
        paths: &AppPaths,
        server: &str,
        project_key: &str,
    ) -> Result<SyncSnapshot> {
        if !paths.state_db_path().try_exists()? {
            return Ok(SyncSnapshot {
                workspace: None,
                sync: None,
            });
        }
        let home = initialization::checked_home(paths, false)?;
        let database = paths.state_db_path();
        let filename = database
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("metadata filename missing"))?;
        let database = std::fs::canonicalize(home)?.join(filename);
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let mut name = database.as_os_str().to_os_string();
            name.push(suffix);
            initialization::validate_file(std::path::Path::new(&name))?;
        }
        let connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(3))?;
        let state = Self { connection };
        state.read_sync_snapshot(server, project_key)
    }
    fn read_sync_snapshot(&self, server: &str, project_key: &str) -> Result<SyncSnapshot> {
        let workspace = self.get_workspace_by_project_key(server, project_key)?;
        let sync = match &workspace {
            Some(value) => {
                let count: u64 = self.connection.query_row(
                    "SELECT COUNT(*) FROM sync_sessions WHERE workspace_id = ?1",
                    [&value.id],
                    |row| row.get(0),
                )?;
                anyhow::ensure!(count <= 1, "ambiguous local sync mapping");
                self.get_sync_session_for_workspace(&value.id)?
            }
            None => None,
        };
        Ok(SyncSnapshot { workspace, sync })
    }
    pub fn compare_sync_snapshot(
        &self,
        server: &str,
        project_key: &str,
        expected: &SyncSnapshot,
        workspace: Option<&LocalWorkspace>,
        sync: Option<&LocalSyncSession>,
    ) -> Result<bool> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if self.read_sync_snapshot(server, project_key)? != *expected {
            return Ok(false);
        }
        if let Some(workspace) = workspace {
            self.upsert_workspace(workspace)?;
        }
        if let Some(sync) = sync {
            self.upsert_sync_session(sync)?;
        }
        transaction.commit()?;
        Ok(true)
    }
    /// Remove only the reviewed mapping. No transaction spans remote or daemon work.
    pub fn remove_sync_snapshot(
        &self,
        server: &str,
        project_key: &str,
        expected: &SyncSnapshot,
        remove_workspace: bool,
    ) -> Result<bool> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if self.read_sync_snapshot(server, project_key)? != *expected {
            return Ok(false);
        }
        let Some(workspace) = &expected.workspace else {
            return Ok(false);
        };
        let count: u64 = self.connection.query_row(
            "SELECT COUNT(*) FROM sync_sessions WHERE workspace_id = ?1",
            [&workspace.id],
            |row| row.get(0),
        )?;
        // Historical databases permit multiple rows for a workspace; never broaden
        // one reviewed session into deletion of another row or its owning mapping.
        if count != u64::from(expected.sync.is_some()) {
            return Ok(false);
        }
        if let Some(sync) = &expected.sync {
            let deleted = self.connection.execute(
                "DELETE FROM sync_sessions WHERE id = ?1 AND workspace_id = ?2 AND server_url = ?3",
                rusqlite::params![sync.id, workspace.id, server],
            )?;
            if deleted != 1 {
                return Ok(false);
            }
        }
        if remove_workspace {
            let deleted = self.connection.execute(
                "DELETE FROM workspaces WHERE id = ?1 AND server_url = ?2 AND project_key = ?3",
                rusqlite::params![workspace.id, server, project_key],
            )?;
            if deleted != 1 {
                return Ok(false);
            }
        }
        transaction.commit()?;
        Ok(true)
    }
}
