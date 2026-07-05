use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

use crate::config::AppPaths;

pub struct LocalState {
    connection: Connection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalDevice {
    pub id: String,
    pub server_url: String,
    pub name: String,
    pub platform: String,
    pub status: String,
    pub ssh_key_id: Option<String>,
    pub wireguard_peer_id: Option<String>,
    pub created_at: Option<String>,
    pub last_seen_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWorkspace {
    pub id: String,
    pub server_url: String,
    pub project_key: String,
    pub local_path: String,
    pub display_name: String,
    pub remote_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalSyncSession {
    pub id: String,
    pub server_url: String,
    pub workspace_id: String,
    pub node_id: Option<String>,
    pub status: String,
    pub conflict_status: String,
    pub mutagen_session_id: Option<String>,
    pub remote_endpoint: Option<String>,
}

impl LocalState {
    pub fn open(paths: &AppPaths) -> Result<Self> {
        paths.ensure_base_dirs()?;
        let connection = Connection::open(paths.state_db_path())?;
        Ok(Self { connection })
    }

    pub fn init_schema(&self) -> Result<()> {
        self.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS kv (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL,
                 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE TABLE IF NOT EXISTS devices (
                 id TEXT PRIMARY KEY,
                 server_url TEXT NOT NULL,
                 name TEXT NOT NULL,
                 platform TEXT NOT NULL,
                 status TEXT NOT NULL,
                 ssh_key_id TEXT,
                 wireguard_peer_id TEXT,
                 created_at TEXT,
                 last_seen_at TEXT,
                 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE INDEX IF NOT EXISTS devices_server_status_idx
                 ON devices (server_url, status);
             CREATE TABLE IF NOT EXISTS workspaces (
                 id TEXT PRIMARY KEY,
                 server_url TEXT NOT NULL,
                 project_key TEXT NOT NULL,
                 local_path TEXT NOT NULL,
                 display_name TEXT NOT NULL,
                 remote_path TEXT,
                 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE UNIQUE INDEX IF NOT EXISTS workspaces_server_project_idx
                 ON workspaces (server_url, project_key);
             CREATE TABLE IF NOT EXISTS sync_sessions (
                 id TEXT PRIMARY KEY,
                 server_url TEXT NOT NULL,
                 workspace_id TEXT NOT NULL,
                 node_id TEXT,
                 status TEXT NOT NULL,
                 conflict_status TEXT NOT NULL,
                 mutagen_session_id TEXT,
                 remote_endpoint TEXT,
                 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE INDEX IF NOT EXISTS sync_sessions_workspace_idx
                 ON sync_sessions (workspace_id);",
        )?;
        self.connection.pragma_update(None, "user_version", 2)?;
        Ok(())
    }

    pub fn set_kv(&self, key: &str, value: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO kv (key, value, updated_at)
             VALUES (?1, ?2, CURRENT_TIMESTAMP)
             ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_kv(&self, key: &str) -> Result<Option<String>> {
        let value = self
            .connection
            .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |row| {
                row.get(0)
            })
            .optional()?;
        Ok(value)
    }

    pub fn delete_kv(&self, key: &str) -> Result<()> {
        self.connection
            .execute("DELETE FROM kv WHERE key = ?1", params![key])?;
        Ok(())
    }

    pub fn upsert_device(&self, device: &LocalDevice) -> Result<()> {
        self.connection.execute(
            "INSERT INTO devices (
                id, server_url, name, platform, status, ssh_key_id,
                wireguard_peer_id, created_at, last_seen_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, CURRENT_TIMESTAMP)
             ON CONFLICT(id) DO UPDATE SET
                server_url = excluded.server_url,
                name = excluded.name,
                platform = excluded.platform,
                status = excluded.status,
                ssh_key_id = excluded.ssh_key_id,
                wireguard_peer_id = excluded.wireguard_peer_id,
                created_at = excluded.created_at,
                last_seen_at = excluded.last_seen_at,
                updated_at = CURRENT_TIMESTAMP",
            params![
                device.id,
                device.server_url,
                device.name,
                device.platform,
                device.status,
                device.ssh_key_id,
                device.wireguard_peer_id,
                device.created_at,
                device.last_seen_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_device(&self, device_id: &str) -> Result<Option<LocalDevice>> {
        let device = self
            .connection
            .query_row(
                "SELECT id, server_url, name, platform, status, ssh_key_id,
                        wireguard_peer_id, created_at, last_seen_at
                 FROM devices WHERE id = ?1",
                params![device_id],
                |row| {
                    Ok(LocalDevice {
                        id: row.get(0)?,
                        server_url: row.get(1)?,
                        name: row.get(2)?,
                        platform: row.get(3)?,
                        status: row.get(4)?,
                        ssh_key_id: row.get(5)?,
                        wireguard_peer_id: row.get(6)?,
                        created_at: row.get(7)?,
                        last_seen_at: row.get(8)?,
                    })
                },
            )
            .optional()?;
        Ok(device)
    }

    pub fn upsert_workspace(&self, workspace: &LocalWorkspace) -> Result<()> {
        self.connection.execute(
            "INSERT INTO workspaces (
                id, server_url, project_key, local_path, display_name, remote_path, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)
             ON CONFLICT(id) DO UPDATE SET
                server_url = excluded.server_url,
                project_key = excluded.project_key,
                local_path = excluded.local_path,
                display_name = excluded.display_name,
                remote_path = excluded.remote_path,
                updated_at = CURRENT_TIMESTAMP",
            params![
                workspace.id,
                workspace.server_url,
                workspace.project_key,
                workspace.local_path,
                workspace.display_name,
                workspace.remote_path,
            ],
        )?;
        Ok(())
    }

    pub fn get_workspace_by_project_key(
        &self,
        server_url: &str,
        project_key: &str,
    ) -> Result<Option<LocalWorkspace>> {
        let workspace = self
            .connection
            .query_row(
                "SELECT id, server_url, project_key, local_path, display_name, remote_path
                 FROM workspaces WHERE server_url = ?1 AND project_key = ?2",
                params![server_url, project_key],
                |row| {
                    Ok(LocalWorkspace {
                        id: row.get(0)?,
                        server_url: row.get(1)?,
                        project_key: row.get(2)?,
                        local_path: row.get(3)?,
                        display_name: row.get(4)?,
                        remote_path: row.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(workspace)
    }

    pub fn upsert_sync_session(&self, sync_session: &LocalSyncSession) -> Result<()> {
        self.connection.execute(
            "INSERT INTO sync_sessions (
                id, server_url, workspace_id, node_id, status, conflict_status,
                mutagen_session_id, remote_endpoint, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP)
             ON CONFLICT(id) DO UPDATE SET
                server_url = excluded.server_url,
                workspace_id = excluded.workspace_id,
                node_id = excluded.node_id,
                status = excluded.status,
                conflict_status = excluded.conflict_status,
                mutagen_session_id = excluded.mutagen_session_id,
                remote_endpoint = excluded.remote_endpoint,
                updated_at = CURRENT_TIMESTAMP",
            params![
                sync_session.id,
                sync_session.server_url,
                sync_session.workspace_id,
                sync_session.node_id,
                sync_session.status,
                sync_session.conflict_status,
                sync_session.mutagen_session_id,
                sync_session.remote_endpoint,
            ],
        )?;
        Ok(())
    }

    pub fn get_sync_session_for_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<Option<LocalSyncSession>> {
        let sync_session = self
            .connection
            .query_row(
                "SELECT id, server_url, workspace_id, node_id, status, conflict_status,
                        mutagen_session_id, remote_endpoint
                 FROM sync_sessions WHERE workspace_id = ?1
                 ORDER BY updated_at DESC LIMIT 1",
                params![workspace_id],
                |row| {
                    Ok(LocalSyncSession {
                        id: row.get(0)?,
                        server_url: row.get(1)?,
                        workspace_id: row.get(2)?,
                        node_id: row.get(3)?,
                        status: row.get(4)?,
                        conflict_status: row.get(5)?,
                        mutagen_session_id: row.get(6)?,
                        remote_endpoint: row.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(sync_session)
    }

    #[cfg(test)]
    pub fn table_columns(&self, table: &str) -> Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare(&format!("PRAGMA table_info({table})"))?;
        let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
        let mut columns = Vec::new();
        for row in rows {
            columns.push(row?);
        }
        Ok(columns)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::config::AppPaths;

    use super::{LocalDevice, LocalState, LocalSyncSession, LocalWorkspace};

    #[test]
    fn stores_device_metadata_without_token_columns() {
        let dir = tempdir().unwrap();
        let paths = AppPaths::from_home(dir.path().join("agent-remote"));
        let state = LocalState::open(&paths).unwrap();
        state.init_schema().unwrap();

        state
            .upsert_device(&LocalDevice {
                id: "dev_1".to_string(),
                server_url: "https://example.test".to_string(),
                name: "laptop".to_string(),
                platform: "macos".to_string(),
                status: "active".to_string(),
                ssh_key_id: Some("ssh_1".to_string()),
                wireguard_peer_id: None,
                created_at: Some("2026-07-04T00:00:00Z".to_string()),
                last_seen_at: None,
            })
            .unwrap();

        let device = state.get_device("dev_1").unwrap().unwrap();
        assert_eq!(device.name, "laptop");
        let columns = state.table_columns("devices").unwrap();
        assert!(!columns.iter().any(|column| column.contains("token")));
        assert!(!columns.iter().any(|column| column.contains("secret")));
    }

    #[test]
    fn stores_key_value_metadata() {
        let dir = tempdir().unwrap();
        let paths = AppPaths::from_home(dir.path().join("agent-remote"));
        let state = LocalState::open(&paths).unwrap();
        state.init_schema().unwrap();
        state.set_kv("last_login_mode", "device_token").unwrap();
        assert_eq!(
            state.get_kv("last_login_mode").unwrap().as_deref(),
            Some("device_token")
        );
    }

    #[test]
    fn stores_workspace_and_sync_metadata() {
        let dir = tempdir().unwrap();
        let paths = AppPaths::from_home(dir.path().join("agent-remote"));
        let state = LocalState::open(&paths).unwrap();
        state.init_schema().unwrap();

        state
            .upsert_workspace(&LocalWorkspace {
                id: "workspace_1".to_string(),
                server_url: "https://example.test".to_string(),
                project_key: "sha256:test".to_string(),
                local_path: "/tmp/project".to_string(),
                display_name: "project".to_string(),
                remote_path: Some("/var/lib/agent-remote/users/u/workspaces/w/files".to_string()),
            })
            .unwrap();
        state
            .upsert_sync_session(&LocalSyncSession {
                id: "sync_1".to_string(),
                server_url: "https://example.test".to_string(),
                workspace_id: "workspace_1".to_string(),
                node_id: Some("node_1".to_string()),
                status: "starting".to_string(),
                conflict_status: "none".to_string(),
                mutagen_session_id: Some("agent-remote-sync".to_string()),
                remote_endpoint: Some("ssh://agent@example.test/project".to_string()),
            })
            .unwrap();

        let workspace = state
            .get_workspace_by_project_key("https://example.test", "sha256:test")
            .unwrap()
            .unwrap();
        assert_eq!(workspace.id, "workspace_1");
        let sync = state
            .get_sync_session_for_workspace("workspace_1")
            .unwrap()
            .unwrap();
        assert_eq!(sync.id, "sync_1");
    }
}
