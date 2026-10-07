mod skill_commands;
pub use skill_commands::{skill_command_state, SkillCommandRecord};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEgoBrowserBinding {
    pub id: String,
    pub server_url: String,
    pub ego_browser_device_id: String,
    pub tool_session_id: String,
    pub node_id: String,
    pub status: String,
    pub generation: u64,
    pub relay_binding_kind: String,
    pub lease_until: Option<String>,
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
                 ON sync_sessions (workspace_id);
             CREATE TABLE IF NOT EXISTS ego_browser_bindings (
                 id TEXT PRIMARY KEY,
                 server_url TEXT NOT NULL,
                 ego_browser_device_id TEXT NOT NULL,
                 tool_session_id TEXT NOT NULL,
                 node_id TEXT NOT NULL,
                 status TEXT NOT NULL,
                 generation INTEGER NOT NULL,
                 relay_binding_kind TEXT NOT NULL,
                 lease_until TEXT,
                 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE INDEX IF NOT EXISTS ego_browser_bindings_server_status_idx
                 ON ego_browser_bindings (server_url, status);",
        )?;
        self.init_skill_commands()?;
        self.connection.pragma_update(None, "user_version", 4)?;
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

    #[allow(dead_code)]
    pub fn get_workspace_by_id(&self, workspace_id: &str) -> Result<Option<LocalWorkspace>> {
        let workspace = self
            .connection
            .query_row(
                "SELECT id, server_url, project_key, local_path, display_name, remote_path
                 FROM workspaces WHERE id = ?1",
                params![workspace_id],
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

    pub fn delete_workspace_mapping(&self, workspace_id: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM sync_sessions WHERE workspace_id = ?1",
            params![workspace_id],
        )?;
        self.connection.execute(
            "DELETE FROM workspaces WHERE id = ?1",
            params![workspace_id],
        )?;
        Ok(())
    }

    pub fn delete_sync_session(&self, sync_session_id: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM sync_sessions WHERE id = ?1",
            params![sync_session_id],
        )?;
        Ok(())
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

    pub fn upsert_ego_browser_binding(&self, binding: &LocalEgoBrowserBinding) -> Result<()> {
        self.connection.execute(
            "INSERT INTO ego_browser_bindings (
                id, server_url, ego_browser_device_id, tool_session_id, node_id,
                status, generation, relay_binding_kind, lease_until, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, CURRENT_TIMESTAMP)
             ON CONFLICT(id) DO UPDATE SET
                server_url = excluded.server_url,
                ego_browser_device_id = excluded.ego_browser_device_id,
                tool_session_id = excluded.tool_session_id,
                node_id = excluded.node_id,
                status = excluded.status,
                generation = excluded.generation,
                relay_binding_kind = excluded.relay_binding_kind,
                lease_until = excluded.lease_until,
                updated_at = CURRENT_TIMESTAMP",
            params![
                binding.id,
                binding.server_url,
                binding.ego_browser_device_id,
                binding.tool_session_id,
                binding.node_id,
                binding.status,
                binding.generation,
                binding.relay_binding_kind,
                binding.lease_until,
            ],
        )?;
        Ok(())
    }

    /// Returns stale diagnostic bindings that must never authorize offline actions.
    pub fn list_ego_browser_bindings(
        &self,
        server_url: &str,
    ) -> Result<Vec<LocalEgoBrowserBinding>> {
        let mut statement = self.connection.prepare(
            "SELECT id, server_url, ego_browser_device_id, tool_session_id,
                    node_id, status, generation, relay_binding_kind, lease_until
             FROM ego_browser_bindings WHERE server_url = ?1 ORDER BY updated_at DESC",
        )?;
        let rows = statement.query_map(params![server_url], |row| {
            Ok(LocalEgoBrowserBinding {
                id: row.get(0)?,
                server_url: row.get(1)?,
                ego_browser_device_id: row.get(2)?,
                tool_session_id: row.get(3)?,
                node_id: row.get(4)?,
                status: row.get(5)?,
                generation: row.get(6)?,
                relay_binding_kind: row.get(7)?,
                lease_until: row.get(8)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Remove one ego-browser binding metadata row for a server.
    pub fn delete_ego_browser_binding(&self, server_url: &str, binding_id: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM ego_browser_bindings WHERE server_url = ?1 AND id = ?2",
            params![server_url, binding_id],
        )?;
        Ok(())
    }

    /// Remove all locally cached bindings for one server-scoped browser device.
    pub fn delete_ego_browser_bindings_for_device(
        &self,
        server_url: &str,
        device_id: &str,
    ) -> Result<()> {
        self.connection.execute(
            "DELETE FROM ego_browser_bindings
             WHERE server_url = ?1 AND ego_browser_device_id = ?2",
            params![server_url, device_id],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn get_ego_browser_binding(
        &self,
        binding_id: &str,
    ) -> Result<Option<LocalEgoBrowserBinding>> {
        let binding = self
            .connection
            .query_row(
                "SELECT id, server_url, ego_browser_device_id, tool_session_id,
                        node_id, status, generation, relay_binding_kind, lease_until
                 FROM ego_browser_bindings WHERE id = ?1",
                params![binding_id],
                |row| {
                    Ok(LocalEgoBrowserBinding {
                        id: row.get(0)?,
                        server_url: row.get(1)?,
                        ego_browser_device_id: row.get(2)?,
                        tool_session_id: row.get(3)?,
                        node_id: row.get(4)?,
                        status: row.get(5)?,
                        generation: row.get(6)?,
                        relay_binding_kind: row.get(7)?,
                        lease_until: row.get(8)?,
                    })
                },
            )
            .optional()?;
        Ok(binding)
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
#[path = "../tests/unit/src/local_state.rs"]
mod tests;
