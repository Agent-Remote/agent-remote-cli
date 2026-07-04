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
                 ON devices (server_url, status);",
        )?;
        self.connection.pragma_update(None, "user_version", 1)?;
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

    use super::{LocalDevice, LocalState};

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
}
