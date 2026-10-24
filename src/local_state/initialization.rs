use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};

use super::LocalState;
use crate::config::AppPaths;

const SCHEMA_VERSION: i64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateInitialization {
    Ready,
    Applied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalStateInitializationError {
    InvalidPath,
    UnsupportedVersion(i64),
    Unavailable,
}

impl fmt::Display for LocalStateInitializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => f.write_str("local metadata path is not a regular file"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported local metadata schema version {version}")
            }
            Self::Unavailable => f.write_str("local metadata schema is invalid or unavailable"),
        }
    }
}
impl std::error::Error for LocalStateInitializationError {}

impl LocalState {
    /// Initialize metadata only. The caller owns preparation of the home directory.
    /// Existing records and unknown future schemas are never replaced.
    pub fn initialize_local(paths: &AppPaths) -> Result<StateInitialization> {
        Self::open_metadata(paths)?.initialize_schema()
    }

    pub(super) fn open_metadata(paths: &AppPaths) -> Result<Self> {
        let checked_home = checked_home(paths, false)?;
        // SQLite NOFOLLOW rejects links anywhere in its input path. Resolve only
        // the already-checked parent so system aliases such as macOS /var remain
        // usable, while the database filename itself is never canonicalized.
        let requested = paths.state_db_path();
        let filename = requested
            .file_name()
            .ok_or(LocalStateInitializationError::InvalidPath)?;
        let path = fs::canonicalize(&checked_home)?.join(filename);
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            validate_file(Path::new(&name))?;
        }
        // Reserve a missing database with private permissions, without truncating
        // one created by another initializer between validation and creation.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_file(&path)?;
            }
            Err(error) => return Err(error.into()),
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(3))?;
        Ok(Self { connection })
    }

    pub(super) fn initialize_schema(&self) -> Result<StateInitialization> {
        self.connection.pragma_update(None, "foreign_keys", true)?;
        // Acquire the writer reservation before checking the version: a concurrent
        // newer client must not be overwritten by a stale version read.
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let version: i64 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if !(0..=SCHEMA_VERSION).contains(&version) {
            return Err(LocalStateInitializationError::UnsupportedVersion(version).into());
        }
        let integrity: String =
            transaction.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(LocalStateInitializationError::Unavailable.into());
        }
        let before: i64 =
            transaction.pragma_query_value(None, "schema_version", |row| row.get(0))?;
        self.create_schema()?;
        validate_schema(&transaction)?;
        let after: i64 =
            transaction.pragma_query_value(None, "schema_version", |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        transaction.commit()?;
        Ok(if version == SCHEMA_VERSION && before == after {
            StateInitialization::Ready
        } else {
            StateInitialization::Applied
        })
    }
}

pub(super) fn checked_home(paths: &AppPaths, allow_missing: bool) -> Result<std::path::PathBuf> {
    // Remove trailing `/` and `/.` lexically: lstat would otherwise follow
    // the final directory link before SQLite's NOFOLLOW check can protect it.
    let home: std::path::PathBuf = paths.home().components().collect();
    match fs::symlink_metadata(&home) {
        Ok(metadata) if metadata.is_dir() && !is_link(&metadata) => Ok(home),
        Ok(_) => Err(LocalStateInitializationError::InvalidPath.into()),
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => Ok(home),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn validate_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !is_link(&metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(LocalStateInitializationError::InvalidPath.into());
                }
            }
            Ok(())
        }
        Ok(_) => Err(LocalStateInitializationError::InvalidPath.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

fn validate_schema(connection: &Connection) -> Result<()> {
    // IF NOT EXISTS alone also accepts unrelated tables with the same names.
    // Preparing these queries checks every column consumed by local metadata APIs.
    for sql in [
        "SELECT key,value,updated_at FROM kv LIMIT 0",
        "SELECT id,server_url,name,platform,status,ssh_key_id,wireguard_peer_id,created_at,last_seen_at,updated_at FROM devices LIMIT 0",
        "SELECT id,server_url,project_key,local_path,display_name,remote_path,updated_at FROM workspaces LIMIT 0",
        "SELECT id,server_url,workspace_id,node_id,status,conflict_status,mutagen_session_id,remote_endpoint,updated_at FROM sync_sessions LIMIT 0",
        "SELECT id,server_url,ego_browser_device_id,tool_session_id,node_id,status,generation,relay_binding_kind,lease_until,updated_at FROM ego_browser_bindings LIMIT 0",
        "SELECT server_url,user_id,intent_digest,idempotency_key,request_json,state,operation_id,created_at,updated_at FROM skill_commands LIMIT 0",
    ] {
        connection.prepare(sql)?;
    }
    for (table, expected) in [
        ("kv", vec!["key"]),
        ("devices", vec!["id"]),
        ("workspaces", vec!["id"]),
        ("sync_sessions", vec!["id"]),
        ("ego_browser_bindings", vec!["id"]),
        (
            "skill_commands",
            vec!["server_url", "user_id", "idempotency_key"],
        ),
    ] {
        let mut query = connection
            .prepare("SELECT name FROM pragma_table_info(?1) WHERE pk > 0 ORDER BY pk")?;
        let actual = query
            .query_map([table], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if actual != expected {
            return Err(LocalStateInitializationError::Unavailable.into());
        }
    }
    validate_indexes(connection)?;
    Ok(())
}

fn validate_indexes(connection: &Connection) -> Result<()> {
    use rusqlite::OptionalExtension;
    for (table, index, unique, partial, expected) in [
        (
            "devices",
            "devices_server_status_idx",
            false,
            false,
            vec!["server_url", "status"],
        ),
        (
            "workspaces",
            "workspaces_server_project_idx",
            true,
            false,
            vec!["server_url", "project_key"],
        ),
        (
            "sync_sessions",
            "sync_sessions_workspace_idx",
            false,
            false,
            vec!["workspace_id"],
        ),
        (
            "ego_browser_bindings",
            "ego_browser_bindings_server_status_idx",
            false,
            false,
            vec!["server_url", "status"],
        ),
        (
            "skill_commands",
            "skill_commands_pending_intent",
            true,
            true,
            vec!["server_url", "user_id", "intent_digest"],
        ),
    ] {
        let properties: Option<(bool, bool)> = connection
            .query_row(
                r#"SELECT "unique", partial FROM pragma_index_list(?1) WHERE name=?2"#,
                [table, index],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let mut query =
            connection.prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")?;
        let columns = query
            .query_map([index], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if properties != Some((unique, partial)) || columns != expected {
            return Err(LocalStateInitializationError::Unavailable.into());
        }
        if partial {
            let sql: String = connection.query_row(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
                [index],
                |row| row.get(0),
            )?;
            let normalized: String = sql
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_ascii_lowercase();
            if !normalized.ends_with("wherestate='pending'") {
                return Err(LocalStateInitializationError::Unavailable.into());
            }
        }
    }
    Ok(())
}
