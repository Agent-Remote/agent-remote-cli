// Tests for src/local_state.rs.

use tempfile::tempdir;

use crate::config::AppPaths;

use super::{LocalDevice, LocalEgoBrowserBinding, LocalState, LocalSyncSession, LocalWorkspace};

#[test]
fn local_initialization_is_idempotent_and_preserves_records() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    assert_eq!(
        LocalState::initialize_local(&paths).unwrap(),
        super::StateInitialization::Applied
    );
    let state = LocalState::open(&paths).unwrap();
    state.set_kv("existing", "keep").unwrap();
    assert_eq!(
        LocalState::initialize_local(&paths).unwrap(),
        super::StateInitialization::Ready
    );
    assert_eq!(state.get_kv("existing").unwrap().as_deref(), Some("keep"));
    state
        .connection
        .pragma_update(None, "user_version", 3)
        .unwrap();
    assert_eq!(
        LocalState::initialize_local(&paths).unwrap(),
        super::StateInitialization::Applied
    );
    assert_eq!(state.get_kv("existing").unwrap().as_deref(), Some("keep"));
}

#[test]
fn initialization_refuses_future_version_without_downgrading_or_removing_records() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state.set_kv("future-record", "retain").unwrap();
    state
        .connection
        .pragma_update(None, "user_version", 99)
        .unwrap();
    let error = state.init_schema().unwrap_err();
    assert_eq!(
        error.downcast_ref::<super::LocalStateInitializationError>(),
        Some(&super::LocalStateInitializationError::UnsupportedVersion(
            99
        ))
    );
    assert_eq!(
        state
            .connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        99
    );
    assert_eq!(
        state.get_kv("future-record").unwrap().as_deref(),
        Some("retain")
    );
}

#[test]
fn failed_schema_initialization_rolls_back_all_tables_and_version() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let state = LocalState::open(&paths).unwrap();
    state.connection.execute_batch("CREATE TABLE kv (key TEXT PRIMARY KEY); INSERT INTO kv VALUES ('retain'); PRAGMA user_version=2;").unwrap();
    assert!(state.init_schema().is_err());
    assert_eq!(
        state
            .connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    let tables: i64 = state
        .connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 1);
    assert_eq!(
        state
            .connection
            .query_row("SELECT key FROM kv", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "retain"
    );
}

#[test]
fn initialization_refuses_corrupt_database_without_replacement() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let bytes = b"this is not SQLite metadata";
    std::fs::write(paths.state_db_path(), bytes).unwrap();
    assert!(LocalState::initialize_local(&paths).is_err());
    assert_eq!(std::fs::read(paths.state_db_path()).unwrap(), bytes);
}

#[test]
fn initialization_rejects_table_without_required_primary_key() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let state = LocalState::open(&paths).unwrap();
    state
        .connection
        .execute_batch(
            "CREATE TABLE kv (key TEXT, value TEXT, updated_at TEXT); PRAGMA user_version=4;",
        )
        .unwrap();
    let error = state.init_schema().unwrap_err();
    assert_eq!(
        error.downcast_ref::<super::LocalStateInitializationError>(),
        Some(&super::LocalStateInitializationError::Unavailable)
    );
    assert_eq!(
        state
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn initialization_rejects_wrong_named_indexes_without_version_or_schema_changes() {
    for replacement in [
        "CREATE INDEX workspaces_server_project_idx ON workspaces(server_url, project_key)",
        "CREATE UNIQUE INDEX workspaces_server_project_idx ON workspaces(server_url, local_path)",
        "CREATE UNIQUE INDEX skill_commands_pending_intent ON skill_commands(server_url,user_id,intent_digest) WHERE state='received'",
    ] {
        let dir = tempdir().unwrap();
        let paths = AppPaths::from_home(dir.path().to_owned());
        let state = LocalState::open(&paths).unwrap();
        state.init_schema().unwrap();
        state.set_kv("retain", "original").unwrap();
        state.connection.execute_batch("DROP INDEX workspaces_server_project_idx; DROP INDEX skill_commands_pending_intent; PRAGMA user_version=3;").unwrap();
        state.connection.execute_batch(replacement).unwrap();
        let before: i64 = state.connection.pragma_query_value(None, "schema_version", |row| row.get(0)).unwrap();
        let error = state.init_schema().unwrap_err();
        assert_eq!(error.downcast_ref::<super::LocalStateInitializationError>(), Some(&super::LocalStateInitializationError::Unavailable));
        assert_eq!(state.connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0)).unwrap(), 3);
        assert_eq!(state.connection.pragma_query_value(None, "schema_version", |row| row.get::<_, i64>(0)).unwrap(), before);
        assert_eq!(state.get_kv("retain").unwrap().as_deref(), Some("original"));
    }
}

#[test]
fn concurrent_initialization_applies_schema_once() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let jobs: Vec<_> = (0..8)
        .map(|_| {
            let paths = paths.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                LocalState::initialize_local(&paths).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
    assert_eq!(
        results
            .iter()
            .filter(|&&status| status == super::StateInitialization::Applied)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|&&status| status == super::StateInitialization::Ready)
            .count(),
        7
    );
}

#[test]
fn initialization_does_not_overwrite_version_changed_while_waiting_for_writer() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state
        .connection
        .execute_batch("BEGIN IMMEDIATE; PRAGMA user_version=99;")
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let waiting = barrier.clone();
    let contender = std::thread::spawn(move || {
        let other = LocalState::open(&paths).unwrap();
        waiting.wait();
        other.init_schema().unwrap_err()
    });
    barrier.wait();
    state.connection.execute_batch("COMMIT;").unwrap();
    let error = contender.join().unwrap();
    assert_eq!(
        error.downcast_ref::<super::LocalStateInitializationError>(),
        Some(&super::LocalStateInitializationError::UnsupportedVersion(
            99
        ))
    );
}

#[test]
fn initialization_has_a_bounded_writer_lock_wait() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state.connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    let other = LocalState::open(&paths).unwrap();
    let started = std::time::Instant::now();
    assert!(other.init_schema().is_err());
    // SQLite's configured busy timeout is three seconds. Keep enough margin
    // for shared CI runners compiling and scheduling many test binaries while
    // still proving that initialization does not wait indefinitely.
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    state.connection.execute_batch("ROLLBACK;").unwrap();
}

#[cfg(unix)]
#[test]
fn initialization_rejects_linked_and_special_database_paths() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let target = dir.path().join("target");
    std::fs::write(&target, b"retain").unwrap();
    for kind in ["symlink", "hardlink", "directory", "fifo"] {
        let path = paths.state_db_path();
        match kind {
            "symlink" => symlink(&target, &path).unwrap(),
            "hardlink" => std::fs::hard_link(&target, &path).unwrap(),
            "directory" => std::fs::create_dir(&path).unwrap(),
            "fifo" => {
                use std::os::unix::ffi::OsStrExt;
                let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }
        let error = LocalState::initialize_local(&paths).unwrap_err();
        assert_eq!(
            error.downcast_ref::<super::LocalStateInitializationError>(),
            Some(&super::LocalStateInitializationError::InvalidPath),
            "{kind}"
        );
        if kind == "directory" {
            std::fs::remove_dir(path).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
    }
    assert_eq!(std::fs::read(target).unwrap(), b"retain");
}

#[cfg(unix)]
#[test]
fn initialization_rejects_home_link_aliases_before_any_writes() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let link = dir.path().join("linked-home");
    symlink(&target, &link).unwrap();
    for suffix in ["", "/", "/.", "/./"] {
        let mut spelling = link.as_os_str().to_os_string();
        spelling.push(suffix);
        let paths = AppPaths::from_home(spelling.into());
        assert!(LocalState::initialize_local(&paths).is_err(), "{suffix}");
        assert!(LocalState::open(&paths).is_err(), "{suffix}");
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0, "{suffix}");
    }
    for suffix in ["/", "/."] {
        let mut spelling = target.as_os_str().to_os_string();
        spelling.push(suffix);
        let paths = AppPaths::from_home(spelling.into());
        LocalState::initialize_local(&paths).unwrap();
        LocalState::open(&paths).unwrap().init_schema().unwrap();
    }
}

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
fn stores_ego_browser_metadata_without_connection_secrets() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    let binding = LocalEgoBrowserBinding {
        id: "11111111-2222-3333-4444-555555555555".to_string(),
        server_url: "https://example.test".to_string(),
        ego_browser_device_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
        tool_session_id: "99999999-8888-7777-6666-555555555555".to_string(),
        node_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
        status: "active".to_string(),
        generation: 7,
        relay_binding_kind: "ego_browser".to_string(),
        lease_until: Some("2026-09-06T12:00:00Z".to_string()),
    };

    state.upsert_ego_browser_binding(&binding).unwrap();
    assert_eq!(
        state.get_ego_browser_binding(&binding.id).unwrap(),
        Some(binding)
    );
    let columns = state.table_columns("ego_browser_bindings").unwrap();
    assert!(!columns.iter().any(|column| {
        column.contains("token") || column.contains("script") || column.contains("secret")
    }));
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

#[test]
fn removes_stale_workspace_and_sync_mappings() {
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
            remote_path: None,
        })
        .unwrap();
    for id in ["sync_1", "sync_2"] {
        state
            .upsert_sync_session(&LocalSyncSession {
                id: id.to_string(),
                server_url: "https://example.test".to_string(),
                workspace_id: "workspace_1".to_string(),
                node_id: None,
                status: "active".to_string(),
                conflict_status: "none".to_string(),
                mutagen_session_id: None,
                remote_endpoint: None,
            })
            .unwrap();
    }

    state.delete_sync_session("sync_1").unwrap();
    assert_eq!(
        state
            .get_sync_session_for_workspace("workspace_1")
            .unwrap()
            .unwrap()
            .id,
        "sync_2"
    );
    state.delete_workspace_mapping("workspace_1").unwrap();
    assert!(state
        .get_workspace_by_project_key("https://example.test", "sha256:test")
        .unwrap()
        .is_none());
    assert!(state
        .get_sync_session_for_workspace("workspace_1")
        .unwrap()
        .is_none());
}
