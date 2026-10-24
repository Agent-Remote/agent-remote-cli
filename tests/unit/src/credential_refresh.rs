use super::*;
use crate::local_state::LocalState;

#[test]
fn missing_state_and_missing_schema_do_not_initialize_anything() {
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(root.path().join("missing"));
    assert!(RefreshRecord::read(&paths, "key".into()).is_err());
    assert!(!paths.home().exists());
    std::fs::create_dir(paths.home()).unwrap();
    Connection::open(paths.state_db_path()).unwrap();
    let before = std::fs::read(paths.state_db_path()).unwrap();
    assert!(RefreshRecord::read(&paths, "key".into()).is_err());
    assert_eq!(before, std::fs::read(paths.state_db_path()).unwrap());
    assert!(!paths.secrets_dir().exists());
}

#[test]
fn refresh_update_requires_original_row_and_never_inserts() {
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(root.path().join("home"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state.set_kv("key", "1").unwrap();
    let record = RefreshRecord::read(&paths, "key".into()).unwrap();
    record.update(&paths, 2).unwrap();
    assert_eq!(state.get_kv("key").unwrap().as_deref(), Some("2"));
    assert!(record.update(&paths, 3).is_err());
    let next = RefreshRecord::read(&paths, "key".into()).unwrap();
    state
        .connection
        .execute("DELETE FROM kv WHERE key='key'", [])
        .unwrap();
    assert!(next.update(&paths, 3).is_err());
    assert!(state.get_kv("key").unwrap().is_none());
}

#[test]
fn refresh_database_replacement_and_failed_commit_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(root.path().join("home"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state.set_kv("key", "1").unwrap();
    let record = RefreshRecord::read(&paths, "key".into()).unwrap();
    let locked = Connection::open(paths.state_db_path()).unwrap();
    locked.execute_batch("BEGIN; SELECT * FROM kv;").unwrap();
    assert!(record.update(&paths, 3).is_err());
    locked.execute_batch("ROLLBACK;").unwrap();
    assert_eq!(state.get_kv("key").unwrap().as_deref(), Some("1"));
    drop(locked);
    drop(state);
    std::fs::rename(paths.state_db_path(), paths.home().join("previous.sqlite3")).unwrap();
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state.set_kv("key", "1").unwrap();
    assert!(record.update(&paths, 4).is_err());
    assert_eq!(state.get_kv("key").unwrap().as_deref(), Some("1"));
}

#[cfg(unix)]
#[test]
fn refresh_identity_inspection_preserves_other_connections_posix_locks() {
    const CHILD: &str = "AGENT_REMOTE_REFRESH_LOCK_PROBE";
    if let Some(path) = std::env::var_os(CHILD) {
        let writer = Connection::open(path).unwrap();
        writer
            .busy_timeout(std::time::Duration::from_millis(40))
            .unwrap();
        let error = writer
            .execute("UPDATE kv SET value='external' WHERE key='key'", [])
            .unwrap_err();
        assert!(matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ));
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(root.path().join("home"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state.set_kv("key", "1").unwrap();
    state
        .connection
        .execute_batch("BEGIN; SELECT * FROM kv;")
        .unwrap();
    let external_writer_must_be_blocked = || {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "local_state::credential_refresh::tests::refresh_identity_inspection_preserves_other_connections_posix_locks", "--nocapture"])
            .env(CHILD, paths.state_db_path()).output().unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let record = RefreshRecord::read(&paths, "key".into()).unwrap();
    external_writer_must_be_blocked();
    assert!(record.update(&paths, 2).is_err());
    external_writer_must_be_blocked();
    assert_eq!(state.get_kv("key").unwrap().as_deref(), Some("1"));
    state.connection.execute_batch("ROLLBACK;").unwrap();
    let writer = Connection::open(paths.state_db_path()).unwrap();
    assert_eq!(
        writer
            .execute("UPDATE kv SET value='2' WHERE key='key'", [])
            .unwrap(),
        1
    );
}
