use super::*;
use crate::config::AppPaths;
use crate::local_state::{LocalState, SessionCreateRecord};
use tempfile::tempdir;

#[test]
fn request_id_is_canonical_v4_and_nonzero() {
    let value = new_request_id();
    let uuid = uuid::Uuid::parse_str(&value).unwrap();
    assert_eq!(uuid.to_string(), value);
    assert_eq!(uuid.get_version_num(), 4);
    assert_ne!(uuid, uuid::Uuid::nil());
}

#[test]
fn argv_digest_is_ordered_canonical_json_and_does_not_store_values() {
    assert_eq!(
        argv_digest(&["--resume".into(), "原始值".into()]),
        "sha256:32b3c8faa0e7cca093958359758c09f34e4597b69581b63216630f24eb8547a1"
    );
    assert_ne!(
        argv_digest(&["a".into(), "b".into()]),
        argv_digest(&["b".into(), "a".into()])
    );
}

#[test]
fn wire_intent_fingerprint_matches_server_sorted_json_contract() {
    let target = serde_json::json!({
        "id": "44444444-4444-4444-8444-444444444444",
        "workspace_id": "33333333-3333-4333-8333-333333333333",
        "node_id": null,
        "local_path": "/a",
        "remote_path": "/b",
        "target_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    });
    assert_eq!(
        intent_fingerprint_wire(
            "claude",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "project",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            None,
            &target,
        ),
        "sha256:9ee9f1abc9340652fce9f98fd3f8dbb78f5f181256d1dce1a3bccc74ee65f903"
    );
}

fn record(home: &std::path::Path) -> SessionCreateRecord {
    SessionCreateRecord {
        home: home.to_path_buf(),
        server_url: "https://server.test".into(),
        user_id: authenticated_scope("opaque-token"),
        request_id: "11111111-1111-4111-8111-111111111111".into(),
        tool_type: "claude".into(),
        tool_account_id: "22222222-2222-4222-8222-222222222222".into(),
        workspace_id: "33333333-3333-4333-8333-333333333333".into(),
        project_key: "project".into(),
        argv_digest: argv_digest(&["--resume".into()]),
        replacement_session_id: None,
        sync_target_digest: None,
        prepare_task_id: None,
        prepare_task_record_id: None,
        phase: "prepared".into(),
        session_id: None,
        create_task_id: None,
        task_record_id: None,
        last_observation: None,
    }
}

#[test]
fn journal_is_atomic_and_only_compare_and_swap_changes_observation() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let paths = AppPaths::from_home(home.clone());
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    let original = record(&home);
    assert!(state.reserve_session_create(&original).unwrap());
    assert!(!state.reserve_session_create(&original).unwrap());
    let mut next = original.clone();
    next.phase = "accepted".into();
    next.session_id = Some("44444444-4444-4444-8444-444444444444".into());
    assert!(state.update_session_create(&original, &next).unwrap());
    let records = LocalState::session_create_records(&paths).unwrap();
    assert_eq!(records, vec![next.clone()]);
    let raw = std::fs::read_to_string(paths.state_db_path()).unwrap_or_default();
    assert!(!raw.contains("--resume"));
    let mut changed = next.clone();
    changed.project_key = "other".into();
    assert!(state.update_session_create(&next, &changed).is_err());
}
