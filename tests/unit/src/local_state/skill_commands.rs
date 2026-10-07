// Tests for src/local_state/skill_commands.rs.

use super::*;
use crate::config::AppPaths;

#[test]
fn skill_command_recovery_preserves_exact_input_and_owner() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(home.path().to_path_buf());
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    let mut record = SkillCommandRecord {
        server_url: "https://example.test".into(),
        user_id: "user-one".into(),
        intent_digest: "a".repeat(64),
        idempotency_key: "original".into(),
        request_json: r#"{"expected_generation":7}"#.into(),
    };
    assert_eq!(state.begin_skill_command(&record).unwrap(), record);
    let original = record.clone();
    record.idempotency_key = "replacement".into();
    record.request_json = r#"{"expected_generation":8}"#.into();
    assert_eq!(state.begin_skill_command(&record).unwrap(), original);
    drop(state);
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    assert_eq!(
        state
            .pending_skill_command(
                &original.server_url,
                &original.user_id,
                &original.intent_digest
            )
            .unwrap(),
        Some(original.clone())
    );
    assert!(state
        .pending_skill_command(
            &original.server_url,
            "another-user",
            &original.intent_digest
        )
        .unwrap()
        .is_none());
    assert!(state
        .pending_skill_command(
            "https://another.test",
            &original.user_id,
            &original.intent_digest
        )
        .unwrap()
        .is_none());
    assert_eq!(
        state
            .pending_skill_commands(&original.server_url, &original.user_id)
            .unwrap(),
        vec![original.clone()]
    );
    assert!(state
        .pending_skill_commands(&original.server_url, "another-user")
        .unwrap()
        .is_empty());
    assert!(state
        .pending_skill_commands("https://another.test", &original.user_id)
        .unwrap()
        .is_empty());
    state
        .receive_skill_command(&original, Some("operation-one"))
        .unwrap();
    state
        .receive_skill_command(&original, Some("operation-one"))
        .unwrap();
    assert!(state
        .receive_skill_command(&original, Some("operation-two"))
        .is_err());
    assert!(state
        .pending_skill_command(
            &original.server_url,
            &original.user_id,
            &original.intent_digest
        )
        .unwrap()
        .is_none());
    assert!(state
        .pending_skill_commands(&original.server_url, &original.user_id)
        .unwrap()
        .is_empty());
    assert_eq!(state.begin_skill_command(&record).unwrap(), record);
}

#[test]
fn concurrent_skill_commands_share_one_pending_request() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(home.path().to_path_buf());
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|index| {
            let root = home.path().to_path_buf();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let state = LocalState::open(&AppPaths::from_home(root)).unwrap();
                let record = SkillCommandRecord {
                    server_url: "https://example.test".into(),
                    user_id: "same-user".into(),
                    intent_digest: "c".repeat(64),
                    idempotency_key: format!("request-{index}"),
                    request_json: format!("{{\"expected_generation\":{index}}}"),
                };
                barrier.wait();
                state.begin_skill_command(&record).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results[0], results[1]);
}
