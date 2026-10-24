use super::*;
use crate::api::runtime_recovery::RecoveryBinding;

fn record_for(paths: &AppPaths) -> Record {
    let context = UserContext {
        home: paths.home().into(),
        server_url: "https://example.invalid".into(),
        actor_user_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
    };
    let account = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let key = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    let original = Original {
        task_id: format!("migrate_tool_account_runtime:{account}:{key}"),
        task_record_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into(),
        user_id: account.into(),
        tool_account_id: account.into(),
        node_id: key.into(),
        tool_type: "claude".into(),
        source_runtime_backend: "native".into(),
        target_runtime_backend: "docker_sandbox".into(),
    };
    Record {
        digest: digest(&context, account, &original, Action::VerifyTarget).unwrap(),
        context,
        account_id: account.into(),
        request_id: key.into(),
        original,
        action: Action::VerifyTarget,
        binding: None,
        phase: "unknown".into(),
        rejection_code: None,
    }
}
fn binding(record: &Record) -> RecoveryBinding {
    RecoveryBinding {
        version: 1,
        action: None,
        task_id: format!(
            "recover_tool_account_runtime:{}:{}",
            record.account_id, record.request_id
        ),
        task_record_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".into(),
        original_task_id: record.original.task_id.clone(),
        original_task_record_id: record.original.task_record_id.clone(),
        user_id: record.original.user_id.clone(),
        tool_account_id: record.account_id.clone(),
        node_id: record.original.node_id.clone(),
        tool_type: "claude".into(),
        source_runtime_backend: record.original.source_runtime_backend.clone(),
        target_runtime_backend: record.original.target_runtime_backend.clone(),
    }
}

#[test]
fn context_actor_action_and_original_identity_all_change_review_digest() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(Some(temp.path().join("home"))).unwrap();
    let original = record_for(&paths);
    let mut next = original.clone();
    next.context.actor_user_id = next.account_id.clone();
    assert_ne!(
        digest(&next.context, &next.account_id, &next.original, next.action).unwrap(),
        original.digest
    );
    next = original.clone();
    next.action = Action::RepairSource;
    assert_ne!(
        digest(&next.context, &next.account_id, &next.original, next.action).unwrap(),
        original.digest
    );
    next = original.clone();
    next.original.task_record_id = next.context.actor_user_id.clone();
    assert_ne!(
        digest(&next.context, &next.account_id, &next.original, next.action).unwrap(),
        original.digest
    );
}

#[test]
fn concurrent_reservations_retain_only_one_same_account_intent() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(Some(temp.path().join("home"))).unwrap();
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    drop(state);
    let first = record_for(&paths);
    let mut second = first.clone();
    second.request_id = "ffffffff-ffff-4fff-8fff-ffffffffffff".into();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = [first, second]
        .into_iter()
        .map(|record| {
            let paths = paths.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let state = LocalState::open(&paths).unwrap();
                barrier.wait();
                state.reserve_runtime_recovery(&record).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let won = handles
        .into_iter()
        .map(|h| usize::from(h.join().unwrap()))
        .sum::<usize>();
    assert_eq!(won, 1);
    assert_eq!(
        LocalState::runtime_recovery_records(&paths).unwrap().len(),
        1
    );
}

#[test]
fn stale_record_cannot_remove_a_newly_saved_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(Some(temp.path().join("home"))).unwrap();
    let original = record_for(&paths);
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    assert!(state.reserve_runtime_recovery(&original).unwrap());
    let mut next = original.clone();
    next.phase = "accepted".into();
    next.binding = Some(binding(&original));
    assert!(state.update_runtime_recovery(&original, &next).unwrap());
    assert!(!state.forget_runtime_recovery(&original).unwrap());
    assert_eq!(
        LocalState::runtime_recovery_records(&paths).unwrap(),
        vec![next]
    );
}

#[test]
fn registry_corruption_is_rejected_without_returning_partial_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(Some(temp.path().join("home"))).unwrap();
    let original = record_for(&paths);
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    assert!(state.reserve_runtime_recovery(&original).unwrap());
    let mut broken = original.clone();
    broken.original.user_id = broken.context.actor_user_id.clone();
    state
        .set_kv(
            &format!("runtime_recovery_request:{}", original.request_id),
            &serde_json::to_string(&broken).unwrap(),
        )
        .unwrap();
    assert!(pending(&paths).is_err());
}
