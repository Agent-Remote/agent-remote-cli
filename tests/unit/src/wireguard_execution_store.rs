use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::*;
use crate::wireguard::inspection::ConfigBinding;
use crate::wireguard::target::{TargetReason, TargetState};
use crate::wireguard::tunnel::Action;

fn configuration() -> ExecutionConfig {
    let private = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let bytes =
        format!("[Interface]\nPrivateKey = {private}\nAddress = 10.77.0.2/32\n").into_bytes();
    let binding = ConfigBinding {
        file_identity: "a".repeat(64),
        content_sha256: format!("{:x}", Sha256::digest(&bytes)),
        public_key: crate::wireguard::public_key_from_private(private).unwrap(),
    };
    ExecutionConfig::from_transfer(bytes, &binding).unwrap()
}
fn request(config: &ExecutionConfig) -> ExecutionRequest {
    ExecutionRequest {
        version: 1,
        request_id: "1".repeat(64),
        caller_sha256: "2".repeat(64),
        plan_sha256: "3".repeat(64),
        target_scope_sha256: "4".repeat(64),
        action: Action::Up,
        logical_name: "test-tunnel".into(),
        config: config.binding().clone(),
    }
}
fn store() -> (tempfile::TempDir, ExecutionStore) {
    let temporary = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    (temporary, ExecutionStore::new(root))
}
fn created(result: BeginOperation<'_>) -> Box<Operation<'_>> {
    match result {
        BeginOperation::Created(operation) => operation,
        _ => panic!("new ID did not create lease"),
    }
}
fn unknown(name: &str) -> TargetObservation {
    TargetObservation {
        logical_name: name.into(),
        state: TargetState::Unknown,
        reason: Some(TargetReason::NativeQueryFailed),
        status_state: "not_queried".into(),
        identity: None,
    }
}

#[test]
fn snapshots_preserve_exact_bytes_basename_and_survive_lease_drop() {
    let (_temporary, store) = store();
    let config = configuration();
    let request = request(&config);
    let operation = created(
        store
            .begin(request.clone(), &config, &AtomicBool::new(false))
            .unwrap(),
    );
    let path = operation.directory.path().join("test-tunnel.conf");
    assert_eq!(std::fs::read(&path).unwrap(), config.as_bytes());
    let record = serde_json::to_string(operation.record()).unwrap();
    assert!(!record.contains("PrivateKey"));
    assert!(!record.contains("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    #[cfg(unix)]
    assert_eq!(operation.directory_sync(), DirectorySync::Synced);
    #[cfg(windows)]
    assert_eq!(operation.directory_sync(), DirectorySync::Unsupported);
    drop(operation);
    assert!(path.is_file());
    assert_eq!(
        store
            .read(&request.request_id, &AtomicBool::new(false))
            .unwrap()
            .unwrap()
            .phase,
        OperationPhase::Prepared
    );
}

#[test]
fn every_existing_phase_is_read_only_and_never_grants_a_second_lease() {
    for phase in [
        OperationPhase::Prepared,
        OperationPhase::Submitted,
        OperationPhase::Observed,
        OperationPhase::Failed,
    ] {
        let (_temporary, store) = store();
        let config = configuration();
        let request = request(&config);
        let mut operation = created(
            store
                .begin(request.clone(), &config, &AtomicBool::new(false))
                .unwrap(),
        );
        if phase != OperationPhase::Prepared {
            operation.mark_submitted(&AtomicBool::new(false)).unwrap();
        }
        match phase {
            OperationPhase::Observed => {
                operation
                    .record_observation(unknown(&request.logical_name))
                    .unwrap();
            }
            OperationPhase::Failed => {
                operation
                    .record_failure(ExecutionFailure::ToolFailed)
                    .unwrap();
            }
            _ => {}
        }
        drop(operation);
        match store
            .begin(request, &config, &AtomicBool::new(false))
            .unwrap()
        {
            BeginOperation::Existing(record) => assert_eq!(record.phase, phase),
            _ => panic!("existing ID acquired another lease"),
        }
    }
}

#[test]
fn existing_request_binding_cannot_be_changed() {
    let (_temporary, store) = store();
    let config = configuration();
    let original = request(&config);
    drop(created(
        store
            .begin(original.clone(), &config, &AtomicBool::new(false))
            .unwrap(),
    ));
    for field in 0..7 {
        let mut changed = original.clone();
        match field {
            0 => changed.caller_sha256 = "5".repeat(64),
            1 => changed.plan_sha256 = "5".repeat(64),
            2 => changed.target_scope_sha256 = "5".repeat(64),
            3 => changed.action = Action::Down,
            4 => changed.logical_name = "other".into(),
            5 => changed.config.file_identity = "5".repeat(64),
            _ => changed.version = 2,
        }
        assert!(store
            .begin(changed, &config, &AtomicBool::new(false))
            .is_err());
    }
}

#[test]
fn target_lock_uses_platform_alias_semantics_and_excludes_caller() {
    let config = configuration();
    let original = request(&config);
    let mut changed = original.clone();
    changed.request_id = "b".repeat(64);
    changed.caller_sha256 = "c".repeat(64);
    changed.plan_sha256 = "d".repeat(64);
    assert_eq!(
        files::target_lock_name(&original),
        files::target_lock_name(&changed)
    );
    changed.logical_name = changed.logical_name.to_ascii_uppercase();
    assert_eq!(
        files::target_lock_name(&original) == files::target_lock_name(&changed),
        cfg!(any(windows, target_os = "macos"))
    );
    changed.logical_name = original.logical_name.clone();
    changed.target_scope_sha256 = "e".repeat(64);
    assert_ne!(
        files::target_lock_name(&original),
        files::target_lock_name(&changed)
    );
}

#[test]
fn transitions_are_one_way_and_cancellation_before_submission_preserves_prepared() {
    let (_temporary, store) = store();
    let config = configuration();
    let request = request(&config);
    let mut operation = created(
        store
            .begin(request.clone(), &config, &AtomicBool::new(false))
            .unwrap(),
    );
    assert!(operation
        .record_failure(ExecutionFailure::ToolFailed)
        .is_err());
    assert!(operation
        .record_observation(unknown(&request.logical_name))
        .is_err());
    assert!(operation.mark_submitted(&AtomicBool::new(true)).is_err());
    assert_eq!(operation.record().phase, OperationPhase::Prepared);
    operation.mark_submitted(&AtomicBool::new(false)).unwrap();
    assert!(operation.mark_submitted(&AtomicBool::new(false)).is_err());
    operation
        .record_failure(ExecutionFailure::Cancelled)
        .unwrap();
    assert!(operation
        .record_observation(unknown(&request.logical_name))
        .is_err());
    assert!(operation.mark_submitted(&AtomicBool::new(false)).is_err());
}

#[test]
fn incomplete_reservations_and_corrupt_records_cannot_be_recreated() {
    for mode in 0..6 {
        let (_temporary, store) = store();
        let config = configuration();
        let request = request(&config);
        if mode == 0 {
            store.root.create_child(&request.request_id).unwrap();
        } else {
            let operation = created(
                store
                    .begin(request.clone(), &config, &AtomicBool::new(false))
                    .unwrap(),
            );
            let path = operation.directory.path().join("record.json");
            drop(operation);
            let bytes = std::fs::read(&path).unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let malformed = match mode {
                1 => {
                    value.as_object_mut().unwrap().remove("observation");
                    serde_json::to_vec(&value).unwrap()
                }
                2 => {
                    value["failure"] = "tool_failed".into();
                    serde_json::to_vec(&value).unwrap()
                }
                3 => {
                    value["private_key"] = "forbidden".into();
                    serde_json::to_vec(&value).unwrap()
                }
                4 => vec![b' '; 128 * 1024 + 1],
                _ => b"{".to_vec(),
            };
            std::fs::write(path, malformed).unwrap();
        }
        assert!(store
            .begin(request.clone(), &config, &AtomicBool::new(false))
            .is_err());
        assert!(store
            .root
            .open_child(&request.request_id)
            .unwrap()
            .is_some());
    }
}

#[test]
fn snapshot_content_or_object_replacement_invalidates_submission() {
    for replacement in [false, true] {
        let (_temporary, store) = store();
        let config = configuration();
        let request = request(&config);
        let mut operation = created(
            store
                .begin(request.clone(), &config, &AtomicBool::new(false))
                .unwrap(),
        );
        let path = operation.directory.path().join("test-tunnel.conf");
        if replacement {
            std::fs::remove_file(&path).unwrap();
            operation
                .directory
                .create_file("test-tunnel.conf")
                .unwrap()
                .write_all(config.as_bytes())
                .unwrap();
        } else {
            std::fs::write(&path, b"different").unwrap();
        }
        assert!(operation.mark_submitted(&AtomicBool::new(false)).is_err());
        drop(operation);
        assert!(store
            .begin(request, &config, &AtomicBool::new(false))
            .is_err());
    }
}

#[test]
fn failed_record_publication_never_creates_replay_permission() {
    use files::faults::{arm, Stage};
    for initial in [false, true] {
        for stage in [
            Stage::Write,
            Stage::FileSync,
            Stage::Rename,
            Stage::DirectorySync,
        ] {
            let (_temporary, store) = store();
            let config = configuration();
            let request = request(&config);
            let mut operation = if initial {
                None
            } else {
                Some(created(
                    store
                        .begin(request.clone(), &config, &AtomicBool::new(false))
                        .unwrap(),
                ))
            };
            let guard = arm(stage);
            if let Some(operation) = &mut operation {
                assert!(operation.mark_submitted(&AtomicBool::new(false)).is_err());
            } else {
                assert!(store
                    .begin(request.clone(), &config, &AtomicBool::new(false))
                    .is_err());
            }
            drop(guard);
            drop(operation);
            match store.begin(request.clone(), &config, &AtomicBool::new(false)) {
                Ok(BeginOperation::Created(_)) => panic!("failed persistence allowed replay"),
                Ok(BeginOperation::Existing(record)) => assert!(matches!(
                    record.phase,
                    OperationPhase::Prepared | OperationPhase::Submitted
                )),
                Err(_) => {}
            }
            assert!(store
                .root
                .open_child(&request.request_id)
                .unwrap()
                .is_some());
        }
    }
}

#[test]
fn a_waiting_request_can_cancel_without_touching_the_target() {
    let (_temporary, store) = store();
    let config = configuration();
    let request = request(&config);
    let operation = created(
        store
            .begin(request.clone(), &config, &AtomicBool::new(false))
            .unwrap(),
    );
    let mut second = request;
    second.request_id = "b".repeat(64);
    let cancel = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let flag = cancel.clone();
        let store_ref = &store;
        let config_ref = &config;
        let waiting = scope.spawn(move || store_ref.begin(second, config_ref, &flag));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !store
            .root
            .path()
            .join(format!("request-{}.lock", "b".repeat(64)))
            .exists()
        {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        cancel.store(true, Ordering::Release);
        match waiting.join().unwrap() {
            Err(error) => assert_eq!(error.0, "wireguard_execution_canceled"),
            _ => panic!("canceled waiter acquired lease"),
        }
    });
    assert!(store.root.open_child(&"b".repeat(64)).unwrap().is_none());
    drop(operation);
}

#[test]
fn independent_processes_share_request_and_target_locks() {
    let (_temporary, store) = store();
    let config = configuration();
    let request = request(&config);
    let operation = created(
        store
            .begin(request.clone(), &config, &AtomicBool::new(false))
            .unwrap(),
    );
    for same_id in [false, true] {
        let mut other = request.clone();
        if same_id {
            other.logical_name = "different".into();
        } else {
            other.request_id = "b".repeat(64);
            other.caller_sha256 = "e".repeat(64);
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "wireguard::execution_store::tests::execution_store_child",
                "--nocapture",
            ])
            .env("AR_EXECUTION_CHILD_ROOT", store.root.path())
            .env(
                "AR_EXECUTION_CHILD_REQUEST",
                serde_json::to_string(&other).unwrap(),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child did not observe the held lock: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    drop(operation);
}

#[test]
fn execution_store_child() {
    let Some(root) = std::env::var_os("AR_EXECUTION_CHILD_ROOT") else {
        return;
    };
    let store = ExecutionStore::new(
        ProtectedDirectory::open_test_root(std::path::Path::new(&root)).unwrap(),
    );
    let request: ExecutionRequest =
        serde_json::from_str(&std::env::var("AR_EXECUTION_CHILD_REQUEST").unwrap()).unwrap();
    let mode = std::env::var("AR_EXECUTION_CHILD_MODE").unwrap_or_default();
    if mode.starts_with("exit_") {
        let config = configuration();
        let mut operation = created(
            store
                .begin(request, &config, &AtomicBool::new(false))
                .unwrap(),
        );
        if mode == "exit_submitted" {
            operation.mark_submitted(&AtomicBool::new(false)).unwrap();
        }
        // Abrupt process termination: no Rust lease, file or directory Drop runs.
        std::process::exit(23);
    }
    match store.begin(request, &configuration(), &AtomicBool::new(false)) {
        Err(error) => assert_eq!(error.0, "wireguard_execution_busy"),
        _ => panic!("another process bypassed a held lock"),
    }
}

#[test]
fn process_exit_preserves_prepared_and_submitted_records_without_replay() {
    for (mode, phase) in [
        ("exit_prepared", OperationPhase::Prepared),
        ("exit_submitted", OperationPhase::Submitted),
    ] {
        let (_temporary, store) = store();
        let config = configuration();
        let request = request(&config);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "wireguard::execution_store::tests::execution_store_child",
            ])
            .env("AR_EXECUTION_CHILD_ROOT", store.root.path())
            .env(
                "AR_EXECUTION_CHILD_REQUEST",
                serde_json::to_string(&request).unwrap(),
            )
            .env("AR_EXECUTION_CHILD_MODE", mode)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(23));
        assert_eq!(
            store
                .read(&request.request_id, &AtomicBool::new(false))
                .unwrap()
                .unwrap()
                .phase,
            phase
        );
        let recovered = store.submitted_records(&AtomicBool::new(false)).unwrap();
        assert_eq!(
            recovered
                .iter()
                .map(|record| record.request.request_id.as_str())
                .collect::<Vec<_>>(),
            if phase == OperationPhase::Submitted {
                vec![request.request_id.as_str()]
            } else {
                Vec::new()
            }
        );
        match store
            .begin(request, &config, &AtomicBool::new(false))
            .unwrap()
        {
            BeginOperation::Existing(record) => assert_eq!(record.phase, phase),
            _ => panic!("process exit enabled replay"),
        };
    }
}

#[test]
fn submitted_records_are_recovered_in_stable_order_without_replay() {
    let (_temporary, store) = store();
    let config = configuration();
    let mut first = request(&config);
    first.request_id = "f".repeat(64);
    let mut second = request(&config);
    second.request_id = "e".repeat(64);
    for request in [first.clone(), second.clone()] {
        let mut operation = created(
            store
                .begin(request, &config, &AtomicBool::new(false))
                .unwrap(),
        );
        operation.mark_submitted(&AtomicBool::new(false)).unwrap();
        drop(operation);
    }
    let prepared = request(&config);
    let prepared = created(
        store
            .begin(prepared, &config, &AtomicBool::new(false))
            .unwrap(),
    );
    drop(prepared);

    let records = store.submitted_records(&AtomicBool::new(false)).unwrap();
    let ids = records
        .iter()
        .map(|record| record.request.request_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["e".repeat(64), "f".repeat(64)]);
    assert!(records
        .iter()
        .all(|record| record.phase == OperationPhase::Submitted));

    // Recovery is observational and does not grant a second lease.
    match store
        .begin(first, &config, &AtomicBool::new(false))
        .unwrap()
    {
        BeginOperation::Existing(record) => assert_eq!(record.phase, OperationPhase::Submitted),
        BeginOperation::Created(_) => panic!("recovery query enabled replay"),
    }
}

#[test]
fn submission_journal_is_append_only_canonical_and_hash_chained() {
    let (_temporary, store) = store();
    let config = configuration();
    let request = request(&config);
    let mut operation = created(
        store
            .begin(request.clone(), &config, &AtomicBool::new(false))
            .unwrap(),
    );
    let path = operation.directory.path().join("submission.log");
    let prepared = std::fs::read_to_string(&path).unwrap();
    assert_eq!(prepared.lines().count(), 1);
    assert!(prepared.ends_with('\n'));
    assert!(!prepared.contains("PrivateKey"));
    let first: serde_json::Value = serde_json::from_str(prepared.lines().next().unwrap()).unwrap();
    assert_eq!(first["sequence"], 1);
    assert_eq!(first["record"]["phase"], "prepared");
    assert_eq!(first["previous_sha256"], "0".repeat(64));
    let first_hash = first["event_sha256"].as_str().unwrap().to_owned();

    operation.mark_submitted(&AtomicBool::new(false)).unwrap();
    drop(operation);
    let submitted = std::fs::read_to_string(&path).unwrap();
    assert_eq!(submitted.lines().count(), 2);
    let second: serde_json::Value =
        serde_json::from_str(submitted.lines().nth(1).unwrap()).unwrap();
    assert_eq!(second["sequence"], 2);
    assert_eq!(second["record"]["phase"], "submitted");
    assert_eq!(second["previous_sha256"], first_hash);
    assert!(store
        .read(&request.request_id, &AtomicBool::new(false))
        .is_ok());

    // Extra blank lines are not canonical journal records and cannot be used
    // to hide an append or truncate the chain.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    assert!(store
        .read(&request.request_id, &AtomicBool::new(false))
        .is_err());
}

#[test]
fn submission_journal_tampering_fails_closed_without_replay() {
    let (_temporary, store) = store();
    let config = configuration();
    let request = request(&config);
    let mut operation = created(
        store
            .begin(request.clone(), &config, &AtomicBool::new(false))
            .unwrap(),
    );
    operation.mark_submitted(&AtomicBool::new(false)).unwrap();
    drop(operation);
    let path = store
        .root
        .path()
        .join(&request.request_id)
        .join("submission.log");
    let mut lines = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    second["record"]["request"]["plan_sha256"] = "f".repeat(64).into();
    lines[1] = serde_json::to_string(&second).unwrap();
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

    assert!(store
        .read(&request.request_id, &AtomicBool::new(false))
        .is_err());
    assert!(store
        .begin(request, &config, &AtomicBool::new(false))
        .is_err());
}

#[cfg(windows)]
#[test]
fn windows_directory_sync_gap_never_reports_durable_submission() {
    let (_temporary, store) = store();
    let config = configuration();
    let request = request(&config);
    let mut operation = created(
        store
            .begin(request, &config, &AtomicBool::new(false))
            .unwrap(),
    );
    assert_eq!(
        operation.mark_submitted(&AtomicBool::new(false)).unwrap(),
        DirectorySync::Unsupported
    );
    assert_eq!(operation.directory_sync(), DirectorySync::Unsupported);
}

#[test]
fn malformed_request_directory_fails_closed_during_recovery() {
    let (_temporary, store) = store();
    let config = configuration();
    let request = request(&config);
    let operation = created(
        store
            .begin(request.clone(), &config, &AtomicBool::new(false))
            .unwrap(),
    );
    drop(operation);
    let orphan = store.root.path().join("a".repeat(64));
    std::fs::create_dir(&orphan).unwrap();
    assert!(matches!(
        store
            .submitted_records(&AtomicBool::new(false))
            .unwrap_err()
            .0,
        "wireguard_execution_record_invalid" | "wireguard_execution_unavailable"
    ));
}
