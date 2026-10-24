use super::fixture::*;
use agent_remote_cli::{
    config::AppPaths,
    local_state::{LocalState, LocalSyncSession, LocalWorkspace},
    sync_operations, workspace,
};
use serde_json::{json, Value};
pub(super) const WS: &str = "12345678-1234-1234-1234-123456789abc";
pub(super) const SYNC: &str = "87654321-1234-1234-1234-123456789abc";
fn data(path: &std::path::Path, status: &str) -> Value {
    json!({"id":SYNC,"user_id":"secret-user-id","workspace_id":WS,"node_id":null,"local_path":path,"remote_path":"/workspaces/test","status":status,"conflict_status":"none","sync_mode":"two_way","sync_git":true,"exclude":["node_modules"],"mutagen_session_id":"ar-sync-test","remote_endpoint":"test@127.0.0.1:/workspaces/test","target_precondition_version":1,"target_precondition_checked":true,"prepare_task_id":null,"created_at":"now","updated_at":"now"})
}
pub(super) fn seed(f: &Fixture, path: &std::path::Path, sync: bool) -> Value {
    let paths = AppPaths::new(Some(f.home.clone())).unwrap();
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    let identity = workspace::identify_workspace(Some(path)).unwrap();
    state
        .upsert_workspace(&LocalWorkspace {
            id: WS.into(),
            server_url: f.context["server_url"].as_str().unwrap().into(),
            project_key: identity.project_key.clone(),
            local_path: path.to_string_lossy().into(),
            display_name: "test".into(),
            remote_path: Some("/workspaces/test".into()),
        })
        .unwrap();
    if sync {
        state
            .upsert_sync_session(&LocalSyncSession {
                id: SYNC.into(),
                server_url: f.context["server_url"].as_str().unwrap().into(),
                workspace_id: WS.into(),
                node_id: None,
                status: "active".into(),
                conflict_status: "none".into(),
                mutagen_session_id: Some("ar-sync-test".into()),
                remote_endpoint: Some("test@127.0.0.1:/workspaces/test".into()),
            })
            .unwrap();
    }
    let fingerprint = if sync {
        Some(sync_operations::fingerprint(
            &serde_json::from_value(data(path, "active")).unwrap(),
        ))
    } else {
        None
    };
    json!({"local_path":path,"project_key":identity.project_key,"workspace_id":WS,"sync_session_id":if sync{Some(SYNC)}else{None},"fingerprint":fingerprint})
}
fn input(f: &Fixture, target: Value, dry_run: bool) -> Value {
    json!({"confirmed":true,"expected_context":f.context,"expected_target":target,"dry_run":dry_run})
}
#[test]
fn sync_status_reads_mapping_and_never_posts_or_initializes_mutagen() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![envelope(data(&path, "active"))]);
    let target = seed(&f, &path, true);
    let paths = AppPaths::new(Some(f.home.clone())).unwrap();
    let before = std::fs::read(paths.state_db_path()).unwrap();
    let (ok, response) = f.invoke(
        "sync.status",
        json!({"expected_context":f.context,"local_path":path}),
    );
    assert!(ok, "{response}");
    assert_eq!(response["result"]["target"], target);
    assert_eq!(response["result"]["mutagen"]["conflicts"], "unknown");
    assert_eq!(before, std::fs::read(paths.state_db_path()).unwrap());
    assert!(!paths.ssh_dir().join("mutagen-environment").exists());
    assert_eq!(f.wires().len(), 1);
    redact(&response);
}
#[test]
fn sync_dry_run_still_posts_and_persists_but_reports_mutagen_skipped() {
    for (method, status) in [
        ("sync.pause", "paused"),
        ("sync.resume", "active"),
        ("sync.resolve", "active"),
        ("sync.reset", "active"),
    ] {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().canonicalize().unwrap();
        let f = Fixture::new(vec![
            envelope(data(&path, "active")),
            envelope(data(&path, status)),
        ]);
        let target = seed(&f, &path, true);
        let (ok, response) = f.invoke(method, input(&f, target.clone(), true));
        assert!(ok, "{response}");
        let r = &response["result"];
        assert_eq!(r["outcome"], "completed");
        assert_eq!(r["target"], target);
        assert!(r["stages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "mutagen" && s["state"] == "skipped"));
        let wires = f.wires();
        assert_eq!(wires.len(), 2);
        assert!(wires[1].starts_with(&format!(
            "POST /api/v1/sync-sessions/{SYNC}/{}",
            method.trim_start_matches("sync.")
        )));
        let body: Value = serde_json::from_str(wires[1].split_once("\r\n\r\n").unwrap().1).unwrap();
        let expected = &body["expected_target"];
        for field in [
            "id",
            "workspace_id",
            "node_id",
            "local_path",
            "remote_path",
            "mutagen_session_id",
            "remote_endpoint",
            "sync_mode",
            "sync_git",
            "exclude",
        ] {
            assert_eq!(
                expected[field],
                data(&path, "active")[field],
                "missing conditional target {field}"
            );
        }
        let state = LocalState::open(&AppPaths::new(Some(f.home.clone())).unwrap()).unwrap();
        assert_eq!(
            state
                .get_sync_session_for_workspace(WS)
                .unwrap()
                .unwrap()
                .status,
            status
        );
        redact(&response);
    }
}
#[test]
fn sync_same_id_changed_endpoint_requires_new_confirmation_before_post() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let mut changed = data(&path, "active");
    changed["remote_endpoint"] = json!("attacker@127.0.0.1:/other");
    let f = Fixture::new(vec![envelope(changed)]);
    let target = seed(&f, &path, true);
    let (ok, response) = f.invoke("sync.reset", input(&f, target, true));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "sync_target_changed");
    assert_eq!(f.wires().len(), 1);
}
#[test]
fn sync_unknown_post_is_not_retried_and_preserves_original_target() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![
        envelope(data(&path, "active")),
        Reply::json(503, json!({"detail":"secret-server-diagnostics"})),
    ]);
    let target = seed(&f, &path, true);
    let (ok, response) = f.invoke("sync.resume", input(&f, target.clone(), true));
    assert!(ok, "{response}");
    assert_eq!(response["result"]["outcome"], "unknown");
    assert_eq!(response["result"]["target"], target);
    assert_eq!(
        response["result"]["stages"][0],
        json!({"name":"server","state":"unknown"})
    );
    assert_eq!(f.wires().len(), 2);
    assert!(!response.to_string().contains("secret-server"));
}
#[test]
fn sync_confirmation_and_missing_nullable_target_rejected_without_http() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![]);
    let target = seed(&f, &path, false);
    let mut params = input(&f, target, false);
    params["confirmed"] = json!(false);
    let (_, response) = f.invoke("sync.ensure", params.clone());
    assert_eq!(response["error"]["code"], "confirmation_required");
    params["confirmed"] = json!(true);
    params["expected_target"]
        .as_object_mut()
        .unwrap()
        .remove("fingerprint");
    let (_, response) = f.invoke("sync.ensure", params);
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(f.wires().is_empty());
}

#[test]
fn sync_ensure_records_workspace_server_and_local_metadata_separately() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let identity = workspace::identify_workspace(Some(&path)).unwrap();
    let workspace = json!({"id":WS,"user_id":"secret-user-id","device_id":"device-test","project_key":identity.project_key,"local_start_path":path,"display_name":"test","remote_path":"/workspaces/test","sync_git":true,"created_at":"now","updated_at":"now"});
    let f = Fixture::new(vec![envelope(workspace), envelope(data(&path, "active"))]);
    let target = seed(&f, &path, false);
    let (ok, response) = f.invoke("sync.ensure", input(&f, target.clone(), true));
    assert!(ok, "{response}");
    let result = &response["result"];
    assert_eq!(result["outcome"], "completed");
    assert_eq!(result["target"], target);
    assert_eq!(result["result_target"]["sync_session_id"], SYNC);
    assert_eq!(result["stages"][0]["name"], "workspace");
    assert!(result["stages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["name"] == "persist" && s["state"] == "completed"));
    assert_eq!(f.wires().len(), 2);
    let state = LocalState::open(&AppPaths::new(Some(f.home.clone())).unwrap()).unwrap();
    assert_eq!(
        state
            .get_sync_session_for_workspace(WS)
            .unwrap()
            .unwrap()
            .id,
        SYNC
    );
}
#[test]
fn sync_ensure_retains_workspace_receipt_when_second_post_is_unknown() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let identity = workspace::identify_workspace(Some(&path)).unwrap();
    let workspace = json!({"id":WS,"user_id":"secret-user-id","device_id":"device-test","project_key":identity.project_key,"local_start_path":path,"display_name":"test","remote_path":"/workspaces/test","sync_git":true,"created_at":"now","updated_at":"now"});
    let f = Fixture::new(vec![
        envelope(workspace),
        Reply::json(503, json!({"detail":"secret failure"})),
    ]);
    let target = seed(&f, &path, false);
    let (ok, response) = f.invoke("sync.ensure", input(&f, target, true));
    assert!(ok, "{response}");
    let result = &response["result"];
    assert_eq!(result["outcome"], "unknown");
    assert_eq!(
        result["stages"][0],
        json!({"name":"workspace","state":"completed"})
    );
    assert_eq!(
        result["stages"][1],
        json!({"name":"persist","state":"completed"})
    );
    assert_eq!(
        result["stages"][2],
        json!({"name":"server","state":"unknown"})
    );
    assert_eq!(f.wires().len(), 2);
}
#[test]
fn sync_post_response_target_change_is_unknown_and_not_persisted() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let mut next = data(&path, "active");
    next["remote_path"] = json!("/unexpected");
    let f = Fixture::new(vec![envelope(data(&path, "active")), envelope(next)]);
    let target = seed(&f, &path, true);
    let (ok, response) = f.invoke("sync.reset", input(&f, target, true));
    assert!(ok, "{response}");
    assert_eq!(response["result"]["outcome"], "unknown");
    assert_eq!(response["result"]["error_code"], "sync_outcome_unknown");
    assert_eq!(response["result"]["stages"].as_array().unwrap().len(), 1);
}
#[test]
fn sync_snapshot_compare_and_set_preserves_concurrent_mapping() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![]);
    seed(&f, &path, true);
    let paths = AppPaths::new(Some(f.home.clone())).unwrap();
    let identity = workspace::identify_workspace(Some(&path)).unwrap();
    let server = f.context["server_url"].as_str().unwrap();
    let expected = LocalState::sync_snapshot(&paths, server, &identity.project_key).unwrap();
    let state = LocalState::open(&paths).unwrap();
    let mut changed = expected.sync.clone().unwrap();
    changed.status = "paused".into();
    state.upsert_sync_session(&changed).unwrap();
    assert!(!state
        .compare_sync_snapshot(
            server,
            &identity.project_key,
            &expected,
            None,
            expected.sync.as_ref()
        )
        .unwrap());
    assert_eq!(
        LocalState::sync_snapshot(&paths, server, &identity.project_key)
            .unwrap()
            .sync
            .unwrap()
            .status,
        "paused"
    );
}

#[test]
fn sync_legacy_server_cannot_silently_downgrade_conditional_actions() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let mut old = data(&path, "active");
    old.as_object_mut()
        .unwrap()
        .remove("target_precondition_version");
    let f = Fixture::new(vec![envelope(old)]);
    let target = seed(&f, &path, true);
    let (ok, response) = f.invoke("sync.pause", input(&f, target, true));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "sync_response_invalid");
    assert_eq!(f.wires().len(), 1);
}
#[test]
fn sync_unchecked_action_response_is_unknown_even_if_destination_matches() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let mut reply = data(&path, "active");
    reply["target_precondition_checked"] = json!(false);
    let f = Fixture::new(vec![envelope(data(&path, "active")), envelope(reply)]);
    let target = seed(&f, &path, true);
    let (ok, response) = f.invoke("sync.resume", input(&f, target, true));
    assert!(ok, "{response}");
    assert_eq!(response["result"]["outcome"], "unknown");
    assert_eq!(f.wires().len(), 2);
}

#[test]
fn human_sync_dry_run_shares_conditional_service_without_claiming_local_flush() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![
        envelope(data(&path, "active")),
        envelope(data(&path, "active")),
        envelope(data(&path, "active")),
    ]);
    seed(&f, &path, true);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .args(["sync", "resolve", "--workspace"])
        .arg(&path)
        .arg("--dry-run")
        .env("AGENT_REMOTE_HOME", &f.home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Server sync operation completed; local Mutagen changes skipped"));
    assert!(!stdout.contains("flush completed"));
    let wires = f.wires();
    assert_eq!(wires.len(), 3);
    let body: Value = serde_json::from_str(wires[2].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["expected_target"]["id"], SYNC);
}

#[test]
fn sync_server_conflicted_state_remains_visible_and_can_be_reviewed_for_resolution() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let mut conflicted = data(&path, "conflicted");
    conflicted["conflict_status"] = json!("has_conflicts");
    let f = Fixture::new(vec![
        envelope(conflicted.clone()),
        envelope(conflicted),
        envelope(data(&path, "active")),
    ]);
    let target = seed(&f, &path, true);
    let (ok, status) = f.invoke(
        "sync.status",
        json!({"expected_context":f.context,"local_path":path}),
    );
    assert!(ok, "{status}");
    assert_eq!(status["result"]["sync"]["status"], "conflicted");
    assert_eq!(status["result"]["sync"]["conflict_status"], "has_conflicts");
    assert_eq!(status["result"]["target"], target);
    let (ok, response) = f.invoke("sync.resolve", input(&f, target, true));
    assert!(ok, "{response}");
    assert_eq!(response["result"]["outcome"], "completed");
    assert_eq!(response["result"]["sync"]["conflict_status"], "none");
    assert_eq!(f.wires().len(), 3);
}

#[test]
fn sync_ensure_reuses_prepared_legacy_healthy_and_conflicted_sessions_without_polling() {
    for (status, conflicts) in [("healthy", "none"), ("conflicted", "has_conflicts")] {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().canonicalize().unwrap();
        let identity = workspace::identify_workspace(Some(&path)).unwrap();
        let workspace = json!({"id":WS,"user_id":"secret-user-id","device_id":"device-test","project_key":identity.project_key,"local_start_path":path,"display_name":"test","remote_path":"/workspaces/test","sync_git":true,"created_at":"now","updated_at":"now"});
        let mut sync = data(&path, status);
        sync["conflict_status"] = json!(conflicts);
        let f = Fixture::new(vec![
            envelope(sync.clone()),
            envelope(workspace),
            envelope(sync),
        ]);
        let target = seed(&f, &path, true);
        let (ok, response) = f.invoke("sync.ensure", input(&f, target.clone(), true));
        assert!(ok, "{response}");
        let result = &response["result"];
        assert_eq!(result["outcome"], "completed");
        assert_eq!(result["target"], target);
        assert_eq!(result["result_target"], target);
        assert_eq!(result["sync"]["status"], status);
        assert_eq!(result["sync"]["conflict_status"], conflicts);
        let wires = f.wires();
        assert_eq!(
            wires.len(),
            3,
            "existing prepared target must not poll again"
        );
        assert!(wires[0].starts_with(&format!("GET /api/v1/sync-sessions/{SYNC} ")));
        assert!(wires[1].starts_with("POST /api/v1/workspaces "));
        assert!(wires[2].starts_with("POST /api/v1/sync-sessions "));
        let state = LocalState::open(&AppPaths::new(Some(f.home.clone())).unwrap()).unwrap();
        let stored = state.get_sync_session_for_workspace(WS).unwrap().unwrap();
        assert_eq!(stored.status, status);
        assert_eq!(stored.conflict_status, conflicts);
    }
}

#[test]
fn recovery_cas_never_erases_concurrent_or_additional_project_mappings() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![]);
    seed(&f, &path, true);
    let paths = AppPaths::new(Some(f.home.clone())).unwrap();
    let identity = workspace::identify_workspace(Some(&path)).unwrap();
    let server = f.context["server_url"].as_str().unwrap();
    let expected = LocalState::sync_snapshot(&paths, server, &identity.project_key).unwrap();
    let state = LocalState::open(&paths).unwrap();
    let mut additional = expected.sync.clone().unwrap();
    additional.id = "33333333-3333-4333-8333-333333333333".into();
    state.upsert_sync_session(&additional).unwrap();
    assert!(state
        .remove_sync_snapshot(server, &identity.project_key, &expected, true)
        .is_err());
    assert!(state.get_workspace_by_id(WS).unwrap().is_some());
    state.delete_sync_session(&additional.id).unwrap();
    let mut changed = expected.sync.clone().unwrap();
    changed.remote_endpoint = Some("new@127.0.0.1:/different".into());
    state.upsert_sync_session(&changed).unwrap();
    assert!(!state
        .remove_sync_snapshot(server, &identity.project_key, &expected, true)
        .unwrap());
    assert_eq!(
        state.get_sync_session_for_workspace(WS).unwrap().unwrap(),
        changed
    );
}

#[test]
fn recovery_cas_can_clear_only_sync_without_deleting_workspace_or_project_files() {
    for remove_workspace in [false, true] {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().canonicalize().unwrap();
        std::fs::write(path.join("keep.txt"), "keep both endpoints").unwrap();
        let f = Fixture::new(vec![]);
        seed(&f, &path, true);
        let paths = AppPaths::new(Some(f.home.clone())).unwrap();
        let identity = workspace::identify_workspace(Some(&path)).unwrap();
        let server = f.context["server_url"].as_str().unwrap();
        let expected = LocalState::sync_snapshot(&paths, server, &identity.project_key).unwrap();
        let state = LocalState::open(&paths).unwrap();
        let mut unrelated_workspace = expected.workspace.clone().unwrap();
        unrelated_workspace.id = "44444444-4444-4444-8444-444444444444".into();
        unrelated_workspace.project_key = "sha256:unrelated-project".into();
        unrelated_workspace.local_path = path.join("unrelated").to_string_lossy().into();
        state.upsert_workspace(&unrelated_workspace).unwrap();
        let mut unrelated_sync = expected.sync.clone().unwrap();
        unrelated_sync.id = "55555555-5555-4555-8555-555555555555".into();
        unrelated_sync.workspace_id = unrelated_workspace.id.clone();
        state.upsert_sync_session(&unrelated_sync).unwrap();
        assert!(state
            .remove_sync_snapshot(server, &identity.project_key, &expected, remove_workspace)
            .unwrap());
        assert_eq!(
            state.get_workspace_by_id(WS).unwrap().is_none(),
            remove_workspace
        );
        assert!(state.get_sync_session_for_workspace(WS).unwrap().is_none());
        assert_eq!(
            state.get_workspace_by_id(&unrelated_workspace.id).unwrap(),
            Some(unrelated_workspace.clone())
        );
        assert_eq!(
            state
                .get_sync_session_for_workspace(&unrelated_workspace.id)
                .unwrap(),
            Some(unrelated_sync)
        );
        assert_eq!(
            std::fs::read_to_string(path.join("keep.txt")).unwrap(),
            "keep both endpoints"
        );
        assert!(!state
            .remove_sync_snapshot(server, &identity.project_key, &expected, remove_workspace)
            .unwrap());
    }
}
