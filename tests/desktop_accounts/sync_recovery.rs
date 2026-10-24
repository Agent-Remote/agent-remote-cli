use super::{
    fixture::*,
    sync::{seed, SYNC, WS},
};
use agent_remote_cli::{config::AppPaths, local_state::LocalState, workspace};
use serde_json::{json, Value};
fn missing() -> Reply {
    Reply::json(404, json!({"detail":"secret-server-diagnostics"}))
}
fn workspace_reply(path: &std::path::Path) -> Reply {
    let identity = workspace::identify_workspace(Some(path)).unwrap();
    envelope(
        json!({"id":WS,"user_id":"secret-user-id","device_id":"device-test","project_key":identity.project_key,"local_start_path":path,"display_name":"test","remote_path":"/workspaces/test","created_at":"now","updated_at":"now"}),
    )
}
fn preview(f: &Fixture, path: &std::path::Path) -> (bool, Value) {
    f.invoke(
        "sync.recovery.preview",
        json!({"expected_context":f.context,"local_path":path}),
    )
}
#[test]
fn recovery_preview_requires_exact_missing_resource_and_never_mutates() {
    for (status, code) in [
        (403, "permission_denied"),
        (401, "authentication_required"),
        (503, "server_unavailable"),
        (200, "sync_response_invalid"),
    ] {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().canonicalize().unwrap();
        let f = Fixture::new(vec![Reply::json(
            status,
            json!({"detail":"secret-server-diagnostics"}),
        )]);
        seed(&f, &path, true);
        let paths = AppPaths::new(Some(f.home.clone())).unwrap();
        let before = std::fs::read(paths.state_db_path()).unwrap();
        let (ok, result) = preview(&f, &path);
        assert!(!ok, "{result}");
        assert_eq!(result["error"]["code"], code);
        assert_eq!(f.wires().len(), 1);
        assert_eq!(before, std::fs::read(paths.state_db_path()).unwrap());
        assert!(!result.to_string().contains("secret-server"));
    }
}
#[test]
fn recovery_preview_keeps_original_mapping_and_blocks_unknown_local_session() {
    for workspace_missing in [false, true] {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().canonicalize().unwrap();
        let f = Fixture::new(vec![
            missing(),
            if workspace_missing {
                missing()
            } else {
                workspace_reply(&path)
            },
        ]);
        seed(&f, &path, true);
        let paths = AppPaths::new(Some(f.home.clone())).unwrap();
        let before = std::fs::read(paths.state_db_path()).unwrap();
        let (ok, response) = preview(&f, &path);
        assert!(ok, "{response}");
        let plan = &response["result"];
        assert_eq!(plan["target"]["sync_session_id"], SYNC);
        assert!(plan["target"]["fingerprint"].is_null());
        assert_eq!(plan["mapping"]["sync"]["id"], SYNC);
        assert_eq!(plan["mapping"]["workspace"]["id"], WS);
        assert_eq!(
            plan["server_state"],
            if workspace_missing {
                "workspace_not_found"
            } else {
                "sync_not_found"
            }
        );
        assert_eq!(plan["recoverable"], false);
        assert!(plan["mapping_fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(before, std::fs::read(paths.state_db_path()).unwrap());
        assert!(!paths.ssh_dir().join("mutagen-environment").exists());
        assert_eq!(f.wires().len(), 2);
        redact(&response);
    }
}
#[test]
fn recovery_workspace_auth_failure_is_never_absence() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![
        missing(),
        Reply::json(403, json!({"detail":"denied"})),
    ]);
    seed(&f, &path, true);
    let (ok, response) = preview(&f, &path);
    assert!(!ok);
    assert_eq!(response["error"]["code"], "permission_denied");
    let state = LocalState::open(&AppPaths::new(Some(f.home.clone())).unwrap()).unwrap();
    assert!(state.get_sync_session_for_workspace(WS).unwrap().is_some());
}

#[cfg(unix)]
fn managed_mutagen(f: &Fixture, path: &std::path::Path, exists: bool) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let paths = AppPaths::new(Some(f.home.clone())).unwrap();
    let state = LocalState::open(&paths).unwrap();
    let mut sync = state.get_sync_session_for_workspace(WS).unwrap().unwrap();
    sync.remote_endpoint = Some("test@127.0.0.1:22:/workspaces/test".into());
    state.upsert_sync_session(&sync).unwrap();
    std::fs::create_dir_all(paths.bin_dir()).unwrap();
    let data = f._temp.path().join("mutagen-data");
    std::fs::create_dir_all(data.join("daemon")).unwrap();
    let model = json!({"identifier":"sync_ReviewedSession","name":"ar-sync-test","mode":"two-way-safe","alpha":{"protocol":"local","path":path},"beta":{"protocol":"ssh","path":"/workspaces/test","host":"127.0.0.1","user":"test","port":22},"ignore":{"paths":[".git/index"]},"permissions":{"defaultFileMode":"0660","defaultDirectoryMode":"0770"},"paused":false,"status":"watching"});
    if exists {
        std::fs::write(data.join("session.json"), model.to_string()).unwrap();
    }
    let binary = paths.bin_dir().join("mutagen");
    std::fs::write(&binary,r#"#!/bin/sh
set -eu
[ "$MUTAGEN_DISABLE_AUTOSTART" = 1 ] || exit 71
printf '%s\n' "$*" >> "$MUTAGEN_DATA_DIRECTORY/invocations"
case "$1 $2" in
  'sync list')
    if [ -f "$MUTAGEN_DATA_DIRECTORY/session.json" ]; then cat "$MUTAGEN_DATA_DIRECTORY/session.json"; fi
    ;;
  'sync terminate')
    [ "$3" = -- ] && [ "$4" = sync_ReviewedSession ] || exit 72
    if [ -f "$MUTAGEN_DATA_DIRECTORY/fail-terminate" ]; then exit 73; fi
    rm "$MUTAGEN_DATA_DIRECTORY/session.json"
    ;;
  *) exit 74 ;;
esac
"#).unwrap();
    std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    data
}
#[cfg(unix)]
fn invoke_isolated(
    f: &Fixture,
    data: &std::path::Path,
    method: &str,
    params: Value,
) -> (bool, Value) {
    use std::io::Write;
    let mut child = command(&f.home)
        .env("MUTAGEN_DATA_DIRECTORY", data)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request(method, params))
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}
#[cfg(unix)]
#[test]
fn recovery_only_terminates_reviewed_session_and_clears_exact_missing_mapping() {
    for exists in [false, true] {
        for workspace_missing in [false, true] {
            let project = tempfile::tempdir().unwrap();
            let path = project.path().canonicalize().unwrap();
            std::fs::write(path.join("preserved"), "local project data").unwrap();
            let f = Fixture::new(vec![
                missing(),
                if workspace_missing {
                    missing()
                } else {
                    workspace_reply(&path)
                },
                missing(),
                if workspace_missing {
                    missing()
                } else {
                    workspace_reply(&path)
                },
            ]);
            seed(&f, &path, true);
            let data = managed_mutagen(&f, &path, exists);
            let (ok, response) = invoke_isolated(
                &f,
                &data,
                "sync.recovery.preview",
                json!({"expected_context":f.context,"local_path":path}),
            );
            assert!(ok, "{response}");
            let plan = response["result"].clone();
            assert_eq!(plan["recoverable"], true, "{plan}");
            let (ok, response) = invoke_isolated(
                &f,
                &data,
                "sync.recovery.apply",
                json!({"expected_context":f.context,"confirmed":true,"expected_plan":plan}),
            );
            assert!(ok, "{response}");
            let receipt = &response["result"];
            assert_eq!(receipt["outcome"], "completed", "{receipt}");
            assert_eq!(receipt["plan"], plan);
            assert!(receipt["result_target"]["sync_session_id"].is_null());
            assert_eq!(
                receipt["result_target"]["workspace_id"].is_null(),
                workspace_missing
            );
            let state = LocalState::open(&AppPaths::new(Some(f.home.clone())).unwrap()).unwrap();
            assert!(state.get_sync_session_for_workspace(WS).unwrap().is_none());
            assert_eq!(
                state.get_workspace_by_id(WS).unwrap().is_none(),
                workspace_missing
            );
            assert_eq!(
                std::fs::read_to_string(path.join("preserved")).unwrap(),
                "local project data"
            );
            let calls = std::fs::read_to_string(data.join("invocations")).unwrap();
            assert_eq!(
                calls
                    .lines()
                    .filter(|line| line.starts_with("sync terminate"))
                    .count(),
                usize::from(exists)
            );
            assert!(!calls.contains("daemon"));
            assert_eq!(f.wires().len(), 4);
        }
    }
}
#[cfg(unix)]
#[test]
fn recovery_failed_local_termination_retains_mapping_and_unknown_receipt() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![missing(), missing(), missing(), missing()]);
    seed(&f, &path, true);
    let data = managed_mutagen(&f, &path, true);
    let (_, response) = invoke_isolated(
        &f,
        &data,
        "sync.recovery.preview",
        json!({"expected_context":f.context,"local_path":path}),
    );
    let plan = response["result"].clone();
    std::fs::write(data.join("fail-terminate"), "").unwrap();
    let (ok, response) = invoke_isolated(
        &f,
        &data,
        "sync.recovery.apply",
        json!({"expected_context":f.context,"confirmed":true,"expected_plan":plan}),
    );
    assert!(ok, "{response}");
    assert_eq!(response["result"]["outcome"], "unknown");
    assert_eq!(response["result"]["plan"], plan);
    let state = LocalState::open(&AppPaths::new(Some(f.home.clone())).unwrap()).unwrap();
    assert!(state.get_sync_session_for_workspace(WS).unwrap().is_some());
    assert!(data.join("session.json").exists());
    let calls = std::fs::read_to_string(data.join("invocations")).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("sync terminate"))
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn recovery_changed_local_identifier_or_mapping_never_targets_replacement() {
    for change_mapping in [false, true] {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().canonicalize().unwrap();
        let replies = if change_mapping {
            vec![missing(), missing()]
        } else {
            vec![missing(), missing(), missing(), missing()]
        };
        let f = Fixture::new(replies);
        seed(&f, &path, true);
        let data = managed_mutagen(&f, &path, true);
        let (_, response) = invoke_isolated(
            &f,
            &data,
            "sync.recovery.preview",
            json!({"expected_context":f.context,"local_path":path}),
        );
        let plan = response["result"].clone();
        let state = LocalState::open(&AppPaths::new(Some(f.home.clone())).unwrap()).unwrap();
        if change_mapping {
            let mut next = state.get_sync_session_for_workspace(WS).unwrap().unwrap();
            next.remote_endpoint = Some("new@127.0.0.1:22:/changed".into());
            state.upsert_sync_session(&next).unwrap();
        } else {
            let mut model: Value =
                serde_json::from_slice(&std::fs::read(data.join("session.json")).unwrap()).unwrap();
            model["identifier"] = json!("sync_Replacement");
            std::fs::write(data.join("session.json"), model.to_string()).unwrap();
        }
        let (ok, response) = invoke_isolated(
            &f,
            &data,
            "sync.recovery.apply",
            json!({"expected_context":f.context,"confirmed":true,"expected_plan":plan}),
        );
        if change_mapping {
            assert!(!ok);
            assert_eq!(response["error"]["code"], "sync_target_changed");
        } else {
            assert!(ok);
            assert_eq!(response["result"]["outcome"], "partial");
        }
        assert!(state.get_sync_session_for_workspace(WS).unwrap().is_some());
        assert!(data.join("session.json").exists());
        assert!(!std::fs::read_to_string(data.join("invocations"))
            .unwrap()
            .contains("sync terminate"));
    }
}
#[cfg(unix)]
#[test]
fn recovery_stopped_daemon_does_not_allow_forgetting_an_existing_relationship() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![missing(), missing()]);
    seed(&f, &path, true);
    let data = managed_mutagen(&f, &path, true);
    std::fs::remove_dir(data.join("daemon")).unwrap();
    let (ok, response) = invoke_isolated(
        &f,
        &data,
        "sync.recovery.preview",
        json!({"expected_context":f.context,"local_path":path}),
    );
    assert!(ok, "{response}");
    assert_eq!(response["result"]["recoverable"], false);
    assert_eq!(response["result"]["mutagen"]["state"], "unavailable");
    assert!(data.join("session.json").exists());
    assert!(!data.join("invocations").exists());
}

#[cfg(unix)]
#[test]
fn human_ensure_recovery_requires_its_own_confirmation_and_never_creates_replacement() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    for confirmed in [false, true] {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().canonicalize().unwrap();
        let replies = if confirmed {
            vec![missing(), missing(), missing(), missing(), missing()]
        } else {
            vec![missing(), missing(), missing()]
        };
        let f = Fixture::new(replies);
        seed(&f, &path, true);
        let data = managed_mutagen(&f, &path, true);
        let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
            .args(["sync", "ensure", "--yes", "--workspace"])
            .arg(&path)
            .env("AGENT_REMOTE_HOME", &f.home)
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .env("MUTAGEN_DATA_DIRECTORY", &data)
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(if confirmed { b"yes\n" } else { b"no\n" })
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.success(),
            confirmed,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Remove this exact obsolete local sync relationship?"));
        assert!(stdout.contains("test@127.0.0.1:22:/workspaces/test"));
        assert!(f.wires().iter().all(|wire| wire.starts_with("GET ")));
        let state = LocalState::open(&AppPaths::new(Some(f.home.clone())).unwrap()).unwrap();
        assert_eq!(
            state.get_sync_session_for_workspace(WS).unwrap().is_none(),
            confirmed
        );
        if confirmed {
            assert!(stdout.contains("Run agent-remote sync ensure again"));
        }
    }
}

#[cfg(unix)]
#[test]
fn recovery_rejects_unconfirmed_or_incomplete_plan_without_new_requests() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().canonicalize().unwrap();
    let f = Fixture::new(vec![missing(), missing()]);
    seed(&f, &path, true);
    let data = managed_mutagen(&f, &path, true);
    let (_, response) = invoke_isolated(
        &f,
        &data,
        "sync.recovery.preview",
        json!({"expected_context":f.context,"local_path":path}),
    );
    let plan = response["result"].clone();
    let (ok, response) = invoke_isolated(
        &f,
        &data,
        "sync.recovery.apply",
        json!({"expected_context":f.context,"confirmed":false,"expected_plan":plan}),
    );
    assert!(!ok);
    assert_eq!(response["error"]["code"], "confirmation_required");
    let mut malformed = plan.clone();
    malformed["mapping"]["sync"]
        .as_object_mut()
        .unwrap()
        .remove("node_id");
    let (ok, response) = invoke_isolated(
        &f,
        &data,
        "sync.recovery.apply",
        json!({"expected_context":f.context,"confirmed":true,"expected_plan":malformed}),
    );
    assert!(!ok);
    assert_eq!(response["error"]["code"], "invalid_params");
    assert_eq!(f.wires().len(), 2);
    assert!(data.join("session.json").exists());
}
