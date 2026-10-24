use super::*;
use serde_json::json;

fn sync() -> SyncSessionData {
    SyncSessionData {
        id: "s".into(),
        user_id: "u".into(),
        workspace_id: "w".into(),
        node_id: Some("n".into()),
        local_path: if cfg!(windows) {
            "C:\\project"
        } else {
            "/project"
        }
        .into(),
        remote_path: "/var/lib/agent-remote/users/u/workspaces/w/files".into(),
        status: "active".into(),
        conflict_status: "none".into(),
        sync_mode: "two_way".into(),
        sync_git: true,
        exclude: crate::workspace::DEFAULT_EXCLUDES
            .iter()
            .map(|s| s.to_string())
            .collect(),
        mutagen_session_id: Some("agent-remote-sync-test".into()),
        remote_endpoint: Some(
            "agent-remote@10.0.0.1:22:/var/lib/agent-remote/users/u/workspaces/w/files".into(),
        ),
        prepare_task_id: None,
        created_at: String::new(),
        updated_at: String::new(),
    }
}
fn public_model() -> serde_json::Value {
    let s = sync();
    json!({
        "identifier":"sync_ExampleIdentifier", "name":s.mutagen_session_id,
        "paused":false, "status":"watching", "mode":"two-way-safe", "successfulCycles":1,
        "ignore":{"paths":s.exclude}, "permissions":{"defaultFileMode":"0660","defaultDirectoryMode":"0770"},
        "alpha":{"protocol":"local","path":s.local_path,"connected":true,"scanned":true,"ignore":{},"permissions":{}},
        "beta":{"protocol":"ssh","user":"agent-remote","host":"10.0.0.1","port":22,"path":s.remote_path,"connected":true,"scanned":true}
    })
}

#[test]
fn structured_status_requires_a_completed_healthy_cycle_for_zero_conflicts() {
    let s = sync();
    let v = public_model();
    let obs = model::select(v.to_string().as_bytes(), &s)
        .unwrap()
        .unwrap()
        .observation();
    assert_eq!(obs.conflicts, "none_observed");
    assert_eq!(obs.conflict_count, Some(0));
    for (key, value) in [
        ("successfulCycles", json!(0)),
        ("lastError", json!("do not log file names")),
        ("paused", json!(true)),
        ("status", json!("scanning")),
    ] {
        let mut v = v.clone();
        v[key] = value;
        let obs = model::select(v.to_string().as_bytes(), &s)
            .unwrap()
            .unwrap()
            .observation();
        assert_eq!(obs.conflicts, "unknown");
        assert_eq!(obs.conflict_count, None);
    }
    let mut v = v;
    v["alpha"]["scanProblems"] = json!([{"path":"private","error":"private"}]);
    assert_eq!(
        model::select(v.to_string().as_bytes(), &s)
            .unwrap()
            .unwrap()
            .observation()
            .conflicts,
        "unknown"
    );
}

#[test]
fn structured_conflicts_include_truncated_count_without_project_content() {
    let mut v = public_model();
    v["conflicts"] = json!([{"alphaChanges":["private"]}]);
    v["excludedConflicts"] = json!(9);
    let obs = model::select(v.to_string().as_bytes(), &sync())
        .unwrap()
        .unwrap()
        .observation();
    assert_eq!(obs.conflicts, "detected");
    assert_eq!(obs.conflict_count, Some(10));
    assert!(!serde_json::to_string(&obs).unwrap().contains("private"));
}

#[test]
fn selection_rejects_duplicate_names_endpoint_drift_and_config_overrides() {
    let value = public_model().to_string();
    assert!(model::select(format!("{value}{value}").as_bytes(), &sync()).is_err());
    assert!(model::select(b"not JSON", &sync()).is_err());
    assert!(model::select(b" \n", &sync()).unwrap().is_none());
    for pointer in [
        "/identifier",
        "/name",
        "/alpha/path",
        "/beta/path",
        "/beta/host",
        "/beta/user",
        "/mode",
        "/permissions/defaultFileMode",
    ] {
        let mut v = public_model();
        *v.pointer_mut(pointer).unwrap() = json!("changed");
        assert!(
            model::select(v.to_string().as_bytes(), &sync()).is_err(),
            "{pointer}"
        );
    }
    let mut v = public_model();
    v["beta"]["permissions"] = json!({"defaultFileMode":"0777"});
    assert!(model::select(v.to_string().as_bytes(), &sync()).is_err());
    let mut v = public_model();
    v["ignore"]["paths"] = json!([]);
    assert!(model::select(v.to_string().as_bytes(), &sync()).is_err());
}

#[test]
fn target_validation_rejects_remote_flags_and_path_escape() {
    assert!(model::validate_target(&sync()).is_ok());
    for remote in [
        "-oProxyCommand=evil",
        "agent-remote@-host:22:/x",
        "root@10.0.0.1:22:/x",
    ] {
        let mut s = sync();
        s.remote_endpoint = Some(remote.into());
        assert!(model::validate_target(&s).is_err());
    }
    let mut s = sync();
    s.mutagen_session_id = Some("--all".into());
    assert!(model::validate_target(&s).is_err());
    let mut s = sync();
    s.remote_path = "/a/../escape".into();
    s.remote_endpoint = Some("agent-remote@host:22:/a/../escape".into());
    assert!(model::validate_target(&s).is_err());
}

#[test]
fn custom_node_ssh_user_is_bound_to_the_observed_endpoint() {
    let mut s = sync();
    s.remote_endpoint = s
        .remote_endpoint
        .map(|v| v.replacen("agent-remote@", "managed-sync@", 1));
    assert!(model::validate_target(&s).is_ok());
    let mut value = public_model();
    assert!(model::select(value.to_string().as_bytes(), &s).is_err());
    value["beta"]["user"] = json!("managed-sync");
    assert!(model::select(value.to_string().as_bytes(), &s).is_ok());
}

#[cfg(unix)]
fn fake_binary(script: &str) -> (tempfile::TempDir, AppPaths) {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(temp.path().join("home"));
    std::fs::create_dir_all(paths.bin_dir()).unwrap();
    let binary = crate::platform::managed_binary(&paths.bin_dir(), "mutagen");
    std::fs::write(&binary, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    (temp, paths)
}

#[cfg(unix)]
#[tokio::test]
async fn transient_client_is_bounded_sanitized_and_cannot_autostart_daemon() {
    let (_temp, paths) =
        fake_binary("test \"$MUTAGEN_DISABLE_AUTOSTART\" = 1 || exit 4\nprintf 'safe'");
    assert_eq!(
        process::run(
            &paths,
            &["sync", "list"],
            Duration::from_secs(2),
            false,
            false
        )
        .await
        .unwrap(),
        b"safe"
    );
    let (_temp, paths) = fake_binary("printf 'private error' >&2\nexit 4");
    let e = process::run(
        &paths,
        &["sync", "pause"],
        Duration::from_secs(2),
        true,
        false,
    )
    .await
    .unwrap_err();
    assert!(e.may_have_changed());
    assert!(!e.to_string().contains("private"));
    let (_temp,paths)=fake_binary("while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done");
    let e = process::run(
        &paths,
        &["sync", "list"],
        Duration::from_secs(3),
        false,
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(e.code(), "sync_mutagen_output_limit");
    assert!(!e.may_have_changed());
    let (_temp, paths) = fake_binary("exec sleep 30");
    let began = std::time::Instant::now();
    let e = process::run(
        &paths,
        &["sync", "flush"],
        Duration::from_millis(75),
        true,
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(e.code(), "sync_mutagen_timeout");
    assert!(e.may_have_changed());
    assert!(began.elapsed() < Duration::from_secs(3));
}

#[cfg(unix)]
#[tokio::test]
async fn cancellation_reaps_transient_client_descendants() {
    let (_temp, paths) =
        fake_binary("sleep 30 &\necho \"$!\" > \"$AGENT_REMOTE_HOME/child.pid\"\nwait");
    let child_paths = paths.clone();
    let operation = tokio::spawn(async move {
        process::run(
            &child_paths,
            &["sync", "flush"],
            Duration::from_secs(30),
            true,
            false,
        )
        .await
    });
    let marker = paths.home().join("child.pid");
    for _ in 0..200 {
        if marker.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    let pid: u32 = std::fs::read_to_string(marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    for _ in 0..200 {
        let state = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&state.stdout);
        if state.trim().is_empty() || state.trim().starts_with('Z') {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("transient descendant survived operation cancellation");
}
