use super::*;

#[tokio::test]
async fn recovery_namespace_binds_native_directory_identity() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let before = namespace_fingerprint(&data).await.unwrap();
    assert_eq!(namespace_fingerprint(&data).await.unwrap(), before);
    std::fs::rename(&data, root.path().join("original")).unwrap();
    std::fs::create_dir(&data).unwrap();
    assert_ne!(namespace_fingerprint(&data).await.unwrap(), before);
}

fn session() -> Value {
    json!({
        "identifier":"sync_RecoveryIdentifier", "name":"agent-remote-recovery",
        "version":1,"creationTime":"2026-10-18T00:00:00Z","creatingVersion":"0.18.1",
        "mode":"two-way-safe","paused":true,"status":"disconnected",
        "ignore":{"paths":["private-exclusion"]},
        "alpha":{"protocol":"local","path":"/project","connected":false},
        "beta":{"protocol":"ssh","path":"/remote","user":"agent-remote","host":"localhost","port":22,"connected":false}
    })
}

fn target(value: &Value) -> Result<Option<RecoveryTarget>> {
    select(
        value.to_string().as_bytes(),
        "/project",
        "/remote",
        "agent-remote-recovery",
        "agent-remote@localhost:22:/remote",
    )
}

#[test]
fn recovery_freezes_configuration_without_leaking_content_or_runtime_changes() {
    let original = target(&session()).unwrap().unwrap();
    assert!(!serde_json::to_string(&original)
        .unwrap()
        .contains("private-exclusion"));
    let mut observed = session();
    observed["paused"] = json!(false);
    observed["status"] = json!("watching");
    observed["successfulCycles"] = json!(15);
    observed["lastError"] = json!("private error");
    observed["conflicts"] = json!([{"private file":"private bytes"}]);
    observed["beta"]["connected"] = json!(true);
    observed["beta"]["scanProblems"] = json!(["private scan"]);
    assert_eq!(target(&observed).unwrap().unwrap(), original);
    for (key, value) in [
        ("mode", json!("one-way-replica")),
        ("ignore", json!({"paths":[]})),
        ("futureConfig", json!({"value":1})),
        ("identifier", json!("sync_Replacement")),
    ] {
        let mut changed = session();
        changed[key] = value;
        assert_ne!(target(&changed).unwrap().unwrap(), original, "{key}");
    }
    let mut changed = session();
    changed["beta"]["environment"] = json!({"SECRET":"never-export"});
    let changed = target(&changed).unwrap().unwrap();
    assert_ne!(changed, original);
    assert!(!serde_json::to_string(&changed)
        .unwrap()
        .contains("never-export"));
}

#[test]
fn recovery_rejects_name_ambiguity_and_endpoint_drift() {
    for pointer in [
        "/identifier",
        "/name",
        "/alpha/protocol",
        "/alpha/path",
        "/beta/path",
        "/beta/user",
        "/beta/host",
        "/beta/port",
    ] {
        let mut changed = session();
        *changed.pointer_mut(pointer).unwrap() = json!("changed");
        assert!(target(&changed).is_err(), "{pointer}");
    }
    let bytes = format!("{}{}", session(), session());
    assert_eq!(
        select(
            bytes.as_bytes(),
            "/project",
            "/remote",
            "agent-remote-recovery",
            "agent-remote@localhost:22:/remote"
        )
        .unwrap_err()
        .code(),
        "sync_mutagen_ambiguous"
    );
    assert!(select(
        b" \n",
        "/project",
        "/remote",
        "agent-remote-recovery",
        "agent-remote@localhost:22:/remote"
    )
    .unwrap()
    .is_none());
    assert!(select(
        b"not JSON",
        "/project",
        "/remote",
        "agent-remote-recovery",
        "agent-remote@localhost:22:/remote"
    )
    .is_err());
}

#[tokio::test]
async fn incomplete_metadata_and_missing_tools_never_prove_absence() {
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(root.path().join("home"));
    let local = root.path().to_str().unwrap();
    let missing = inspect_recovery(&paths, local, None, None, None)
        .await
        .unwrap();
    assert_eq!(missing.state, "blocked");
    assert!(!missing.recoverable);
    let missing = inspect_recovery(
        &paths,
        local,
        Some("/remote"),
        Some("agent-remote-recovery"),
        Some("agent-remote@localhost:22:/remote"),
    )
    .await
    .unwrap();
    assert_eq!(missing.state, "missing");
    assert!(!missing.recoverable);
    assert!(!paths.home().exists());
}
