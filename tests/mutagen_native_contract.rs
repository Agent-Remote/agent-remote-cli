//! Opt-in native Mutagen protocol probe, isolated from the developer's daemon.
#![cfg(unix)]
use agent_remote_cli::{
    api::SyncSessionData, config::AppPaths, mutagen::desktop, workspace::DEFAULT_EXCLUDES,
};
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

struct Daemon {
    binary: PathBuf,
    data: PathBuf,
}
impl Daemon {
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(&self.binary)
            .args(args)
            .env("MUTAGEN_DATA_DIRECTORY", &self.data)
            .env("MUTAGEN_DISABLE_AUTOSTART", "1")
            .env("MUTAGEN_SSH_PATH", self.binary.parent().unwrap())
            .output()
            .unwrap()
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.run(&["daemon", "stop"]);
    }
}

#[tokio::test]
async fn native_public_model_read_only_inspection_and_exact_session_pause() {
    let Some(binary) = std::env::var_os("AGENT_REMOTE_TEST_MUTAGEN") else {
        return;
    };
    if let Some(root) = std::env::var_os("AGENT_REMOTE_TEST_MUTAGEN_NATIVE_CHILD") {
        exercise(Path::new(&root), Path::new(&binary)).await;
        return;
    }
    // Child-only environment prevents touching the developer's daemon/launchd.
    let root = tempfile::Builder::new()
        .prefix("ar-mtg-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = root.path().join("os-home");
    std::fs::create_dir(&home).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_public_model_read_only_inspection_and_exact_session_pause",
            "--nocapture",
        ])
        .env("HOME", home)
        .env("MUTAGEN_DATA_DIRECTORY", root.path().join("data"))
        .env("AGENT_REMOTE_TEST_MUTAGEN_NATIVE_CHILD", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("running 1 test"));
}

async fn repair(paths: &AppPaths) {
    let plan = desktop::environment::preview(paths).await.unwrap();
    let receipt = desktop::environment::apply(paths, &plan.fingerprint)
        .await
        .unwrap();
    assert_eq!(receipt.outcome, "completed", "{:?}", receipt.error_code);
}

async fn exercise(root: &Path, binary: &Path) {
    let data = root.join("data");
    let paths = AppPaths::new(Some(root.join("home"))).unwrap();
    std::fs::create_dir_all(paths.bin_dir()).unwrap();
    symlink(binary, paths.bin_dir().join("mutagen")).unwrap();
    for proxy in ["ssh", "scp"] {
        let path = paths.bin_dir().join(proxy);
        std::fs::write(&path, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let local = root.join("project");
    std::fs::create_dir(&local).unwrap();
    let sync = SyncSessionData {
        id: "sync-test".into(),
        user_id: "u".into(),
        workspace_id: "w".into(),
        node_id: Some("n".into()),
        local_path: local.canonicalize().unwrap().to_str().unwrap().into(),
        remote_path: "/var/lib/agent-remote/probe".into(),
        status: "active".into(),
        conflict_status: "none".into(),
        sync_mode: "two_way".into(),
        sync_git: true,
        exclude: DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect(),
        mutagen_session_id: Some("agent-remote-native-probe".into()),
        remote_endpoint: Some("agent-remote@127.0.0.1:22:/var/lib/agent-remote/probe".into()),
        prepare_task_id: None,
        created_at: String::new(),
        updated_at: String::new(),
    };
    assert_eq!(
        desktop::inspect(&paths, &sync).await.unwrap().state,
        "unavailable"
    );
    assert!(!data.exists());
    assert!(!paths.ssh_dir().exists());
    let daemon = Daemon {
        binary: paths.bin_dir().join("mutagen"),
        data,
    };
    let mut original = Command::new(&daemon.binary)
        .args(["daemon", "run"])
        .env("MUTAGEN_DATA_DIRECTORY", &daemon.data)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut ready = false;
    for _ in 0..40 {
        if daemon
            .run(&["sync", "list", "--template", "{{len .}} "])
            .status
            .success()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ready);
    let mut args = vec![
        "sync",
        "create",
        "--paused",
        "--no-global-configuration",
        "--sync-mode",
        "two-way-safe",
        "--name",
        "agent-remote-native-probe",
        "--default-file-mode",
        "0660",
        "--default-directory-mode",
        "0770",
    ];
    for ignore in DEFAULT_EXCLUDES {
        args.extend(["--ignore", ignore]);
    }
    args.extend([
        "--",
        &sync.local_path,
        sync.remote_endpoint.as_deref().unwrap(),
    ]);
    assert!(daemon.run(&args).status.success());
    let observation = desktop::inspect(&paths, &sync).await.unwrap();
    assert_eq!(observation.state, "available");
    assert_eq!(observation.paused, Some(true));
    assert_eq!(observation.conflicts, "unknown");
    assert!(
        !paths.ssh_dir().exists(),
        "query must not initialize managed SSH state"
    );
    let error = desktop::apply(&paths, &sync, "pause", false)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "sync_mutagen_environment_mismatch");
    assert!(!error.may_have_changed());
    repair(&paths).await;
    assert!(original.wait().unwrap().success());
    assert_eq!(
        desktop::apply(&paths, &sync, "pause", false)
            .await
            .unwrap()
            .paused,
        Some(true)
    );
    let error = desktop::apply(&paths, &sync, "resolve", false)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "sync_mutagen_not_running");
    assert!(!error.may_have_changed());
    let mut drifted = sync.clone();
    drifted.remote_endpoint = Some("agent-remote@127.0.0.2:22:/var/lib/agent-remote/probe".into());
    assert_eq!(
        desktop::apply(&paths, &drifted, "pause", false)
            .await
            .unwrap_err()
            .code(),
        "sync_mutagen_target_changed"
    );
    assert!(daemon.run(&args).status.success());
    assert_eq!(
        desktop::apply(&paths, &sync, "pause", false)
            .await
            .unwrap_err()
            .code(),
        "sync_mutagen_ambiguous"
    );

    let Some(agent) = std::env::var_os("AGENT_REMOTE_TEST_MUTAGEN_AGENT") else {
        return;
    };
    symlink(
        Path::new(&agent),
        paths.bin_dir().join("test-mutagen-agent"),
    )
    .unwrap();
    // Exercise the real synchronization protocol locally. This shim never runs
    // the supplied SSH command or opens a socket; only the pinned test agent runs.
    std::fs::write(
        paths.bin_dir().join("ssh"),
        "#!/bin/sh\nexec \"$MUTAGEN_SSH_PATH/test-mutagen-agent\" synchronizer\n",
    )
    .unwrap();
    repair(&paths).await;
    let remote = root.join("remote");
    std::fs::create_dir(&remote).unwrap();
    let mut sync = sync;
    sync.remote_path = remote.canonicalize().unwrap().to_str().unwrap().to_string();
    sync.remote_endpoint = Some(format!("agent-remote@127.0.0.1:22:{}", sync.remote_path));
    sync.mutagen_session_id = Some("agent-remote-native-transfer".into());
    std::fs::write(local.join("hello.txt"), "from local\n").unwrap();
    assert_eq!(
        desktop::apply(&paths, &sync, "ensure", false)
            .await
            .unwrap()
            .state,
        "available"
    );
    assert_eq!(
        std::fs::read_to_string(remote.join("hello.txt")).unwrap(),
        "from local\n"
    );
    assert_eq!(
        desktop::apply(&paths, &sync, "pause", false)
            .await
            .unwrap()
            .paused,
        Some(true)
    );
    std::fs::write(remote.join("reply.txt"), "from peer\n").unwrap();
    assert!(!local.join("reply.txt").exists());
    assert_eq!(
        desktop::apply(&paths, &sync, "resume", false)
            .await
            .unwrap()
            .paused,
        Some(false)
    );
    assert_eq!(
        desktop::apply(&paths, &sync, "resolve", false)
            .await
            .unwrap()
            .conflicts,
        "none_observed"
    );
    assert_eq!(
        std::fs::read_to_string(local.join("reply.txt")).unwrap(),
        "from peer\n"
    );
    assert_eq!(
        desktop::apply(&paths, &sync, "reset", false)
            .await
            .unwrap()
            .state,
        "available"
    );
    assert_eq!(
        std::fs::read_to_string(remote.join("hello.txt")).unwrap(),
        "from local\n"
    );
    assert_eq!(
        std::fs::read_to_string(local.join("reply.txt")).unwrap(),
        "from peer\n"
    );

    assert_eq!(
        desktop::apply(&paths, &sync, "pause", false)
            .await
            .unwrap()
            .paused,
        Some(true)
    );
    std::fs::write(local.join("hello.txt"), "local conflict\n").unwrap();
    std::fs::write(remote.join("hello.txt"), "remote conflict\n").unwrap();
    desktop::apply(&paths, &sync, "resume", false)
        .await
        .unwrap();
    let error = desktop::apply(&paths, &sync, "resolve", false)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "sync_conflicts_remaining");
    assert_eq!(
        desktop::inspect(&paths, &sync).await.unwrap().conflicts,
        "detected"
    );
    assert_eq!(
        std::fs::read_to_string(local.join("hello.txt")).unwrap(),
        "local conflict\n"
    );
    assert_eq!(
        std::fs::read_to_string(remote.join("hello.txt")).unwrap(),
        "remote conflict\n"
    );

    let planned = desktop::inspect_recovery(
        &paths,
        &sync.local_path,
        Some(&sync.remote_path),
        sync.mutagen_session_id.as_deref(),
        sync.remote_endpoint.as_deref(),
    )
    .await
    .unwrap();
    assert!(planned.recoverable);
    assert_eq!(planned.state, "available");
    // A busy/paused state change does not change the immutable reviewed target.
    desktop::apply(&paths, &sync, "pause", false).await.unwrap();
    let mut wrong = planned.clone();
    wrong.target.as_mut().unwrap().configuration_fingerprint = "sha256:changed".into();
    let error = desktop::terminate_recovery(
        &paths,
        &sync.local_path,
        Some(&sync.remote_path),
        sync.mutagen_session_id.as_deref(),
        sync.remote_endpoint.as_deref(),
        &wrong,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "sync_mutagen_target_changed");
    assert!(!error.may_have_changed());
    // Exact recovery termination doesn't repair or rewrite a mismatched v2 marker.
    let marker_path = daemon.data.join("agent-remote-environment.json");
    let mut marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker_path).unwrap()).unwrap();
    marker["binding"]["fingerprint"] = format!("sha256:{}", "0".repeat(64)).into();
    let mismatched_marker = serde_json::to_vec(&marker).unwrap();
    std::fs::write(&marker_path, &mismatched_marker).unwrap();
    let after = desktop::terminate_recovery(
        &paths,
        &sync.local_path,
        Some(&sync.remote_path),
        sync.mutagen_session_id.as_deref(),
        sync.remote_endpoint.as_deref(),
        &planned,
    )
    .await
    .unwrap();
    assert!(after.recoverable);
    assert_eq!(after.state, "session_missing");
    assert_eq!(std::fs::read(&marker_path).unwrap(), mismatched_marker);
    assert_eq!(
        std::fs::read_to_string(local.join("hello.txt")).unwrap(),
        "local conflict\n"
    );
    assert_eq!(
        std::fs::read_to_string(remote.join("hello.txt")).unwrap(),
        "remote conflict\n"
    );
    // The two unrelated paused sessions survive exact identifier termination.
    assert_eq!(
        String::from_utf8(
            daemon
                .run(&["sync", "list", "--template", "{{len .}}"])
                .stdout
        )
        .unwrap()
        .trim(),
        "2"
    );
    assert!(daemon.run(&["daemon", "stop"]).status.success());
    let stopped = desktop::inspect_recovery(
        &paths,
        &sync.local_path,
        Some(&sync.remote_path),
        sync.mutagen_session_id.as_deref(),
        sync.remote_endpoint.as_deref(),
    )
    .await
    .unwrap();
    assert_eq!(stopped.state, "unavailable");
    assert!(!stopped.recoverable);
}
