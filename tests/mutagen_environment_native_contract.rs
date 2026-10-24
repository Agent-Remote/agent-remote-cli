//! Real daemon-wide recovery, with all process environment/state isolated in a child.
#![cfg(unix)]
use agent_remote_cli::{config::AppPaths, mutagen::desktop::environment};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

struct Daemon {
    binary: PathBuf,
    data: PathBuf,
}
impl Daemon {
    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .args(arguments)
            .env("MUTAGEN_DATA_DIRECTORY", &self.data)
            .env("MUTAGEN_DISABLE_AUTOSTART", "1");
        command
    }
    fn run(&self, arguments: &[&str]) -> std::process::Output {
        self.command(arguments).output().unwrap()
    }
    fn success(&self, arguments: &[&str]) {
        let output = self.run(arguments);
        assert!(
            output.status.success(),
            "official Mutagen {:?}: {}",
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.run(&["daemon", "stop"]);
    }
}

fn disk(path: &Path) -> BTreeMap<PathBuf, (u64, u64, i64, i64, String)> {
    fn walk(
        root: &Path,
        current: &Path,
        result: &mut BTreeMap<PathBuf, (u64, u64, i64, i64, String)>,
    ) {
        let metadata = fs::symlink_metadata(current).unwrap();
        let digest = if metadata.is_file() {
            format!("{:x}", Sha256::digest(fs::read(current).unwrap()))
        } else {
            String::new()
        };
        result.insert(
            current.strip_prefix(root).unwrap().into(),
            (
                metadata.dev(),
                metadata.ino(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                digest,
            ),
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(current).unwrap() {
                walk(root, &entry.unwrap().path(), result);
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(path, path, &mut result);
    result
}

fn legacy_rejected(paths: &AppPaths) {
    let error = agent_remote_cli::mutagen::terminate_session(paths, "absent-native-fixture", false)
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("sync_mutagen_environment_mismatch"),
        "{error:#}"
    );
}

async fn stale_rejected(paths: &AppPaths, plan: &environment::Plan) {
    assert_eq!(
        environment::apply(paths, &plan.fingerprint)
            .await
            .unwrap_err()
            .code(),
        "sync_mutagen_environment_changed"
    );
}

#[tokio::test]
async fn native_stopped_inventory_and_confirmed_daemon_environment_restart() {
    let Some(binary) = std::env::var_os("AGENT_REMOTE_TEST_MUTAGEN") else {
        return;
    };
    if let Some(root) = std::env::var_os("AGENT_REMOTE_TEST_MUTAGEN_ENVIRONMENT_CHILD") {
        exercise(Path::new(&root), Path::new(&binary)).await;
        return;
    }
    let root = tempfile::Builder::new()
        .prefix("ar-env-")
        .tempdir_in("/tmp")
        .unwrap();
    let isolated_home = root.path().join("os-home");
    fs::create_dir(&isolated_home).unwrap();
    // Only the child receives an isolated OS home. The developer's environment,
    // launchd registration and default Mutagen namespace remain untouched.
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_stopped_inventory_and_confirmed_daemon_environment_restart",
            "--nocapture",
        ])
        .env("HOME", &isolated_home)
        .env("MUTAGEN_DATA_DIRECTORY", root.path().join("data"))
        .env("AGENT_REMOTE_TEST_MUTAGEN_ENVIRONMENT_CHILD", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native environment child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("running 1 test"));
}

async fn exercise(root: &Path, binary: &Path) {
    let paths = AppPaths::new(Some(root.join("new-home"))).unwrap();
    fs::create_dir_all(paths.bin_dir()).unwrap();
    symlink(
        binary.canonicalize().unwrap(),
        paths.bin_dir().join("mutagen"),
    )
    .unwrap();
    let shim = root.join("unused-ssh-shim");
    fs::write(&shim, b"#!/bin/sh\nexit 77\n").unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
    for proxy in ["ssh", "scp"] {
        symlink(&shim, paths.bin_dir().join(proxy)).unwrap();
    }
    let daemon = Daemon {
        binary: paths.bin_dir().join("mutagen"),
        data: root.join("data"),
    };
    // A project operation may initialize a genuinely unused namespace.
    let initial =
        agent_remote_cli::mutagen::terminate_session(&paths, "absent-native-fixture", false);
    assert!(initial.is_err());
    assert!(!format!("{:#}", initial.unwrap_err()).contains("environment_mismatch"));
    let initialized = environment::preview(&paths).await.unwrap();
    assert_eq!(initialized.daemon_state, "running");
    assert!(initialized.sessions.is_empty());
    assert_eq!(initialized.previous.as_ref(), Some(&initialized.desired));
    daemon.success(&["daemon", "stop"]);
    // All files belong to this disposable fixture, including its unused daemon.
    fs::remove_dir_all(&daemon.data).unwrap();
    let mut original = daemon
        .command(&["daemon", "run"])
        .env("AGENT_REMOTE_HOME", root.join("old-home"))
        .env("MUTAGEN_SSH_PATH", root.join("old-bin"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut ready = false;
    for _ in 0..40 {
        if daemon
            .run(&["sync", "list", "--template", "{{len .}}"])
            .status
            .success()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "isolated official daemon did not start");
    let alpha = root.join("alpha");
    let beta = root.join("beta");
    fs::create_dir(&alpha).unwrap();
    fs::create_dir(&beta).unwrap();
    daemon.success(&[
        "sync",
        "create",
        "--paused",
        "--no-global-configuration",
        "--name",
        "environment-sync",
        alpha.to_str().unwrap(),
        beta.to_str().unwrap(),
    ]);
    daemon.success(&[
        "forward",
        "create",
        "--paused",
        "--no-global-configuration",
        "--name",
        "environment-forward",
        "tcp:127.0.0.1:0",
        "tcp:127.0.0.1:9",
    ]);
    daemon.success(&["daemon", "stop"]);
    for _ in 0..40 {
        if original.try_wait().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        original.try_wait().unwrap().is_some(),
        "original daemon did not stop"
    );
    legacy_rejected(&paths);
    assert!(!daemon.run(&["sync", "list"]).status.success());
    let before = disk(&daemon.data);
    let preview = environment::preview(&paths).await.unwrap();
    assert_eq!(preview.daemon_state, "stopped");
    assert!(preview.repairable, "{:?}", preview.error_code);
    assert_eq!(preview.sessions.len(), 2);
    assert!(preview.sessions.iter().all(|session| session.paused));
    assert!(preview.sessions.iter().any(|s| s.kind == "sync"));
    assert!(preview.sessions.iter().any(|s| s.kind == "forward"));
    assert_eq!(
        disk(&daemon.data),
        before,
        "stopped preview changed daemon data"
    );
    assert!(
        !daemon.run(&["sync", "list"]).status.success(),
        "preview started daemon"
    );
    // Persisted configuration drift invalidates the reviewed scope while stopped.
    let session_file = daemon.data.join("sessions").join(
        &preview
            .sessions
            .iter()
            .find(|s| s.kind == "sync")
            .unwrap()
            .identifier,
    );
    let original_bytes = fs::read(&session_file).unwrap();
    let mut changed_bytes = original_bytes.clone();
    let name = b"environment-sync";
    let name_offset = changed_bytes
        .windows(name.len())
        .position(|v| v == name)
        .unwrap();
    changed_bytes[name_offset] = b'E';
    fs::write(&session_file, changed_bytes).unwrap();
    let drifted = environment::preview(&paths).await.unwrap();
    assert_ne!(drifted.inventory_fingerprint, preview.inventory_fingerprint);
    stale_rejected(&paths, &preview).await;
    assert!(!daemon.run(&["sync", "list"]).status.success());
    fs::write(&session_file, original_bytes).unwrap();
    let preview = environment::preview(&paths).await.unwrap();
    let receipt = environment::apply(&paths, &preview.fingerprint)
        .await
        .unwrap();
    if receipt.outcome != "completed" {
        eprintln!(
            "recovery stages: {}",
            serde_json::to_string(&receipt.stages).unwrap()
        );
        for kind in ["sync", "forward"] {
            let output = daemon.run(&[
                kind,
                "list",
                "--template",
                "{{range .}}{{.Identifier}} {{.Paused}}{{\"\\n\"}}{{end}}",
            ]);
            eprintln!(
                "official {kind} roster code={:?}, stdout={:?}, stderr={:?}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    assert_eq!(receipt.outcome, "completed", "{:?}", receipt.error_code);
    let after = receipt.environment.unwrap();
    assert_eq!(after.sessions, preview.sessions);
    assert_eq!(after.daemon_state, "running");
    assert_eq!(after.previous.as_ref(), Some(&preview.desired));
    let marker: serde_json::Value = serde_json::from_slice(
        &fs::read(daemon.data.join("agent-remote-environment.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(marker["version"], 2);
    assert_eq!(marker["binding"]["home"], paths.home().to_str().unwrap());
    assert_eq!(
        environment::apply(&paths, &preview.fingerprint)
            .await
            .err()
            .unwrap()
            .code(),
        "sync_mutagen_environment_changed"
    );
    let running = environment::preview(&paths).await.unwrap();
    assert_eq!(running.daemon_state, "running");
    let restart = environment::apply(&paths, &running.fingerprint)
        .await
        .unwrap();
    assert_eq!(restart.outcome, "completed", "{:?}", restart.error_code);
    let final_plan = restart.environment.unwrap();
    assert_eq!(final_plan.sessions, preview.sessions);
    assert_ne!(final_plan.running_fingerprint, running.running_fingerprint);
    assert_eq!(
        environment::apply(&paths, &running.fingerprint)
            .await
            .err()
            .unwrap()
            .code(),
        "sync_mutagen_environment_changed"
    );
    // A paused-state change must invalidate a previously reviewed global restart.
    daemon.success(&["sync", "resume", "environment-sync"]);
    stale_rejected(&paths, &final_plan).await;
    daemon.success(&["sync", "pause", "environment-sync"]);
    assert_eq!(
        environment::preview(&paths)
            .await
            .unwrap()
            .running_fingerprint,
        final_plan.running_fingerprint
    );
    marker_scope(&paths, &daemon, root).await;
    #[cfg(target_os = "macos")]
    external_registration(&paths, &daemon).await;

    // A new real daemon generation cannot reuse the preceding marker.
    daemon.success(&["daemon", "stop"]);
    let mut external = daemon
        .command(&["daemon", "run"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut ready = false;
    for _ in 0..40 {
        if daemon.run(&["sync", "list"]).status.success() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready);
    legacy_rejected(&paths);
    let external_plan = environment::preview(&paths).await.unwrap();
    assert_ne!(
        external_plan.running_fingerprint,
        final_plan.running_fingerprint
    );
    daemon.success(&["daemon", "stop"]);
    assert!(external.wait().unwrap().success());
}

async fn marker_scope(paths: &AppPaths, daemon: &Daemon, root: &Path) {
    let marker_file = daemon.data.join("agent-remote-environment.json");
    let original = fs::read(&marker_file).unwrap();
    let marker: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let before = environment::preview(paths).await.unwrap();
    assert_eq!(
        marker["namespace_fingerprint"],
        before.namespace_fingerprint.as_deref().unwrap()
    );
    assert_eq!(
        marker["running_fingerprint"],
        before.running_fingerprint.as_deref().unwrap()
    );
    for field in ["namespace_fingerprint", "running_fingerprint"] {
        let mut modified = marker.clone();
        modified[field] = format!("sha256:{}", "0".repeat(64)).into();
        fs::write(&marker_file, serde_json::to_vec(&modified).unwrap()).unwrap();
        legacy_rejected(paths);
        stale_rejected(paths, &before).await;
        assert_eq!(
            environment::preview(paths)
                .await
                .unwrap()
                .running_fingerprint,
            before.running_fingerprint
        );
        fs::write(&marker_file, &original).unwrap();
    }
    let renamed = root.join("temporarily-moved-home");
    fs::rename(paths.home(), &renamed).unwrap();
    fs::create_dir_all(paths.bin_dir()).unwrap();
    for binary in ["mutagen", "ssh", "scp"] {
        let resolved = fs::canonicalize(renamed.join("bin").join(binary)).unwrap();
        symlink(resolved, paths.bin_dir().join(binary)).unwrap();
    }
    legacy_rejected(paths);
    let replacement = environment::preview(paths).await.unwrap();
    assert_ne!(replacement.desired.fingerprint, before.desired.fingerprint);
    fs::remove_dir_all(paths.home()).unwrap();
    fs::rename(renamed, paths.home()).unwrap();
}

#[cfg(target_os = "macos")]
async fn external_registration(paths: &AppPaths, daemon: &Daemon) {
    let registration = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join("Library/LaunchAgents/io.mutagen.mutagen.plist");
    fs::create_dir_all(registration.parent().unwrap()).unwrap();
    fs::write(&registration, "isolated fixture registration, never loaded").unwrap();
    let before = disk(&daemon.data);
    let plan = environment::preview(paths).await.unwrap();
    assert_eq!(plan.registration, "external");
    assert!(!plan.repairable);
    assert_eq!(
        plan.error_code.as_deref(),
        Some("sync_mutagen_registration_external")
    );
    assert_eq!(
        environment::apply(paths, &plan.fingerprint)
            .await
            .unwrap_err()
            .code(),
        "sync_mutagen_environment_blocked"
    );
    legacy_rejected(paths);
    assert_eq!(disk(&daemon.data), before);
    fs::remove_file(registration).unwrap();
}
