//! Subprocess isolation keeps backend, home and lock-root overrides out of other tests.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    directory: tempfile::TempDir,
    executable: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory
            .path()
            .join(if cfg!(windows) { "test.exe" } else { "test" });
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        Self {
            directory,
            executable,
        }
    }

    fn command(&self, home: &Path, mode: &str) -> Command {
        std::fs::create_dir_all(home).unwrap();
        let mut command = Command::new(&self.executable);
        command
            .args(["--exact", "strict_credential_child", "--nocapture"])
            .env("STRICT_CREDENTIAL_TEST_MODE", mode)
            .env("AGENT_REMOTE_HOME", home)
            .env(
                "AGENT_REMOTE_WIREGUARD_LOCK_ROOT",
                self.directory.path().join("shared-locks"),
            )
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "child did not reach test barrier"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn finish(mut child: Child) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("strict credential child exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn two_homes_share_one_server_device_lock() {
    let fixture = Fixture::new();
    let first = fixture.directory.path().join("first-home");
    let second = fixture.directory.path().join("second-home");
    let first_child = fixture.command(&first, "lock").spawn().unwrap();
    wait_for(&first.join("acquired"));
    let second_child = fixture.command(&second, "lock").spawn().unwrap();
    wait_for(&second.join("started"));
    std::thread::sleep(Duration::from_millis(150));
    assert!(!second.join("acquired").exists());
    std::fs::write(first.join("release"), b"").unwrap();
    finish(first_child);
    wait_for(&second.join("acquired"));
    std::fs::write(second.join("release"), b"").unwrap();
    finish(second_child);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_system_failures_never_hide_behind_fallback_and_file_backend_skips_system() {
    for (mode, script) in [
        ("lookup_denied", "echo denied >&2; exit 2"),
        ("lookup_absent", "exit 1"),
        ("file_only", "touch \"$STRICT_PROCESS_PID\"; exit 2"),
        ("lookup_oversize", "head -c 70000 /dev/zero"),
    ] {
        let fixture = Fixture::new();
        let home = fixture.directory.path().join("home");
        let tool = fake_tool(&fixture, script);
        let mut command = fixture.command(&home, mode);
        command
            .env("PATH", format!("{}:/usr/bin:/bin", tool.display()))
            .env(
                "STRICT_PROCESS_PID",
                fixture.directory.path().join("unexpected-tool"),
            );
        if mode != "file_only" {
            command.env("AGENT_REMOTE_SECRET_BACKEND", "auto");
        }
        finish(command.spawn().unwrap());
        if mode == "file_only" {
            assert!(!fixture.directory.path().join("unexpected-tool").exists());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_store_cancel_and_timeout_kill_the_tool_group() {
    for (mode, script) in [
        (
            "store_cancel",
            "cat >/dev/null; sleep 60 & echo $! >\"$STRICT_PROCESS_PID\"; wait",
        ),
        // The leader exits first; the descendant still owns inherited output pipes.
        (
            "store_timeout",
            "cat >/dev/null; sleep 60 & echo $! >\"$STRICT_PROCESS_PID\"; exit 0",
        ),
    ] {
        let fixture = Fixture::new();
        let home = fixture.directory.path().join("home");
        let marker = fixture.directory.path().join("tool.pid");
        let tool = fake_tool(&fixture, script);
        let mut command = fixture.command(&home, mode);
        command
            .env("AGENT_REMOTE_SECRET_BACKEND", "auto")
            .env("PATH", format!("{}:/usr/bin:/bin", tool.display()))
            .env("STRICT_PROCESS_PID", &marker);
        finish(command.spawn().unwrap());
        let pid = std::fs::read_to_string(marker)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let gone = unsafe { libc::kill(pid, 0) } != 0;
            let zombie = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .is_some_and(|stat| {
                    stat.rsplit_once(") ")
                        .is_some_and(|(_, tail)| tail.starts_with("Z "))
                });
            if gone || zombie {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "credential descendant survived cancellation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
fn fake_tool(fixture: &Fixture, script: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let directory = fixture.directory.path().join("tools");
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("secret-tool");
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn strict_credential_child() {
    let Ok(mode) = std::env::var("STRICT_CREDENTIAL_TEST_MODE") else {
        return;
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use std::sync::atomic::AtomicBool;
            let paths = agent_remote_cli::config::AppPaths::new(None).unwrap();
            let home = paths.home();
            if mode == "lock" {
                std::fs::write(home.join("started"), b"").unwrap();
                let _guard = agent_remote_cli::auth::lock_wireguard_credentials(
                    "https://locks.invalid",
                    "same-device",
                    &AtomicBool::new(false),
                )
                .await
                .unwrap();
                std::fs::write(home.join("acquired"), b"").unwrap();
                let deadline = Instant::now() + Duration::from_secs(8);
                while !home.join("release").exists() {
                    assert!(Instant::now() < deadline);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            #[cfg(target_os = "linux")]
            if mode != "lock" {
                linux_child(&mode, paths).await;
            }
        });
}

#[cfg(target_os = "linux")]
async fn linux_child(mode: &str, paths: agent_remote_cli::config::AppPaths) {
    use agent_remote_cli::secrets::{SecretStore, SecretValue, StrictSecretError};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    paths.ensure_base_dirs().unwrap();
    let fallback = paths.secrets_dir().join("fixture.secret");
    std::fs::write(&fallback, "fallback-fixture").unwrap();
    std::fs::set_permissions(&fallback, std::fs::Permissions::from_mode(0o600)).unwrap();
    let store = SecretStore::new(paths);
    let cancel = Arc::new(AtomicBool::new(false));
    if mode.starts_with("store_") {
        let marker = PathBuf::from(std::env::var_os("STRICT_PROCESS_PID").unwrap());
        let signal = cancel.clone();
        let should_cancel = mode == "store_cancel";
        let cancellation = tokio::spawn(async move {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if should_cancel {
                signal.store(true, Ordering::Release);
            }
        });
        let error = store
            .write_strict(
                "fixture",
                &SecretValue::new("new-fixture".into()).unwrap(),
                &cancel,
            )
            .await
            .err()
            .unwrap();
        cancellation.await.unwrap();
        assert_eq!(
            error,
            if should_cancel {
                StrictSecretError::Canceled
            } else {
                StrictSecretError::TimedOut
            }
        );
        assert_eq!(
            std::fs::read_to_string(fallback).unwrap(),
            "fallback-fixture"
        );
        return;
    }
    let result = store.read_strict("fixture", &cancel).await;
    match mode {
        "lookup_denied" => assert_eq!(result.err(), Some(StrictSecretError::Unavailable)),
        "lookup_oversize" => assert_eq!(result.err(), Some(StrictSecretError::Invalid)),
        "lookup_absent" | "file_only" => {
            assert_eq!(result.unwrap().unwrap().as_str(), "fallback-fixture")
        }
        _ => panic!("unknown test mode"),
    }
}
