#![cfg(unix)]

use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn setup() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        "server_url = \"https://inspection.invalid\"\n",
    )
    .unwrap();
    std::fs::create_dir(home.path().join("tools")).unwrap();
    std::fs::create_dir(home.path().join("secrets")).unwrap();
    home
}

fn fake_tool(home: &Path, script: &str) {
    for name in ["security", "secret-tool"] {
        let path = home.join("tools").join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn start(home: &Path, file_only: bool) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-remote"));
    command
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", home)
        .env(
            "PATH",
            format!(
                "{}:{}",
                home.join("tools").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if file_only {
        command.env("AGENT_REMOTE_SECRET_BACKEND", "file");
    } else {
        command.env_remove("AGENT_REMOTE_SECRET_BACKEND");
    }
    let mut child = command.spawn().unwrap();
    let request = json!({"protocol_version":1,"request_id":"credential-inspect","method":"diagnostics.inspect","params":{"deep_check":true}});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    child
}

fn finish(mut child: Child) -> Value {
    let deadline = Instant::now() + Duration::from_secs(7);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("credential inspection did not finish within bound")
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-secret"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-error"));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn status(response: &Value) -> &str {
    response["result"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "credential")
        .unwrap()["status"]
        .as_str()
        .unwrap()
}

fn fallback(home: &Path) -> PathBuf {
    home.join("secrets/user-token_https___inspection.invalid.secret")
}

#[test]
fn path_injected_system_tool_distinguishes_missing_from_access_failure() {
    let home = setup();
    fake_tool(home.path(), "printf private-error >&2; exit 36");
    assert_eq!(status(&finish(start(home.path(), false))), "inaccessible");
    fake_tool(home.path(), "printf private-error >&2; exit 1");
    assert_eq!(status(&finish(start(home.path(), false))), "inaccessible");
    fake_tool(
        home.path(),
        if cfg!(target_os = "macos") {
            "exit 44"
        } else {
            "exit 1"
        },
    );
    assert_eq!(status(&finish(start(home.path(), false))), "missing");
    fake_tool(home.path(), "printf fixture-secret; exit 0");
    assert_eq!(status(&finish(start(home.path(), false))), "present");
}

#[test]
fn valid_fallback_remains_usable_when_system_store_is_inaccessible() {
    let home = setup();
    fake_tool(home.path(), "printf private-error >&2; exit 36");
    std::fs::write(fallback(home.path()), "fixture-secret").unwrap();
    assert_eq!(status(&finish(start(home.path(), false))), "present");
}

#[test]
fn fallback_fifo_and_oversize_do_not_hang_or_appear_missing() {
    let home = setup();
    let path = fallback(home.path());
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    let before = Instant::now();
    assert_eq!(status(&finish(start(home.path(), true))), "inaccessible");
    assert!(before.elapsed() < Duration::from_secs(2));
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, vec![b'x'; 64 * 1024 + 1]).unwrap();
    assert_eq!(status(&finish(start(home.path(), true))), "inaccessible");
}

#[test]
fn system_tool_timeout_and_cancellation_reap_spawned_children() {
    for cancel in [false, true] {
        let home = setup();
        fake_tool(
            home.path(),
            "/bin/sleep 30 &\nprintf '%s' $! > \"$AGENT_REMOTE_HOME/probe-child.pid\"\nwait",
        );
        let mut child = start(home.path(), false);
        let deadline = Instant::now() + Duration::from_secs(3);
        let pid_path = home.path().join("probe-child.pid");
        while !pid_path.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !pid_path.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("credential probe did not start")
        }
        let pid: i32 = std::fs::read_to_string(pid_path).unwrap().parse().unwrap();
        if cancel {
            assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
        }
        let response = finish(child);
        if cancel {
            assert_eq!(response["error"]["code"], "canceled");
        } else {
            assert_eq!(status(&response), "inaccessible");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && unsafe { libc::kill(pid, 0) } == 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        if alive {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        assert!(
            !alive,
            "credential probe descendant survived completion/cancellation"
        );
    }
}
