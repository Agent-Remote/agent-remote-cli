use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::fixture::{Behavior, Fixture, TOKEN};

fn tools(fixture: &Fixture) -> std::path::PathBuf {
    let directory = fixture.temp.path().join("tools");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("secret-tool");
    fs::write(
        &path,
        r#"#!/bin/sh
umask 077
if [ "$1" = lookup ]; then
  case "$5" in device-token:*) printf '%s' "$WG_DEVICE_TOKEN"; exit 0;; esac
  exit 1
fi
if [ "$1" = store ]; then
  /bin/cat > "$WG_STORED_KEY"
  if [ "$WG_STORE_MODE" = cancel ]; then
    /bin/sleep 30 &
    printf '%s %s' "$$" "$!" > "$WG_STORE_MARKER"
    wait
    exit 1
  fi
  printf '%s' 'changed-after-key-save' > "$WG_MUTATE_TARGET"
  exit 0
fi
exit 2
"#,
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn key_saved_before_context_or_target_change_is_reported_as_partial() {
    for context in [false, true] {
        let fixture = Fixture::new(Behavior::default());
        let output = fixture.home.join("wireguard/agent-remote.conf");
        let target = if context {
            fixture.home.join("config.toml")
        } else {
            output
        };
        let plan = fixture.plan(None);
        let mut child = fixture
            .command()
            .arg("--desktop-control")
            .env("AGENT_REMOTE_SECRET_BACKEND", "system")
            .env("PATH", tools(&fixture))
            .env("WG_DEVICE_TOKEN", TOKEN)
            .env("WG_STORED_KEY", fixture.temp.path().join("stored-key"))
            .env("WG_MUTATE_TARGET", &target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let request = json!({"protocol_version":1,"request_id":"key-saved","method":"wireguard.config.apply","params":{"confirmed":true,"expected_plan":plan}});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.to_string().as_bytes())
            .unwrap();
        let response = child.wait_with_output().unwrap();
        assert!(response.status.success());
        assert!(response.stderr.is_empty());
        let value: Value = serde_json::from_slice(&response.stdout).unwrap();
        assert_eq!(value["result"]["key_state"], "created");
        assert_eq!(value["result"]["enrollment"], "not_attempted");
        assert_eq!(value["result"]["publication"], "not_attempted");
        assert_eq!(
            value["result"]["code"],
            if context {
                "wireguard_context_changed"
            } else {
                "output_changed"
            }
        );
        assert!(fixture.requests.lock().unwrap().is_empty());
        assert_eq!(fs::read(&target).unwrap(), b"changed-after-key-save");
    }
}

#[test]
fn sigterm_during_secret_store_kills_its_private_process_group() {
    let fixture = Fixture::new(Behavior::default());
    let marker = fixture.temp.path().join("store-pids");
    let plan = fixture.plan(None);
    let mut child = fixture
        .command()
        .arg("--desktop-control")
        .env("AGENT_REMOTE_SECRET_BACKEND", "system")
        .env("PATH", tools(&fixture))
        .env("WG_DEVICE_TOKEN", TOKEN)
        .env("WG_STORED_KEY", fixture.temp.path().join("stored-key"))
        .env("WG_STORE_MODE", "cancel")
        .env("WG_STORE_MARKER", &marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"protocol_version":1,"request_id":"cancel-store","method":"wireguard.config.apply","params":{"confirmed":true,"expected_plan":plan}});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.exists());
    let pids: Vec<i32> = fs::read_to_string(&marker)
        .unwrap()
        .split_whitespace()
        .map(|pid| pid.parse().unwrap())
        .collect();
    assert_eq!(pids.len(), 2);
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let deadline = Instant::now() + Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("CLI did not stop after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "wireguard_outcome_unknown");
    for pid in pids {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if stat.is_empty()
                || stat
                    .split_once(") ")
                    .is_some_and(|(_, rest)| rest.starts_with('Z'))
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "credential process {pid} is still running"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(!fixture.home.join("wireguard/agent-remote.conf").exists());
}
