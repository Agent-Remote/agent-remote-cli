#![cfg(unix)]

#[path = "support/skill_cli.rs"]
mod support;

use agent_remote_cli::{
    config::AppPaths,
    local_state::{LocalDevice, LocalState},
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};
use support::*;

const SNAPSHOT: &str = "55555555-5555-4555-8555-555555555555";
const DEVICE: &str = "77777777-7777-4777-8777-777777777777";
const KEY: &str = "88888888-8888-4888-8888-888888888888";
const WIRE: &[u8] = include_bytes!("fixtures/skill-node-export-v1.bin");
const RECOVERY_WIRE: &[u8] = include_bytes!("fixtures/skill-node-recovery-v1.bin");

#[test]
fn recovery_format_requires_successful_ssh_exit_before_distinct_bundle_publication() {
    for exit in [0, 1] {
        let (url, server) = serve(vec![(200, authorization("succeeded"))]);
        let home = setup(&url, RECOVERY_WIRE, exit);
        let output = command(home.path()).output().unwrap();
        if exit != 0 {
            no_bundle(home.path(), &output);
        } else {
            let result = json_output(&output, 0);
            assert_eq!(
                result["data"]["format"],
                "agent-remote-skill-node-recovery-v1"
            );
            assert_eq!(result["data"]["file_objects"], 3);
            assert_eq!(result["committed"], false);
            assert!(!home.path().join("bundle/manifest.json").exists());
            assert_eq!(
                fs::read_dir(home.path().join("bundle/entries"))
                    .unwrap()
                    .count(),
                3
            );
            assert_eq!(
                fs::read_dir(home.path().join("bundle/objects"))
                    .unwrap()
                    .count(),
                2
            );
        }
        assert_eq!(server.join().unwrap().len(), 1);
    }
}

fn header() -> Value {
    let length = u32::from_be_bytes(WIRE[8..12].try_into().unwrap()) as usize;
    serde_json::from_slice(&WIRE[12..12 + length]).unwrap()
}

fn grant() -> String {
    format!("fixture=.{}", "a".repeat(64))
}

fn authorization(status: &str) -> Value {
    let mut value = envelope(json!({
        "binding":header()["binding"], "device_id":DEVICE, "ssh_key_id":KEY,
        "grant":grant(), "expires_at":"2030-01-01T00:00:00Z",
        "ssh_host":"127.0.0.1", "ssh_port":2222, "ssh_user":"agent-remote",
        "authorization_task_id":"ssh-key-sync:fixture", "authorization_task_status":status
    }));
    value["status"] = json!("authorized");
    value
}

fn setup(url: &str, wire: &[u8], exit: i32) -> tempfile::TempDir {
    let home = home(url);
    let paths = AppPaths::new(Some(home.path().to_owned())).unwrap();
    private(
        &paths.config_path(),
        format!("server_url = {url:?}\nactive_device_id = {DEVICE:?}\n"),
    );
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state
        .upsert_device(&LocalDevice {
            id: DEVICE.into(),
            server_url: url.into(),
            name: "export-test".into(),
            platform: "linux".into(),
            status: "active".into(),
            ssh_key_id: Some(KEY.into()),
            wireguard_peer_id: None,
            created_at: None,
            last_seen_at: None,
        })
        .unwrap();
    fs::create_dir(home.path().join("test-bin")).unwrap();
    fs::write(home.path().join("wire"), wire).unwrap();
    fs::write(
        home.path().join("test-bin/ssh"),
        format!(
            r#"#!/bin/sh
printf '%s\n' "$@" > "$EXPORT_TEST_HOME/arguments"
cat > "$EXPORT_TEST_HOME/stdin"
echo "$SSH_TEST_PRIVATE_ERROR" >&2
printf '%s' "$$" > "$EXPORT_TEST_HOME/pid"
if [ "$EXPORT_TEST_STALL" = 1 ]; then exec sleep 60; fi
cat "$EXPORT_TEST_HOME/wire"
exit {exit}
"#
        ),
    )
    .unwrap();
    fs::set_permissions(
        home.path().join("test-bin/ssh"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    home
}

fn command(home: &Path) -> Command {
    let mut command = Command::new(BIN);
    command
        .arg("--home")
        .arg(home)
        .args([
            "--json",
            "skill",
            "state",
            "export",
            "--snapshot",
            SNAPSHOT,
            "--scope",
            "account-directory",
            "--account-id",
            ACCOUNT,
            "--output",
        ])
        .arg(home.join("bundle"))
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("NO_COLOR", "1")
        .env("EXPORT_TEST_HOME", home)
        .env("SSH_TEST_PRIVATE_ERROR", grant())
        .env(
            "PATH",
            format!(
                "{}:{}",
                home.join("test-bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
    command
}

fn no_bundle(home: &Path, output: &Output) {
    json_output(output, 1);
    assert!(!home.join("bundle").exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&grant()));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&grant()));
    assert!(!fs::read_dir(home).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".skill-export-")));
}

#[test]
fn node_generated_wire_passes_cli_verification_and_publishes_only_portable_objects() {
    let (url, server) = serve(vec![
        (200, authorization("leased")),
        (200, authorization("succeeded")),
    ]);
    let home = setup(&url, WIRE, 0);
    let output = command(home.path()).output().unwrap();
    let result = json_output(&output, 0);
    assert_eq!(result["committed"], false);
    assert_eq!(result["data"]["binding"], header()["binding"]);
    assert_eq!(result["data"]["file_objects"], 2);
    assert_eq!(
        result["data"]["format"],
        "agent-remote-skill-node-snapshot-v1"
    );
    let metadata = fs::read_to_string(home.path().join("bundle/checkpoint.json")).unwrap();
    assert!(!metadata.contains(&grant()));
    assert!(!metadata.contains("expires_at"));
    let manifest: Value =
        serde_json::from_slice(&fs::read(home.path().join("bundle/manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest, header()["manifest"]);
    assert_eq!(
        fs::read_dir(home.path().join("bundle/objects"))
            .unwrap()
            .count(),
        2
    );
    assert!(!home.path().join("bundle/a").exists());
    for entry in manifest["entries"].as_array().unwrap() {
        let bytes = fs::read(
            home.path()
                .join("bundle/objects")
                .join(entry["sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            bytes,
            if entry["path"] == "b" {
                vec![0, 1, 2]
            } else {
                b"learned".to_vec()
            }
        );
    }
    let args = fs::read_to_string(home.path().join("arguments")).unwrap();
    for argument in [
        "-F\nnone\n",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "agent-remote-skill-export",
        SNAPSHOT,
    ] {
        assert!(args.contains(argument));
    }
    assert!(!args.contains(&grant()));
    let input: Value =
        serde_json::from_slice(&fs::read(home.path().join("stdin")).unwrap()).unwrap();
    assert_eq!(
        input,
        json!({"version":1,"grant":grant(),"recovery_version":1})
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert!(request.starts_with(&format!(
            "POST /api/v1/skills/state/node-exports/{SNAPSHOT}/authorize HTTP/1.1"
        )));
        assert!(request
            .to_lowercase()
            .contains("authorization: bearer skill-user-token\r\n"));
        assert!(request.contains(DEVICE) && request.contains(KEY));
    }
    let db = fs::read(home.path().join("state.sqlite3")).unwrap();
    assert!(!db
        .windows(grant().len())
        .any(|part| part == grant().as_bytes()));
}

fn change_header(value: Value) -> Vec<u8> {
    // Reserialization changes no object bytes: the receiver must validate all declared metadata.
    let old_length = u32::from_be_bytes(WIRE[8..12].try_into().unwrap()) as usize;
    let bytes = serde_json::to_vec(&value).unwrap();
    let mut output = WIRE[..8].to_vec();
    output.extend((bytes.len() as u32).to_be_bytes());
    output.extend(bytes);
    output.extend(&WIRE[12 + old_length..]);
    output
}

#[test]
fn incomplete_corrupt_foreign_or_failed_ssh_streams_never_publish() {
    for fault in [
        "missing_footer",
        "truncated",
        "extra",
        "corrupt_object",
        "marker",
        "foreign",
        "generation",
        "digest",
        "count",
        "oversized",
        "ssh_failure",
        "unknown_field",
        "duplicate",
    ] {
        let mut wire = WIRE.to_vec();
        let start = 12 + u32::from_be_bytes(WIRE[8..12].try_into().unwrap()) as usize;
        let mut value = header();
        match fault {
            "missing_footer" => wire.truncate(start + 12),
            "truncated" => wire.truncate(start + 1),
            "extra" => wire.push(0),
            "corrupt_object" => wire[start] = 42,
            "marker" => wire[start + 3] = 0,
            "foreign" => {
                value["binding"]["account_id"] = json!(DEVICE);
                wire = change_header(value);
            }
            "generation" => {
                value["binding"]["library_generation"] = json!(9007199254740992_i64);
                wire = change_header(value);
            }
            "digest" => {
                value["tree_digest"] = json!("a".repeat(64));
                wire = change_header(value);
            }
            "count" => {
                value["file_objects"] = json!(3);
                wire = change_header(value);
            }
            "oversized" => wire[8..12].copy_from_slice(&((64u32 << 20) + 1).to_be_bytes()),
            "unknown_field" => {
                value["path"] = json!("/etc/passwd");
                wire = change_header(value);
            }
            "duplicate" => {
                let mut data = WIRE[12..start].to_vec();
                data.pop();
                data.extend(b",\"version\":1}");
                wire = WIRE[..8].to_vec();
                wire.extend((data.len() as u32).to_be_bytes());
                wire.extend(data);
                wire.extend(&WIRE[start..]);
            }
            _ => {}
        }
        let (url, server) = serve(vec![(200, authorization("succeeded"))]);
        let home = setup(&url, &wire, if fault == "ssh_failure" { 1 } else { 0 });
        no_bundle(home.path(), &command(home.path()).output().unwrap());
        assert_eq!(server.join().unwrap().len(), 1, "{fault}");
    }
}

#[test]
fn frozen_export_rejects_ambiguous_selectors_before_authentication() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec![
            "export",
            "sample",
            "--snapshot",
            SNAPSHOT,
            "--output",
            "unused",
        ],
        vec![
            "export",
            "--scope",
            "account-directory",
            "--snapshot",
            SNAPSHOT,
            "--output",
            "unused",
        ],
        vec![
            "export",
            "--scope",
            "account-directory",
            "--account-id",
            ACCOUNT,
            "--output",
            "unused",
        ],
        vec![
            "export",
            "--scope",
            "account-directory",
            "--account-id",
            ACCOUNT,
            "--snapshot",
            SNAPSHOT,
            "--checkpoint",
            OP,
            "--output",
            "unused",
        ],
    ] {
        let mut full = vec!["skill", "state"];
        full.extend(args);
        assert_eq!(run(home.path(), &full).status.code(), Some(2));
    }
}

#[test]
fn authorization_scope_or_connection_substitution_never_invokes_ssh() {
    for field in [
        "account_id",
        "snapshot_id",
        "device_id",
        "ssh_key_id",
        "ssh_host",
        "ssh_user",
        "grant",
    ] {
        let mut auth = authorization("succeeded");
        match field {
            "account_id" | "snapshot_id" => auth["data"]["binding"][field] = json!(DEVICE),
            "device_id" | "ssh_key_id" => auth["data"][field] = json!(ACCOUNT),
            _ => auth["data"][field] = json!("-oProxyCommand=private"),
        }
        let (url, server) = serve(vec![(200, auth)]);
        let home = setup(&url, WIRE, 0);
        no_bundle(home.path(), &command(home.path()).output().unwrap());
        assert!(!home.path().join("arguments").exists(), "{field}");
        server.join().unwrap();
    }
}

#[test]
fn cancelling_a_blocked_ssh_stream_kills_child_and_leaves_no_bundle() {
    use std::{
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };
    let (url, server) = serve(vec![(200, authorization("succeeded"))]);
    let home = setup(&url, WIRE, 0);
    let mut child = command(home.path())
        .env("EXPORT_TEST_STALL", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !home.path().join("pid").exists() {
        assert!(Instant::now() < deadline && child.try_wait().unwrap().is_none());
        thread::sleep(Duration::from_millis(10));
    }
    let ssh: i32 = fs::read_to_string(home.path().join("pid"))
        .unwrap()
        .parse()
        .unwrap();
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    json_output(&output, 130);
    assert!(!home.path().join("bundle").exists());
    while unsafe { libc::kill(ssh, 0) } == 0 {
        assert!(Instant::now() < deadline, "SSH child survived cancellation");
        thread::sleep(Duration::from_millis(10));
    }
    server.join().unwrap();
}
