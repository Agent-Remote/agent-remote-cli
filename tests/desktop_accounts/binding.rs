use super::fixture::*;
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

const BINDING: &str = "bind-123456781234-0123456789ab";
fn authorization(status: &str) -> Value {
    json!({"version":1,"tool_account_id":ACCOUNT_ID,"binding_session_id":BINDING,"node_id":"33333333-3333-4333-8333-333333333333","device_id":"device-test","ssh_host":"127.0.0.1","ssh_port":2222,"ssh_user":"agent-remote","tmux_session_name":"binding-tmux","authorization_task_id":"ssh-key-sync:device-test:hash","authorization_task_status":status,"expires_in":30})
}
fn native_command(fixture: &Fixture, script: &str) -> Command {
    let bin = fixture._temp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let ssh = bin.join("ssh");
    fs::write(&ssh, script).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let mut search = vec![bin];
    search.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-remote"));
    command
        .args([
            "account",
            "attach",
            ACCOUNT_ID,
            "--binding-session",
            BINDING,
            "--expected-server",
            fixture.context["server_url"].as_str().unwrap(),
            "--expected-device",
            "device-test",
        ])
        .env("AGENT_REMOTE_HOME", &fixture.home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("PATH", std::env::join_paths(search).unwrap())
        .env(
            "TEST_BINDING_SSH_ARGS",
            fixture._temp.path().join("ssh-args"),
        )
        .env_remove("AGENT_REMOTE_LOGIN_CLIPBOARD_ACTIVE")
        .env("AGENT_REMOTE_LOGIN_CLIPBOARD", "0")
        .env("AGENT_REMOTE_CLIPBOARD", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
fn captured(fixture: &Fixture) -> Option<Vec<String>> {
    fs::read_to_string(fixture._temp.path().join("ssh-args"))
        .ok()
        .map(|s| s.lines().map(str::to_owned).collect::<Vec<_>>())
        .filter(|lines| !lines.is_empty())
}
const SSH:&str="#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TEST_BINDING_SSH_ARGS\"\nprintf 'native binding terminal\\n'\n";
fn no_private_output(output: &std::process::Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for secret in [
            "account-test-token",
            "private-server-detail",
            "malicious-command",
            "secret-verifier",
        ] {
            assert!(!text.contains(secret));
        }
    }
}

#[test]
fn one_post_then_only_status_gets_leads_to_exact_unforwarded_ssh() {
    let fixture = Fixture::new(vec![
        envelope(authorization("pending")),
        envelope(authorization("running")),
        envelope(authorization("succeeded")),
    ]);
    let output = native_command(&fixture, SSH).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    no_private_output(&output);
    assert_eq!(output.stdout, b"native binding terminal\n");
    let args = captured(&fixture).unwrap();
    assert_eq!(
        &args[args.len() - 5..],
        [
            "agent-remote-attach",
            "--binding",
            ACCOUNT_ID,
            "--binding-session",
            BINDING
        ]
    );
    assert!(args.contains(&"-a".to_owned()));
    assert!(args.contains(&"-x".to_owned()));
    assert!(args.contains(&"ClearAllForwardings=yes".to_owned()));
    assert!(!args.contains(&"-A".to_owned()));
    assert!(args.contains(&"agent-remote@127.0.0.1".to_owned()));
    assert!(args.contains(&"2222".to_owned()));
    let wires = fixture.wires();
    assert_eq!(wires.len(), 3);
    assert!(wires[0].starts_with(&format!(
        "POST /api/v1/tool-accounts/{ACCOUNT_ID}/bind/attach HTTP/1.1"
    )));
    let body: Value = serde_json::from_str(wires[0].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body, json!({"expected_binding_session_id":BINDING}));
    for wire in &wires[1..] {
        assert!(wire.starts_with(&format!("GET /api/v1/tool-accounts/{ACCOUNT_ID}/bind/attach/ssh-key-sync%3Adevice-test%3Ahash?expected_binding_session_id={BINDING} HTTP/1.1")),"{wire}");
    }
}

#[test]
fn changed_polled_target_never_starts_ssh_or_resubmits_authorization() {
    for field in [
        "ssh_host",
        "node_id",
        "authorization_task_id",
        "binding_session_id",
        "device_id",
    ] {
        let mut changed = authorization("succeeded");
        changed[field] = match field {
            "node_id" => json!("44444444-4444-4444-8444-444444444444"),
            "binding_session_id" => json!("bind-123456781234-aaaaaaaaaaaa"),
            _ => json!("changed-target"),
        };
        let fixture = Fixture::new(vec![envelope(authorization("pending")), envelope(changed)]);
        let output = native_command(&fixture, SSH).output().unwrap();
        assert!(!output.status.success());
        no_private_output(&output);
        assert!(captured(&fixture).is_none());
        let wires = fixture.wires();
        assert_eq!(wires.len(), 2);
        assert!(wires[1].starts_with("GET "));
    }
}

#[test]
fn old_server_ambiguous_response_and_raw_command_additions_never_fall_back() {
    let mut injected = authorization("succeeded");
    injected["connect_command"] = json!("malicious-command");
    for reply in [
        Reply::json(
            404,
            json!({"error":{"code":"NOT_FOUND","message":"private-server-detail"}}),
        ),
        Reply::json(500, json!({"error":"private-server-detail"})),
        Reply {
            status: 200,
            body: Some(b"private-server-detail".to_vec()),
            advertised_length: None,
        },
        envelope(injected),
    ] {
        let fixture = Fixture::new(vec![reply]);
        let output = native_command(&fixture, SSH).output().unwrap();
        assert!(!output.status.success());
        no_private_output(&output);
        assert!(captured(&fixture).is_none());
        assert_eq!(fixture.wires().len(), 1);
    }
}

#[test]
fn unsupported_gateway_requires_upgrade_without_authorization_replay() {
    for polled in [false, true] {
        let mut replies = Vec::new();
        if polled {
            replies.push(envelope(authorization("pending")));
        }
        replies.push(Reply::json(
            409,
            json!({"error":{"code":"NODE_BINDING_ATTACH_UNSUPPORTED","message":"private-server-detail"}}),
        ));
        let fixture = Fixture::new(replies);
        let output = native_command(&fixture, SSH).output().unwrap();
        assert!(!output.status.success());
        no_private_output(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("updated Node and SSH gateway"));
        assert!(captured(&fixture).is_none());
        let wires = fixture.wires();
        assert_eq!(wires.len(), if polled { 2 } else { 1 });
        assert_eq!(
            wires
                .iter()
                .filter(|wire| wire.starts_with("POST "))
                .count(),
            1
        );
    }
}

#[test]
fn expected_context_and_exact_generation_validation_precede_http() {
    let fixture = Fixture::new(vec![]);
    let mut command = native_command(&fixture, SSH);
    let paths = agent_remote_cli::config::AppPaths::new(Some(fixture.home.clone())).unwrap();
    let mut config = agent_remote_cli::config::Config::load(&paths).unwrap();
    config.active_device_id = Some("changed-device".into());
    config.save(&paths).unwrap();
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(fixture.wires().is_empty());
    assert!(captured(&fixture).is_none());
    let output = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .args([
            "account",
            "attach",
            "12345678",
            "--binding-session",
            BINDING,
        ])
        .env("AGENT_REMOTE_HOME", &fixture.home)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(fixture.wires().is_empty());
}

#[test]
fn cancellation_after_post_never_replays_and_never_launches_ssh() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let fixture = Fixture::with_hook(
        vec![Reply {
            status: 200,
            body: None,
            advertised_length: None,
        }],
        Some(Box::new(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        })),
    );
    let child = native_command(&fixture, SSH).spawn().unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let output = child.wait_with_output().unwrap();
    release_tx.send(()).unwrap();
    assert!(!output.status.success());
    no_private_output(&output);
    assert!(captured(&fixture).is_none());
    assert_eq!(fixture.wires().len(), 1);
}

#[test]
fn cancellation_after_ssh_start_terminates_native_child() {
    let fixture = Fixture::new(vec![envelope(authorization("succeeded"))]);
    let script = "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$TEST_BINDING_SSH_ARGS\"\nexec sleep 30\n";
    let child = native_command(&fixture, script).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Some(value) = captured(&fixture) {
            break value[0].parse::<i32>().unwrap();
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    no_private_output(&output);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if unsafe { libc::kill(pid, 0) } != 0 {
            break;
        }
        assert!(Instant::now() < deadline, "SSH child survived cancellation");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn cancellation_cleans_up_real_pty_bridge_and_its_blocking_waiter() {
    let fixture = Fixture::new(vec![envelope(authorization("succeeded"))]);
    let native = native_command(
        &fixture,
        "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$TEST_BINDING_SSH_ARGS\"\nexec sleep 30\n",
    );
    let mut command = Command::new("python3");
    command
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/account_binding_pty.py"
        ))
        .arg(native.get_program())
        .args(native.get_args());
    for (key, value) in native.get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        } else {
            command.env_remove(key);
        }
    }
    command
        .env("AGENT_REMOTE_LOGIN_CLIPBOARD", "1")
        .env("AGENT_REMOTE_CLIPBOARD", "1");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fixture.wires().len(), 1);
}
