use super::fixture::*;
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

const SESSION: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE: &str = "22222222-2222-4222-8222-222222222222";
const RECORD: &str = "44444444-4444-4444-8444-444444444444";

fn authorization(status: &str) -> Value {
    json!({"version":1,"session_id":SESSION,"tool_type":"claude","node_id":"33333333-3333-4333-8333-333333333333","device_id":DEVICE,"ssh_host":"127.0.0.1","ssh_port":2222,"ssh_user":"agent-remote","tmux_session_name":"claude-tmux","forward_ssh_agent":false,"authorization_task_id":"ssh-key-sync:device:digest","authorization_task_record_id":RECORD,"authorization_task_status":status,"expires_in":30})
}
fn fixture(replies: Vec<Reply>) -> Fixture {
    Fixture::with_device(replies, None, DEVICE)
}
const SSH: &str = "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TEST_BINDING_SSH_ARGS\"\nprintf 'native session terminal\\n'\n";
fn native(fixture: &Fixture, script: &str) -> Command {
    let bin = fixture._temp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let ssh = bin.join("ssh");
    fs::write(&ssh, script).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let mut search = vec![bin];
    search.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let mut command = Command::new(env!("CARGO_BIN_EXE_fclaude"));
    command
        .args([
            "attach",
            SESSION,
            "--expected-server",
            fixture.context["server_url"].as_str().unwrap(),
            "--expected-device",
            DEVICE,
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
        .env("AGENT_REMOTE_ATTACHMENTS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
fn captured(fixture: &Fixture) -> Option<Vec<String>> {
    fs::read_to_string(fixture._temp.path().join("ssh-args"))
        .ok()
        .map(|s| s.lines().map(str::to_owned).collect())
        .filter(|v: &Vec<String>| !v.is_empty())
}
fn redacted(output: &std::process::Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for secret in [
            "account-test-token",
            "private-server-detail",
            "malicious-command",
        ] {
            assert!(!text.contains(secret), "{text}");
        }
    }
}

#[test]
fn exact_session_posts_once_polls_original_row_and_launches_fixed_device_command() {
    let fixture = fixture(vec![
        envelope(authorization("pending")),
        envelope(authorization("running")),
        envelope(authorization("succeeded")),
    ]);
    let output = native(&fixture, SSH).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    redacted(&output);
    assert_eq!(output.stdout, b"native session terminal\n");
    let args = captured(&fixture).unwrap();
    assert_eq!(
        &args[args.len() - 5..],
        [
            "agent-remote-attach",
            "--session",
            SESSION,
            "--expected-device",
            DEVICE
        ]
    );
    for required in [
        "-a",
        "-x",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "agent-remote@127.0.0.1",
    ] {
        assert!(args.iter().any(|arg| arg == required));
    }
    assert!(!args.iter().any(|arg| arg == "-A"));
    let wires = fixture.wires();
    assert_eq!(wires.len(), 3);
    assert!(wires[0].starts_with(&format!(
        "POST /api/v1/sessions/{SESSION}/attach/exact HTTP/1.1"
    )));
    let body: Value = serde_json::from_str(wires[0].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body, json!({"expected_device_id":DEVICE}));
    for wire in &wires[1..] {
        assert!(wire.starts_with(&format!("GET /api/v1/sessions/{SESSION}/attach/exact/ssh-key-sync%3Adevice%3Adigest?expected_device_id={DEVICE}&expected_task_record_id={RECORD} HTTP/1.1")), "{wire}");
    }
}

#[test]
fn exact_session_forwarding_uses_explicit_authorization_and_print_only_never_starts_ssh() {
    for print_only in [false, true] {
        let mut data = authorization("succeeded");
        data["forward_ssh_agent"] = true.into();
        let fixture = fixture(vec![envelope(data)]);
        let mut command = native(&fixture, SSH);
        if print_only {
            command.arg("--print-only");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        redacted(&output);
        if print_only {
            assert!(captured(&fixture).is_none());
            assert!(String::from_utf8_lossy(&output.stdout)
                .contains(&format!("--session {SESSION} --expected-device {DEVICE}")));
        } else {
            let args = captured(&fixture).unwrap();
            assert!(args.iter().any(|arg| arg == "-A"));
            assert!(!args.iter().any(|arg| arg == "-a"));
        }
        assert_eq!(fixture.wires().len(), 1);
    }
}

#[test]
fn exact_session_never_initializes_legacy_clipboard_transfer_even_when_enabled() {
    let fixture = fixture(vec![envelope(authorization("succeeded"))]);
    let output = native(&fixture, SSH)
        .env("AGENT_REMOTE_ATTACHMENTS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"native session terminal\n");
    let wires = fixture.wires();
    assert_eq!(wires.len(), 1, "legacy session/account lookup must not run");
    assert!(wires[0].starts_with("POST "));
    assert_eq!(
        &captured(&fixture).unwrap()[captured(&fixture).unwrap().len() - 5..],
        [
            "agent-remote-attach",
            "--session",
            SESSION,
            "--expected-device",
            DEVICE
        ]
    );
}

#[test]
fn exact_session_rejects_changed_original_target_or_task_record_without_another_post() {
    for (field, changed) in [
        ("session_id", json!(DEVICE)),
        ("device_id", json!(SESSION)),
        ("tool_type", json!("codex")),
        ("node_id", json!(SESSION)),
        ("ssh_host", json!("other.example")),
        ("ssh_port", json!(2223)),
        ("ssh_user", json!("other")),
        ("tmux_session_name", json!("other")),
        ("forward_ssh_agent", json!(true)),
        ("authorization_task_id", json!("replacement")),
        ("authorization_task_record_id", json!(SESSION)),
    ] {
        let mut next = authorization("succeeded");
        next[field] = changed;
        let fixture = fixture(vec![envelope(authorization("pending")), envelope(next)]);
        let output = native(&fixture, SSH).output().unwrap();
        assert!(!output.status.success(), "{field}");
        redacted(&output);
        assert!(captured(&fixture).is_none());
        let wires = fixture.wires();
        assert_eq!(wires.len(), 2);
        assert!(wires[1].starts_with("GET "));
    }
}

#[test]
fn exact_session_missing_state_unknown_state_or_untrusted_command_never_falls_back() {
    let mut missing = authorization("succeeded");
    missing
        .as_object_mut()
        .unwrap()
        .remove("authorization_task_status");
    let mut command = authorization("succeeded");
    command["ssh_command"] = "malicious-command".into();
    let mut no_record = authorization("succeeded");
    no_record
        .as_object_mut()
        .unwrap()
        .remove("authorization_task_record_id");
    for reply in [
        envelope(missing),
        envelope(command),
        envelope(no_record),
        envelope(authorization("future")),
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
    ] {
        let fixture = fixture(vec![reply]);
        let output = native(&fixture, SSH).output().unwrap();
        assert!(!output.status.success());
        redacted(&output);
        assert!(captured(&fixture).is_none());
        assert_eq!(fixture.wires().len(), 1);
    }
}

#[test]
fn exact_session_terminal_failure_and_missing_gateway_do_not_reauthorize() {
    for status in ["failed", "cancelled", "expired", "unsupported"] {
        let reply = if status == "unsupported" {
            Reply::json(
                409,
                json!({"error":{"code":"NODE_SESSION_ATTACH_UNSUPPORTED","message":"private-server-detail"}}),
            )
        } else {
            envelope(authorization(status))
        };
        let fixture = fixture(vec![envelope(authorization("pending")), reply]);
        let output = native(&fixture, SSH).output().unwrap();
        assert!(!output.status.success());
        redacted(&output);
        assert!(captured(&fixture).is_none());
        if status == "unsupported" {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("updated Node and SSH gateway")
            );
        }
        let wires = fixture.wires();
        assert_eq!(wires.len(), 2);
        assert!(wires[1].starts_with("GET "));
    }
}

#[test]
fn exact_session_original_ttl_bounds_polling_without_replay() {
    let mut pending = authorization("pending");
    pending["expires_in"] = 1.into();
    let fixture = fixture(vec![envelope(pending.clone()), envelope(pending)]);
    let started = Instant::now();
    let output = native(&fixture, SSH).output().unwrap();
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(5));
    redacted(&output);
    assert!(captured(&fixture).is_none());
    let wires = fixture.wires();
    assert_eq!(wires.len(), 2);
    assert!(wires[0].starts_with("POST "));
    assert!(wires[1].starts_with("GET "));
}

#[test]
fn ordinary_fclaude_prefix_and_print_only_keep_legacy_attach_route() {
    let session = json!({"id":SESSION,"tool_type":"claude","user_id":DEVICE,"tool_account_id":DEVICE,"workspace_id":DEVICE,"node_id":DEVICE,"project_key":"project","status":"running","runtime_backend":"native","created_at":"2026-10-19T00:00:00Z","updated_at":"2026-10-19T00:00:00Z"});
    let legacy = json!({"session_id":SESSION,"node_id":DEVICE,"node_wireguard_ip":"127.0.0.1","ssh_host":"127.0.0.1","ssh_port":2222,"ssh_user":"agent-remote","tmux_session_name":"claude-tmux","command_args":[],"ssh_command":"legacy display command","authorization_task_id":"legacy-task","expires_in":300});
    let fixture = fixture(vec![
        envelope(json!({"items":[session.clone()]})),
        envelope(session),
        envelope(legacy),
    ]);
    let output = Command::new(env!("CARGO_BIN_EXE_fclaude"))
        .args(["attach", "11111111", "--print-only"])
        .env("AGENT_REMOTE_HOME", &fixture.home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("legacy display command"));
    let wires = fixture.wires();
    assert_eq!(wires.len(), 3);
    assert!(wires[0].starts_with("GET /api/v1/sessions?tool_type=claude HTTP/1.1"));
    assert!(wires[1].starts_with(&format!("GET /api/v1/sessions/{SESSION} HTTP/1.1")));
    assert!(wires[2].starts_with(&format!("POST /api/v1/sessions/{SESSION}/attach HTTP/1.1")));
}

#[test]
fn exact_session_context_mismatch_precedes_even_due_credential_refresh() {
    for changed_server in [false, true] {
        let fixture = fixture(vec![]);
        let mut command = native(&fixture, SSH);
        let paths = agent_remote_cli::config::AppPaths::new(Some(fixture.home.clone())).unwrap();
        let mut config = agent_remote_cli::config::Config::load(&paths).unwrap();
        let state = agent_remote_cli::local_state::LocalState::open(&paths).unwrap();
        state
            .set_kv(
                &format!(
                    "device-token-refresh-at:{}:{DEVICE}",
                    config.server_url.as_ref().unwrap()
                ),
                "0",
            )
            .unwrap();
        drop(state);
        if changed_server {
            config.server_url = Some("https://changed.invalid".into());
        } else {
            config.active_device_id = Some(SESSION.into());
        }
        config.save(&paths).unwrap();
        let output = command.output().unwrap();
        assert!(!output.status.success());
        redacted(&output);
        assert!(fixture.wires().is_empty());
        assert!(captured(&fixture).is_none());
    }
}

#[test]
fn exact_session_holds_configuration_lock_during_credential_refresh() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let fixture = Fixture::with_device(
        vec![
            envelope(json!({"access_token":"refreshed-device-token","expires_in":3600})),
            envelope(authorization("succeeded")),
        ],
        Some(Box::new(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        })),
        DEVICE,
    );
    let paths = agent_remote_cli::config::AppPaths::new(Some(fixture.home.clone())).unwrap();
    let mut config = agent_remote_cli::config::Config::load(&paths).unwrap();
    let state = agent_remote_cli::local_state::LocalState::open(&paths).unwrap();
    state
        .set_kv(
            &format!(
                "device-token-refresh-at:{}:{DEVICE}",
                config.server_url.as_ref().unwrap()
            ),
            "0",
        )
        .unwrap();
    drop(state);
    let child = native(&fixture, SSH).spawn().unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    config.active_device_id = Some(SESSION.into());
    assert!(
        config.save(&paths).is_err(),
        "configuration changed during device refresh"
    );
    release_tx.send(()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    redacted(&output);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("refreshed-device-token"));
    let wires = fixture.wires();
    assert_eq!(wires.len(), 2);
    assert!(wires[0].starts_with("POST /api/v1/auth/refresh HTTP/1.1"));
    assert!(wires[1].starts_with(&format!(
        "POST /api/v1/sessions/{SESSION}/attach/exact HTTP/1.1"
    )));
    assert!(wires[1]
        .to_ascii_lowercase()
        .contains("authorization: bearer refreshed-device-token"));
}

#[test]
fn exact_session_login_wait_rechecks_original_context_before_refresh() {
    let fixture = fixture(vec![]);
    let paths = agent_remote_cli::config::AppPaths::new(Some(fixture.home.clone())).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let guard = runtime
        .block_on(agent_remote_cli::auth::login::lock(&paths))
        .unwrap();
    let child = native(&fixture, SSH).spawn().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let mut config = agent_remote_cli::config::Config::load(&paths).unwrap();
    config.active_device_id = Some(SESSION.into());
    config.save(&paths).unwrap();
    drop(guard);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    redacted(&output);
    assert!(fixture.wires().is_empty());
    assert!(captured(&fixture).is_none());
}

#[test]
fn exact_session_invalid_prefix_nil_device_and_unpaired_flags_touch_no_http() {
    let fixture = fixture(vec![]);
    for args in [
        vec![
            "attach",
            "11111111",
            "--expected-server",
            fixture.context["server_url"].as_str().unwrap(),
            "--expected-device",
            DEVICE,
        ],
        vec![
            "attach",
            SESSION,
            "--expected-server",
            fixture.context["server_url"].as_str().unwrap(),
            "--expected-device",
            "00000000-0000-0000-0000-000000000000",
        ],
        vec!["attach", SESSION, "--expected-device", DEVICE],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_fclaude"))
            .args(args)
            .env("AGENT_REMOTE_HOME", &fixture.home)
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .output()
            .unwrap();
        assert!(!output.status.success());
        redacted(&output);
    }
    assert!(fixture.wires().is_empty());
}

#[test]
fn exact_session_cancellation_after_post_never_replays_or_starts_ssh() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let fixture = Fixture::with_device(
        vec![Reply {
            status: 200,
            body: None,
            advertised_length: None,
        }],
        Some(Box::new(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        })),
        DEVICE,
    );
    let child = native(&fixture, SSH).spawn().unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let output = child.wait_with_output().unwrap();
    release_tx.send(()).unwrap();
    assert!(!output.status.success());
    redacted(&output);
    assert!(captured(&fixture).is_none());
    assert_eq!(fixture.wires().len(), 1);
}

#[test]
fn exact_session_ssh_lifetime_releases_locks_and_cancellation_reaps_child() {
    let fixture = fixture(vec![envelope(authorization("succeeded"))]);
    let child = native(
        &fixture,
        "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$TEST_BINDING_SSH_ARGS\"\nexec sleep 30\n",
    )
    .spawn()
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Some(value) = captured(&fixture) {
            break value[0].parse::<i32>().unwrap();
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    };
    let paths = agent_remote_cli::config::AppPaths::new(Some(fixture.home.clone())).unwrap();
    let mut config = agent_remote_cli::config::Config::load(&paths).unwrap();
    config.active_device_id = Some(SESSION.into());
    config.save(&paths).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let guard = runtime
        .block_on(agent_remote_cli::auth::login::lock(&paths))
        .unwrap();
    drop(guard);
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    redacted(&output);
    let deadline = Instant::now() + Duration::from_secs(3);
    while unsafe { libc::kill(pid, 0) } == 0 {
        assert!(Instant::now() < deadline, "SSH child survived cancellation");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fixture.wires().len(), 1);
}

#[test]
fn exact_session_real_pty_cancellation_reaps_owned_ssh() {
    let fixture = fixture(vec![envelope(authorization("succeeded"))]);
    let native = native(
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
