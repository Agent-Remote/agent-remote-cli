use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use agent_remote_cli::config::{AppPaths, Config};
use serde_json::{json, Value};

fn params(server: &str, key: Option<&Path>) -> Value {
    let mut params = super::login::params(server, key);
    for field in ["username", "password", "totp_code"] {
        params.as_object_mut().unwrap().remove(field);
    }
    params
}

fn start(expires_in: u64, interval: u64) -> Value {
    json!({"data":{"device_code":"private-device-code","user_code":"ABCD-EFGH",
        "verification_url":"https://web.example.test/cli?code=ABCD-EFGH",
        "expires_in":expires_in,"interval":interval}})
}

fn pending() -> Value {
    json!({"error":{"code":"COMMON_BAD_REQUEST","message":"CLI login is not approved."}})
}

fn spawn(home: &Path, input: Value) -> Child {
    spawn_with_request(home, super::request("login.device_code", input))
}

fn spawn_with_request(home: &Path, request: Vec<u8>) -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&request).unwrap();
    child
}

fn invoke(home: &Path, input: Value) -> (bool, Vec<Value>) {
    let output = spawn(home, input).wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.ends_with('\n'));
    for secret in [
        "private-device-code",
        "private-access",
        "private-session",
        "private-refresh",
        "private-device",
    ] {
        assert!(!text.contains(secret), "stream leaked secret");
    }
    let events: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!((1..=2).contains(&events.len()));
    for event in &events {
        assert_eq!(event["request_id"], "query-123");
        assert_eq!(event["protocol_version"], 1);
    }
    if events.len() == 2 {
        assert_eq!(events[0]["type"], "progress");
        assert_eq!(events[0]["phase"], "awaiting_approval");
        assert_eq!(events[0]["progress"].as_object().unwrap().len(), 4);
        assert_eq!(events[0]["progress"]["user_code"], "ABCD-EFGH");
    }
    (output.status.success(), events)
}

#[test]
fn browser_approval_polls_only_pending_and_registers_once() {
    let temp = tempfile::tempdir().unwrap();
    let key = super::login::key(temp.path());
    let (url, http) = super::login::server(vec![
        (200, start(600, 1)),
        (400, pending()),
        (200, super::login::token()),
        (200, super::login::registered("device-1")),
        (200, super::login::pair()),
    ]);
    let (ok, events) = invoke(temp.path(), params(&url, Some(&key)));
    assert!(ok, "{events:?}");
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["result"]["registered_device_id"], "device-1");
    assert_eq!(events[1]["result"]["operation_id"], "query-123");
    let requests = http.join().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].starts_with("POST /api/v1/auth/cli/start "));
    for request in &requests[1..3] {
        assert!(request.starts_with("POST /api/v1/auth/cli/complete "));
        assert!(request.contains("\"device_code\":\"private-device-code\""));
    }
    assert!(requests[3].starts_with("POST /api/v1/devices/register "));
    let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
    let config = Config::load(&paths).unwrap();
    assert_eq!(config.server_url.as_deref(), Some(url.as_str()));
    assert_eq!(config.active_device_id.as_deref(), Some("device-1"));
    let db = std::fs::read(paths.state_db_path()).unwrap();
    for secret in [
        b"private-device-code".as_slice(),
        b"private-access",
        b"private-device",
        b"private-refresh",
    ] {
        assert!(!db.windows(secret.len()).any(|w| w == secret));
    }
}

#[test]
fn opt_in_stream_places_started_before_browser_approval() {
    let temp = tempfile::tempdir().unwrap();
    let key = super::login::key(temp.path());
    let (url, http) = super::login::server(vec![
        (200, start(600, 1)),
        (400, pending()),
        (200, super::login::token()),
        (200, super::login::registered("device-1")),
        (200, super::login::pair()),
    ]);
    let mut input = params(&url, Some(&key));
    let request = super::streaming_request("login.device_code", input.take());
    let output = spawn_with_request(temp.path(), request)
        .wait_with_output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["phase"], "started");
    assert_eq!(events[0]["progress"]["operation"], "login.device_code");
    assert_eq!(events[1]["phase"], "awaiting_approval");
    assert_eq!(events[2]["type"], "result");
    assert_eq!(http.join().unwrap().len(), 5);
}

#[test]
fn browser_rejection_expiry_and_uncertain_completion_never_retry_or_publish() {
    for (status, body, expected) in [
        (
            403,
            json!({"error":{"message":"private-device-code"}}),
            "login_rejected",
        ),
        (
            401,
            json!({"error":{"code":"AUTH_TOKEN_EXPIRED","message":"private-device-code"}}),
            "login_expired",
        ),
        (
            503,
            json!({"error":{"message":"private-access"}}),
            "login_outcome_unknown",
        ),
        (
            200,
            json!({"data":{"access_token":"","expires_in":3600}}),
            "login_outcome_unknown",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (url, http) = super::login::server(vec![(200, start(600, 1)), (status, body)]);
        let (ok, events) = invoke(temp.path(), params(&url, None));
        assert!(!ok);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1]["error"]["code"], expected);
        assert_eq!(events[1]["error"]["retryable"], false);
        assert_eq!(http.join().unwrap().len(), 2);
        assert!(!temp.path().join("config.toml").exists());
    }
}

#[test]
fn pending_code_expires_without_an_extra_completion_request() {
    let temp = tempfile::tempdir().unwrap();
    let (url, http) = super::login::server(vec![(200, start(1, 1)), (400, pending())]);
    let (ok, events) = invoke(temp.path(), params(&url, None));
    assert!(!ok);
    assert_eq!(events[1]["error"]["code"], "login_expired");
    assert_eq!(http.join().unwrap().len(), 2);
    assert!(!temp.path().join("config.toml").exists());
}

#[test]
fn browser_progress_is_flushed_before_completion_and_cancel_keeps_state_unpublished() {
    let temp = tempfile::tempdir().unwrap();
    let (url, http) = super::login::server(vec![(200, start(600, 60)), (400, pending())]);
    let mut child = spawn(temp.path(), params(&url, None));
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let progress: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(progress["phase"], "awaiting_approval");
    assert!(!line.contains("private-device-code"));
    assert_eq!(http.join().unwrap().len(), 2);
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    let mut rest = String::new();
    reader.read_to_string(&mut rest).unwrap();
    assert!(
        rest.is_empty(),
        "cancellation cannot invent a completion receipt"
    );
    assert!(!temp.path().join("config.toml").exists());
}

#[test]
fn invalid_approval_data_is_never_forwarded_or_polled() {
    for (field, value) in [
        ("verification_url", json!("javascript:private-device-code")),
        (
            "verification_url",
            json!("https://web.example.test/cli?token=private-device-code"),
        ),
        (
            "verification_url",
            json!("https://web.example.test/cli?other=credential"),
        ),
        (
            "verification_url",
            json!("https://web.example.test/%70rivate-device-code?code=ABCD-EFGH"),
        ),
        (
            "verification_url",
            json!("https://web.example.test/%2570rivate-device-code?code=ABCD-EFGH"),
        ),
        (
            "verification_url",
            json!("https://web.example.test/%252570rivate-device-code?code=ABCD-EFGH"),
        ),
        ("user_code", json!("private-device-code")),
        ("expires_in", json!(0)),
        ("expires_in", json!(1801)),
        ("interval", json!(0)),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut reply = start(600, 1);
        reply["data"][field] = value;
        let (url, http) = super::login::server(vec![(200, reply)]);
        let (ok, events) = invoke(temp.path(), params(&url, None));
        assert!(!ok);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["error"]["code"], "login_outcome_unknown");
        assert_eq!(http.join().unwrap().len(), 1);
        assert!(!temp.path().join("config.toml").exists());
    }
}

#[test]
fn browser_confirmation_context_and_key_validation_precede_start() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let mut input = params("https://unused.invalid", None);
    input["confirmed"] = json!(false);
    let (_, events) = invoke(&home, input);
    assert_eq!(events[0]["error"]["code"], "confirmation_required");
    let mut input = params("https://unused.invalid", None);
    input["expected_context"]["server_url"] = json!("https://stale.invalid");
    let (_, events) = invoke(&home, input);
    assert_eq!(events[0]["error"]["code"], "configuration_changed");
    let path = temp.path().join("private.key");
    std::fs::write(&path, "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate").unwrap();
    let (_, events) = invoke(&home, params("https://unused.invalid", Some(&path)));
    assert_eq!(events[0]["error"]["code"], "ssh_public_key_required");
    assert!(!home.exists());
}

#[test]
fn browser_user_only_login_uses_the_shared_user_session_without_registering() {
    let temp = tempfile::tempdir().unwrap();
    let (url, http) = super::login::server(vec![
        (200, start(600, 1)),
        (200, super::login::token()),
        (200, super::login::pair()),
    ]);
    let (ok, events) = invoke(temp.path(), params(&url, None));
    assert!(ok, "{events:?}");
    assert!(events[1]["result"]["registered_device_id"].is_null());
    assert_eq!(http.join().unwrap().len(), 3);
    let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
    assert_eq!(
        Config::load(&paths).unwrap().server_url.as_deref(),
        Some(url.as_str())
    );
}

#[test]
fn changing_configuration_during_browser_approval_stops_polling() {
    let temp = tempfile::tempdir().unwrap();
    let (url, http) = super::login::server(vec![(200, start(600, 1)), (400, pending())]);
    let child = spawn(temp.path(), params(&url, None));
    assert_eq!(http.join().unwrap().len(), 2);
    let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
    let changed = Config {
        server_url: Some("https://changed.invalid".into()),
        active_device_id: None,
    };
    changed.save(&paths).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["error"]["code"], "configuration_changed");
    assert_eq!(Config::load(&paths).unwrap(), changed);
}

#[test]
fn disconnected_completion_is_unknown_without_retrying() {
    use std::net::TcpListener;
    use std::time::{Duration, Instant};
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let fixture = std::thread::spawn(move || {
        for index in 0..2 {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("missing browser login request: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut length = 0;
            let mut head = String::new();
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                head.push_str(&line);
                assert!(head.len() < 65536);
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            assert!(length < 65536);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            if index == 0 {
                let response = start(600, 1).to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
            } else {
                assert!(head.starts_with("POST /api/v1/auth/cli/complete "));
                // The server received the code but the response is lost. Do not
                // invent a failed authorization or replay a token-issuing request.
                assert!(String::from_utf8(body)
                    .unwrap()
                    .contains("private-device-code"));
            }
        }
    });
    let (ok, events) = invoke(temp.path(), params(&url, None));
    assert!(!ok);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["error"]["code"], "login_outcome_unknown");
    assert_eq!(events[1]["error"]["retryable"], false);
    fixture.join().unwrap();
    assert!(!temp.path().join("config.toml").exists());
}

#[test]
fn disconnected_completion_recovers_only_by_original_key() {
    let temp = tempfile::tempdir().unwrap();
    let (url, http) = super::login::server(vec![
        (200, start(600, 1)),
        (
            503,
            json!({"error":{"code":"SERVER_UNAVAILABLE","message":"lost"}}),
        ),
        (200, super::login::token()),
        (200, super::login::pair()),
    ]);
    let (ok, events) = invoke(temp.path(), params(&url, None));
    assert!(ok, "{events:?}");
    let requests = http.join().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("POST /api/v1/auth/cli/start "));
    assert!(requests[1].starts_with("POST /api/v1/auth/cli/complete "));
    assert!(requests[1].contains("private-device-code"));
    assert!(requests[2].starts_with("GET /api/v1/auth/cli/completions/"));
    assert!(!requests[2].contains("private-device-code"));
    assert!(!requests[2].contains("private-access"));
    assert!(requests[3].starts_with("POST /api/v1/auth/cli/session "));
}

#[tokio::test]
async fn browser_approval_registers_the_prepared_key_when_the_source_file_changes() {
    use base64::Engine;
    let temp = tempfile::tempdir().unwrap();
    let key = super::login::key(temp.path());
    let original = std::fs::read_to_string(&key).unwrap();
    let mut changed_bytes = base64::engine::general_purpose::STANDARD
        .decode(original.split_whitespace().nth(1).unwrap())
        .unwrap();
    *changed_bytes.last_mut().unwrap() = 99;
    let replacement = format!(
        "ssh-ed25519 {} changed",
        base64::engine::general_purpose::STANDARD.encode(changed_bytes)
    );
    let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
    // Keep publication behind a real cross-process lock, so the key replacement
    // deterministically precedes registration even under unusual scheduling.
    let guard = agent_remote_cli::auth::login::lock(&paths).await.unwrap();
    let (url, http) = super::login::server(vec![
        (200, start(600, 1)),
        (400, pending()),
        (200, super::login::token()),
        (200, super::login::registered("device-1")),
        (200, super::login::pair()),
    ]);
    let mut child = spawn(temp.path(), params(&url, Some(&key)));
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let progress: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(progress["phase"], "awaiting_approval");
    std::fs::write(&key, &replacement).unwrap();
    drop(guard);
    let mut terminal = String::new();
    reader.read_to_string(&mut terminal).unwrap();
    assert!(child.wait().unwrap().success(), "{terminal}");
    let result: Value = serde_json::from_str(&terminal).unwrap();
    assert_eq!(result["result"]["registered_device_id"], "device-1");
    let requests = http.join().unwrap();
    let registration: Value =
        serde_json::from_str(requests[3].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(registration["ssh_public_key"], original);
    assert_ne!(registration["ssh_public_key"], replacement);
    assert_eq!(std::fs::read_to_string(&key).unwrap(), replacement);
}
