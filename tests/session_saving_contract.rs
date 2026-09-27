#![cfg(unix)]

use agent_remote_cli::{config::AppPaths, local_state::LocalState};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const OP: &str = "55555555-5555-4555-8555-555555555555";
const SESSION: &str = "44444444-4444-4444-8444-444444444444";

struct Server {
    url: String,
    done: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    join: Option<JoinHandle<()>>,
}

impl Server {
    fn new(states: Vec<Value>, legacy: bool, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let done = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopped = done.clone();
        let seen = requests.clone();
        let join = thread::spawn(move || {
            let mut index = 0;
            while !stopped.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut buffer = [0; 8192];
                let mut count = 0;
                while count < buffer.len() && !buffer[..count].windows(4).any(|v| v == b"\r\n\r\n")
                {
                    let read = stream.read(&mut buffer[count..]).unwrap();
                    if read == 0 {
                        break;
                    }
                    count += read;
                }
                if count == 0 {
                    continue;
                }
                let request = String::from_utf8_lossy(&buffer[..count]);
                assert!(request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-device-token"));
                let line = request.lines().next().unwrap().to_owned();
                seen.lock().unwrap().push(line.clone());
                let body = if line.contains("skill-finalizations") {
                    thread::sleep(delay);
                    let value = states[index.min(states.len() - 1)].clone();
                    index += 1;
                    json!({"data":value})
                } else if line.starts_with("POST ") {
                    json!({"data":session(legacy)})
                } else {
                    json!({"data":{"items":[session(legacy)]}})
                };
                let encoded = body.to_string();
                let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",encoded.len(),encoded);
            }
        });
        Self {
            url,
            done,
            requests,
            join: Some(join),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        let joined = self.join.take().unwrap().join();
        if !thread::panicking() {
            joined.unwrap();
        }
    }
}

fn session(legacy: bool) -> Value {
    json!({"id":SESSION,"tool_type":"claude","user_id":OP,"tool_account_id":OP,
        "workspace_id":OP,"node_id":OP,"project_key":"p","status":"stopping",
        "runtime_backend":"native","created_at":"now","updated_at":"now",
        "skill_finalization_operation_id":if legacy {None} else {Some(OP)},
        "stop_task_id":format!("stop_tool_session:{SESSION}")})
}
fn state(status: &str, stopped: bool) -> Value {
    let retained = matches!(
        status,
        "persisted" | "published" | "conflicted" | "detached" | "superseded"
    );
    json!({"operation_id":OP,"session_id":SESSION,"account_id":OP,
        "process_status":if stopped {"stopped"} else {"stopping"},"process_stopped":stopped,
        "status":status,"unclean":false,"content_retained":retained,
        "finalization_id":if status=="local_durable" {None} else {Some(OP)},"checkpoint_id":if retained {Some(OP)} else {None},
        "publication_id":if matches!(status,"published"|"conflicted"|"detached"|"superseded") {Some(OP)} else {None}})
}
fn command(server: &Server, home: &std::path::Path) -> Command {
    fs::create_dir_all(home.join("secrets")).unwrap();
    fs::write(
        home.join("config.toml"),
        format!(
            "server_url = {:?}\nactive_device_id = \"device-1\"\n",
            server.url
        ),
    )
    .unwrap();
    let key: String = format!("device-token:{}:device-1", server.url)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = home.join("secrets").join(format!("{key}.secret"));
    fs::write(&path, "test-device-token").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    let local = LocalState::open(&AppPaths::new(Some(home.to_owned())).unwrap()).unwrap();
    local.init_schema().unwrap();
    local
        .set_kv(
            &format!("device-token-refresh-at:{}:device-1", server.url),
            "4102444800",
        )
        .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fclaude"));
    cmd.env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("NO_COLOR", "1");
    cmd
}
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn stop_waits_through_persisted_until_published() {
    let server = Server::new(
        vec![state("persisted", true), state("published", true)],
        false,
        Duration::ZERO,
    );
    let home = tempfile::tempdir().unwrap();
    let output = command(&server, home.path())
        .args(["stop", SESSION, "--timeout", "5"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    assert!(text(&output).contains(OP) && text(&output).contains("published"));
    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests.iter().filter(|v| v.starts_with("POST ")).count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|v| v.contains("skill-finalizations"))
            .count(),
        2
    );
}

#[test]
fn stop_timeout_distinguishes_stopped_from_pending_and_legacy() {
    for legacy in [false, true] {
        let server = Server::new(vec![state("upload_pending", true)], legacy, Duration::ZERO);
        let home = tempfile::tempdir().unwrap();
        let output = command(&server, home.path())
            .args(["stop", SESSION, "--timeout", "1"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(if legacy { 0 } else { 3 }),
            "{}",
            text(&output)
        );
        if !legacy {
            assert!(text(&output).contains("Process stopped; data saving pending"));
        } else {
            assert!(!server
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|v| v.contains("skill-finalizations")));
        }
    }
}

#[test]
fn stop_status_is_read_only_and_conflicts_require_review() {
    for (phase, code) in [
        ("local_durable", 0),
        ("conflicted", 1),
        ("detached", 1),
        ("superseded", 1),
    ] {
        let server = Server::new(vec![state(phase, true)], false, Duration::ZERO);
        let home = tempfile::tempdir().unwrap();
        let output = command(&server, home.path())
            .args(["stop-status", OP])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{}", text(&output));
        assert!(text(&output).contains(phase));
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        assert!(server.requests.lock().unwrap()[0]
            .starts_with("GET /api/v1/sessions/skill-finalizations/"));
    }
}

#[test]
fn status_wait_is_bounded_during_http_and_rejects_changed_identity() {
    let server = Server::new(
        vec![state("upload_pending", true)],
        false,
        Duration::from_secs(3),
    );
    let home = tempfile::tempdir().unwrap();
    let mut cmd = command(&server, home.path());
    let mut child = cmd
        .args(["stop-status", OP, "--wait", "--timeout", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let ready = Instant::now() + Duration::from_secs(10);
    while server.requests.lock().unwrap().is_empty() && Instant::now() < ready {
        assert!(
            child.try_wait().unwrap().is_none(),
            "child exited before status request"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(!server.requests.lock().unwrap().is_empty());
    // Authentication and process startup precede the saving deadline; measure the pending HTTP wait.
    let started = Instant::now();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", text(&output));
    assert!(started.elapsed() < Duration::from_secs(2));
    let mut changed = state("published", true);
    changed["operation_id"] = json!(SESSION);
    let server = Server::new(vec![changed], false, Duration::ZERO);
    let home = tempfile::tempdir().unwrap();
    let output = command(&server, home.path())
        .args(["stop-status", OP])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!text(&output).contains("published"));
}

#[test]
fn ctrl_c_ends_wait_without_resubmitting_stop() {
    let server = Server::new(
        vec![state("upload_pending", true)],
        false,
        Duration::from_secs(2),
    );
    let home = tempfile::tempdir().unwrap();
    let mut child = command(&server, home.path())
        .args(["stop-status", OP, "--wait"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while server.requests.lock().unwrap().is_empty() && Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            panic!("child exited before waiting");
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!server.requests.lock().unwrap().is_empty());
    assert!(Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130), "{}", text(&output));
}

#[test]
fn published_without_retained_checkpoint_identity_is_rejected() {
    let mut invalid = state("published", true);
    invalid["checkpoint_id"] = Value::Null;
    invalid["content_retained"] = json!(false);
    let server = Server::new(vec![invalid], false, Duration::ZERO);
    let home = tempfile::tempdir().unwrap();
    let output = command(&server, home.path())
        .args(["stop-status", OP])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(!text(&output).contains("published"));
}

#[test]
fn absent_node_observation_never_claims_stopped_or_locally_durable() {
    let mut pending = state("awaiting_node", false);
    pending["unclean"] = Value::Null;
    pending["finalization_id"] = Value::Null;
    let server = Server::new(vec![pending], false, Duration::ZERO);
    let home = tempfile::tempdir().unwrap();
    let output = command(&server, home.path())
        .args(["stop-status", OP, "--wait", "--timeout", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", text(&output));
    assert!(text(&output).contains("Process stop has not been confirmed"));
    assert!(!text(&output).contains("Process stopped; data saving pending"));
}

fn capture_pending(code: &str) -> Value {
    let mut pending = state("capture_pending", true);
    pending["finalization_id"] = Value::Null;
    pending["capture_error"] = json!(code);
    pending
}

#[test]
fn failed_capture_ends_wait_with_original_export_identity_and_can_recover() {
    for code in [
        "quota_exceeded",
        "insufficient_storage",
        "portability_error",
        "capture_failed",
    ] {
        let server = Server::new(
            vec![capture_pending(code), state("local_durable", true)],
            false,
            Duration::ZERO,
        );
        let home = tempfile::tempdir().unwrap();
        let output = command(&server, home.path())
            .args(["stop-status", OP, "--wait", "--timeout", "5"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{}", text(&output));
        let rendered = text(&output);
        assert!(rendered.contains(code) && rendered.contains("Process stopped; capture failed"));
        assert!(rendered.contains(&format!("--account-id {OP} --snapshot {OP}")));
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        let recovered = command(&server, home.path())
            .args(["stop-status", OP])
            .output()
            .unwrap();
        assert!(recovered.status.success(), "{}", text(&recovered));
        assert!(text(&recovered).contains("local_durable"));
        assert!(!text(&recovered).contains("capture failed"));
        assert!(server
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET ")));
    }
}

#[test]
fn capture_failure_requires_stopped_writers_and_no_durable_content() {
    for fault in [
        "unknown",
        "missing",
        "null",
        "running",
        "finalization",
        "checkpoint",
        "retained",
        "durable",
        "published",
        "unclean",
    ] {
        let mut invalid = capture_pending("quota_exceeded");
        match fault {
            "unknown" => invalid["capture_error"] = json!("private-error-path"),
            "missing" => {
                invalid.as_object_mut().unwrap().remove("capture_error");
            }
            "null" => invalid["capture_error"] = Value::Null,
            "running" => invalid["process_stopped"] = json!(false),
            "finalization" => invalid["finalization_id"] = json!(OP),
            "checkpoint" => invalid["checkpoint_id"] = json!(OP),
            "retained" => invalid["content_retained"] = json!(true),
            "durable" => invalid["status"] = json!("local_durable"),
            "published" => invalid["status"] = json!("published"),
            "unclean" => invalid["unclean"] = Value::Null,
            _ => unreachable!(),
        }
        let server = Server::new(vec![invalid], false, Duration::ZERO);
        let home = tempfile::tempdir().unwrap();
        let output = command(&server, home.path())
            .args(["stop-status", OP])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{fault}: {}", text(&output));
        assert!(
            !text(&output).contains("--snapshot"),
            "invalid recovery instruction: {fault}"
        );
        assert!(!text(&output).contains("private-error-path"));
    }
}
