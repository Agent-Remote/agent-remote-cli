use agent_remote_cli::api::{ApiClient, CreateSessionRequest};
use agent_remote_cli::session_creation::{create_with_takeover_wait, CreationExit};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const OP: &str = "11111111-1111-4111-8111-111111111111";
const ACCOUNT: &str = "22222222-2222-4222-8222-222222222222";
const WORKSPACE: &str = "33333333-3333-4333-8333-333333333333";
const SESSION: &str = "44444444-4444-4444-8444-444444444444";
const CHECKPOINT: &str = "55555555-5555-4555-8555-555555555555";

type Requests = Arc<Mutex<Vec<(String, Value)>>>;
struct Server {
    url: String,
    requests: Requests,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(steps: Vec<(u16, Value, Duration)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests: Requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let task = tokio::spawn(async move {
            let mut index = 0;
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let mut chunk = [0u8; 4096];
                let (line, body) = loop {
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert!(count > 0 && data.len() < 32768);
                    data.extend_from_slice(&chunk[..count]);
                    if let Some(end) = data.windows(4).position(|part| part == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&data[..end]);
                        assert!(header
                            .to_lowercase()
                            .contains("authorization: bearer device-test"));
                        let length = header
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|s| s.parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if data.len() >= end + 4 + length {
                            let body = if length == 0 {
                                Value::Null
                            } else {
                                serde_json::from_slice(&data[end + 4..end + 4 + length]).unwrap()
                            };
                            break (header.lines().next().unwrap().to_owned(), body);
                        }
                    }
                };
                seen.lock().unwrap().push((line, body));
                let (status, body, delay) = &steps[index.min(steps.len() - 1)];
                index += 1;
                tokio::time::sleep(*delay).await;
                let body = body.to_string();
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    async fn create(&self, bound: Duration) -> anyhow::Result<agent_remote_cli::api::SessionData> {
        create_with_takeover_wait(
            &ApiClient::new(self.url.clone()).unwrap(),
            "device-test",
            &request(),
            bound,
        )
        .await
    }

    fn requests(&self) -> Vec<(String, Value)> {
        self.requests.lock().unwrap().clone()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn request() -> CreateSessionRequest {
    CreateSessionRequest {
        tool_type: "claude".into(),
        tool_account_id: ACCOUNT.into(),
        workspace_id: WORKSPACE.into(),
        project_key: "project".into(),
        argv: vec!["--resume".into(), "original".into()],
        replaces_session_id: Some(OP.into()),
    }
}
fn pending() -> Value {
    json!({"error":{"code":"MIGRATION_PENDING","message":"pending","details":{"account_id":ACCOUNT,"takeover_id":OP,"takeover_status":"reserved","reservation_committed":true,"session_created":false}}})
}
fn progress(status: &str) -> Value {
    json!({"data":{"operation_id":OP,"account_id":ACCOUNT,"status":status,"task_status":"running","checkpoint_id":if status=="committed" {Some(CHECKPOINT)} else {None},"recovery_required":false}})
}
fn created() -> Value {
    json!({"data":{"user_id":OP,"created_at":"2026-09-24T00:00:00Z","updated_at":"2026-09-24T00:00:00Z","id":SESSION,"tool_type":"claude","tool_account_id":ACCOUNT,"workspace_id":WORKSPACE,"node_id":OP,"project_key":"project","status":"starting","runtime_backend":"native"}})
}
fn step(status: u16, body: Value) -> (u16, Value, Duration) {
    (status, body, Duration::ZERO)
}

#[tokio::test]
async fn takeover_wait_reads_original_and_submits_one_identical_creation_after_commit() {
    let server = Server::start(vec![
        step(409, pending()),
        step(200, progress("reserved")),
        step(200, progress("committed")),
        step(200, created()),
    ])
    .await;
    let session = server.create(Duration::from_secs(3)).await.unwrap();
    assert_eq!(session.id, SESSION);
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].0.starts_with("POST /api/v1/sessions "));
    assert_eq!(requests[0].1, serde_json::to_value(request()).unwrap());
    assert_eq!(requests[0], requests[3]);
    assert!(requests[1]
        .0
        .starts_with(&format!("GET /api/v1/sessions/skill-takeovers/{OP} ")));
    assert_eq!(requests[1], requests[2]);
}

#[tokio::test]
async fn ordinary_creation_is_one_request_without_takeover_polling() {
    let server = Server::start(vec![step(200, created())]).await;
    assert_eq!(
        server.create(Duration::from_secs(1)).await.unwrap().id,
        SESSION
    );
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn malformed_or_legacy_pending_error_never_authorizes_replay() {
    for field in [
        "session_created",
        "reservation_committed",
        "account_id",
        "takeover_id",
        "takeover_status",
        "missing",
    ] {
        let mut response = pending();
        match field {
            "session_created" => response["error"]["details"][field] = json!(true),
            "reservation_committed" => response["error"]["details"][field] = json!(false),
            "account_id" => response["error"]["details"][field] = json!(OP),
            "takeover_id" => response["error"]["details"][field] = json!("../private"),
            "takeover_status" => response["error"]["details"][field] = json!("committed"),
            _ => {
                response["error"].as_object_mut().unwrap().remove("details");
            }
        }
        let server = Server::start(vec![step(409, response)]).await;
        assert!(
            server.create(Duration::from_secs(1)).await.is_err(),
            "{field}"
        );
        assert_eq!(server.requests().len(), 1, "{field}");
    }
}

#[tokio::test]
async fn changed_progress_or_false_commit_cannot_create_a_session() {
    for field in ["operation_id", "account_id", "checkpoint_id", "task_status"] {
        let mut view = progress("committed");
        view["data"][field] = if field == "checkpoint_id" {
            Value::Null
        } else {
            json!("changed")
        };
        let server = Server::start(vec![step(409, pending()), step(200, view)]).await;
        assert!(
            server.create(Duration::from_secs(1)).await.is_err(),
            "{field}"
        );
        assert_eq!(server.requests().len(), 2);
    }
}

#[tokio::test]
async fn takeover_timeout_covers_http_and_preserves_the_operation() {
    let server = Server::start(vec![
        step(409, pending()),
        (200, progress("reserved"), Duration::from_secs(2)),
    ])
    .await;
    let error = server.create(Duration::from_millis(80)).await.unwrap_err();
    assert_eq!(error.downcast_ref::<CreationExit>().unwrap().0, 3);
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn cancelled_original_task_requires_recovery_without_creation() {
    let mut view = progress("reserved");
    view["data"]["task_status"] = json!("cancelled");
    view["data"]["recovery_required"] = json!(true);
    let server = Server::start(vec![step(409, pending()), step(200, view)]).await;
    assert!(server
        .create(Duration::from_secs(1))
        .await
        .unwrap_err()
        .to_string()
        .contains("requires recovery"));
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn uncertain_resumed_creation_is_never_repeated() {
    let server = Server::start(vec![
        step(409, pending()),
        step(200, progress("committed")),
        step(
            500,
            json!({"error":{"code":"TEMPORARY","message":"unknown"}}),
        ),
    ])
    .await;
    assert!(server.create(Duration::from_secs(1)).await.is_err());
    assert_eq!(server.requests().len(), 3);
    assert_eq!(server.requests()[0], server.requests()[2]);
}

#[cfg(unix)]
#[test]
fn creation_interrupt_probe() {
    let Ok(url) = std::env::var("AGENT_REMOTE_TEST_TAKEOVER_URL") else {
        return;
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let error = runtime
        .block_on(create_with_takeover_wait(
            &ApiClient::new(url).unwrap(),
            "device-test",
            &request(),
            Duration::from_secs(10),
        ))
        .unwrap_err();
    std::process::exit(
        error
            .downcast_ref::<CreationExit>()
            .map_or(1, |exit| exit.0),
    );
}

#[cfg(unix)]
#[tokio::test]
async fn ctrl_c_interrupts_status_http_without_replaying_creation() {
    let server = Server::start(vec![
        step(409, pending()),
        (200, progress("reserved"), Duration::from_secs(5)),
    ])
    .await;
    let child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "creation_interrupt_probe", "--nocapture"])
        .env("AGENT_REMOTE_TEST_TAKEOVER_URL", &server.url)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while server.requests().len() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(tokio::process::Command::new("kill")
        .args(["-INT", &child.id().unwrap().to_string()])
        .status()
        .await
        .unwrap()
        .success());
    let output = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(OP));
    assert_eq!(server.requests().len(), 2);
}
