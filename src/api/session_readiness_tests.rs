use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::super::ApiClient;

struct Server {
    client: ApiClient,
    requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(responses: Vec<Value>, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = ApiClient::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let task = tokio::spawn(async move {
            for response in responses.iter().chain(responses.last().into_iter().cycle()) {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let count = socket.read(&mut buffer).await.unwrap();
                    assert!(count > 0 && request.len() < 32768);
                    request.extend_from_slice(&buffer[..count]);
                }
                seen.lock().unwrap().push(
                    String::from_utf8(request)
                        .unwrap()
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned(),
                );
                tokio::time::sleep(delay).await;
                let body = response.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        Self {
            client,
            requests,
            task,
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn session(status: &str) -> Value {
    json!({"data": {
        "id": "original", "tool_type": "claude", "user_id": "user",
        "tool_account_id": "account", "workspace_id": "workspace", "node_id": "node",
        "project_key": "project", "status": status, "runtime_backend": "native",
        "created_at": "2026-09-29T00:00:00Z", "updated_at": "2026-09-29T00:00:00Z"
    }})
}

fn attach() -> Value {
    json!({"data": {
        "session_id": "original", "node_id": "node", "node_wireguard_ip": "10.77.0.1",
        "ssh_host": "10.77.0.1", "ssh_port": 22, "ssh_user": "test",
        "tmux_session_name": "original", "command_args": [], "ssh_command": "ssh test",
        "authorization_task_id": "key-sync", "authorization_task_status": "succeeded",
        "expires_in": 60
    }})
}

#[tokio::test]
async fn attach_waits_for_original_session_before_requesting_authorization() {
    for ready in ["running", "active"] {
        let server = Server::start(
            vec![session("starting"), session(ready), attach()],
            Duration::ZERO,
        )
        .await;
        let result = server
            .client
            .attach_session("test", "original")
            .await
            .unwrap();
        assert_eq!(result.session_id, "original");
        assert_eq!(
            server.requests(),
            vec![
                "GET /api/v1/sessions/original HTTP/1.1",
                "GET /api/v1/sessions/original HTTP/1.1",
                "POST /api/v1/sessions/original/attach HTTP/1.1",
            ]
        );
    }
}

#[tokio::test]
async fn terminal_and_unknown_states_never_request_attach() {
    for status in ["failed", "stopped", "interrupted", "stopping", "unknown"] {
        let server = Server::start(vec![session(status)], Duration::ZERO).await;
        let error = server
            .client
            .attach_session("test", "original")
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some("SESSION_NOT_ATTACHABLE"));
        assert!(error.message.contains(status));
        assert_eq!(
            server.requests(),
            vec!["GET /api/v1/sessions/original HTTP/1.1"]
        );
    }
}

#[tokio::test]
async fn startup_timeout_retains_original_id_and_bounds_slow_requests() {
    for delay in [Duration::ZERO, Duration::from_secs(10)] {
        let server = Server::start(vec![session("starting")], delay).await;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            server.client.wait_for_session_readiness(
                "test",
                "original",
                Duration::from_millis(100),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(result.code(), Some("SESSION_START_TIMEOUT"));
        assert!(result.message.contains("agent-remote attach original"));
        assert_eq!(
            server.requests(),
            vec!["GET /api/v1/sessions/original HTTP/1.1"]
        );
    }
}

#[tokio::test]
async fn mismatched_session_never_requests_attach() {
    let mut response = session("running");
    response["data"]["id"] = json!("different");
    let server = Server::start(vec![response], Duration::ZERO).await;
    let error = server
        .client
        .attach_session("test", "original")
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("SESSION_IDENTITY_MISMATCH"));
    assert_eq!(
        server.requests(),
        vec!["GET /api/v1/sessions/original HTTP/1.1"]
    );
}

#[tokio::test]
async fn timeout_can_be_retried_without_recreating_the_session() {
    let server = Server::start(
        vec![session("starting"), session("running"), attach()],
        Duration::ZERO,
    )
    .await;
    let error = server
        .client
        .wait_for_session_readiness("test", "original", Duration::from_millis(100))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("SESSION_START_TIMEOUT"));
    let result = server
        .client
        .attach_session("test", "original")
        .await
        .unwrap();
    assert_eq!(result.session_id, "original");
    assert_eq!(
        server.requests(),
        vec![
            "GET /api/v1/sessions/original HTTP/1.1",
            "GET /api/v1/sessions/original HTTP/1.1",
            "POST /api/v1/sessions/original/attach HTTP/1.1",
        ]
    );
}
