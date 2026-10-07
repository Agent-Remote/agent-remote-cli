// Tests for src/port_forward.rs.

use std::{cmp::min, future::poll_fn, time::Duration};

#[cfg(windows)]
use super::assign_kill_on_close_job;
use super::{
    bind_loopback_listeners, client_instance_id, parse_local_port, proxy_stream,
    read_server_handshake, resolve_session, ServerHandshake,
};
#[cfg(unix)]
use super::{connect_ssh_tunnel, start_with_ssh, supervise_tunnel};
use crate::api::ApiClient;
#[cfg(unix)]
use crate::api::{CreatedPortForwardData, PortForwardConnectionData};
use crate::cli::{ForwardAction, ForwardArgs, ForwardStopArgs};
use crate::config::{AppPaths, Config};
use crate::local_state::{LocalDevice, LocalState};
use crate::secrets::{device_token_key, SecretStore};
use bytes::{Buf, Bytes};
use http::{Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[cfg(unix)]
fn client_handshake_size(forward_id: &str, connect_token: &str) -> usize {
    let payload = serde_json::to_vec(&super::ClientHandshake {
        forward_id: forward_id.to_string(),
        connect_token: connect_token.to_string(),
        client_version: crate::cli::VERSION.to_string(),
        max_streams: 128,
    })
    .unwrap();
    super::PROTOCOL_MAGIC.len() + std::mem::size_of::<u32>() + payload.len()
}

async fn fake_control_plane(
    response_bodies: Vec<String>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for body in response_bodies {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2048];
            let header_end = loop {
                let read = connection.read(&mut buffer).await.unwrap();
                assert!(read > 0, "control-plane request ended before headers");
                request.extend_from_slice(&buffer[..read]);
                if let Some(position) = request.windows(4).position(|value| value == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let read = connection.read(&mut buffer).await.unwrap();
                assert!(read > 0, "control-plane request body ended early");
                request.extend_from_slice(&buffer[..read]);
            }
            connection
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            requests.push(String::from_utf8(request).unwrap());
        }
        requests
    });
    (format!("http://{address}"), task)
}

#[cfg(windows)]
#[tokio::test]
async fn windows_job_closes_a_running_ssh_process() {
    let mut child = tokio::process::Command::new("cmd.exe")
        .args(["/D", "/C", "ping -n 30 127.0.0.1 >NUL"])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let job = assign_kill_on_close_job(&child).unwrap();
    drop(job);
    timeout(Duration::from_secs(3), child.wait())
        .await
        .expect("closing the SSH job did not terminate its child")
        .unwrap();
}

fn authenticated_paths(directory: &tempfile::TempDir, server_url: &str) -> AppPaths {
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    Config {
        server_url: Some(server_url.to_string()),
        active_device_id: Some("device-1".to_string()),
    }
    .save(&paths)
    .unwrap();
    SecretStore::file_only(paths.clone())
        .set_secret(&device_token_key(server_url, "device-1"), "device-token")
        .unwrap();
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state
        .set_kv(
            &format!("device-token-refresh-at:{server_url}:device-1"),
            &u64::MAX.to_string(),
        )
        .unwrap();
    state
        .upsert_device(&LocalDevice {
            id: "device-1".to_string(),
            server_url: server_url.to_string(),
            name: "test device".to_string(),
            platform: "test".to_string(),
            status: "active".to_string(),
            ssh_key_id: Some("ssh-key-1".to_string()),
            wireguard_peer_id: None,
            created_at: None,
            last_seen_at: None,
        })
        .unwrap();
    paths
}

fn forward_json(status: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "11111111-1111-4111-8111-111111111111", "user_id": "user-1", "device_id": "device-1",
        "session_id": "22222222-2222-4222-8222-222222222222", "node_id": "node-1", "remote_port": 5173,
        "requested_local_port": 4173, "client_instance_id": "client-1",
        "status": status, "bytes_up": 1024, "bytes_down": 2048, "connection_count": 2,
        "last_connected_at": null, "lease_expires_at": null,
        "expires_at": "2026-07-31T00:00:00Z", "stopped_at": null, "stop_reason": null,
        "created_at": "2026-07-30T00:00:00Z", "updated_at": "2026-07-30T00:00:00Z"
    })
}

fn session_json() -> serde_json::Value {
    serde_json::json!({
        "id": "22222222-2222-4222-8222-222222222222", "tool_type": "claude", "user_id": "user-1",
        "tool_account_id": "account-1", "workspace_id": "workspace-1",
        "workspace_local_path": null, "workspace_remote_path": "/workspace",
        "node_id": "node-1", "project_key": "project-1", "status": "running",
        "tmux_session_name": "session", "container_id": null, "runtime_backend": "native",
        "runtime_resource_id": "runtime-1", "replaces_session_id": null,
        "create_task_id": null, "stop_task_id": null,
        "created_at": "2026-07-30T00:00:00Z", "updated_at": "2026-07-30T00:00:00Z"
    })
}

fn forward_args(action: ForwardAction) -> ForwardArgs {
    ForwardArgs {
        remote_port: None,
        session: None,
        local_port: "same".to_string(),
        open: false,
        ttl_seconds: None,
        action: Some(action),
    }
}

#[tokio::test]
async fn list_command_uses_authenticated_port_forward_endpoint() {
    let body = serde_json::json!({"data": {"items": [forward_json("active")]}});
    let (server_url, server) = fake_control_plane(vec![body.to_string()]).await;
    let directory = tempfile::tempdir().unwrap();
    let paths = authenticated_paths(&directory, &server_url);

    super::run(&paths, &forward_args(ForwardAction::List), None)
        .await
        .unwrap();

    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/v1/port-forwards HTTP/1.1"));
    assert!(requests[0].contains("authorization: Bearer device-token"));
}

#[tokio::test]
async fn stop_command_resolves_forward_and_uses_delete_endpoint() {
    let listed = serde_json::json!({"data": {"items": [forward_json("active")]}});
    let stopped = serde_json::json!({"data": forward_json("stopped")});
    let (server_url, server) =
        fake_control_plane(vec![listed.to_string(), stopped.to_string()]).await;
    let directory = tempfile::tempdir().unwrap();
    let paths = authenticated_paths(&directory, &server_url);
    let args = forward_args(ForwardAction::Stop(ForwardStopArgs {
        forward_id: Some("11111111".to_string()),
        session: None,
        all: false,
    }));

    super::run(&paths, &args, None).await.unwrap();

    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /api/v1/port-forwards HTTP/1.1"));
    assert!(requests[1]
        .starts_with("DELETE /api/v1/port-forwards/11111111-1111-4111-8111-111111111111 HTTP/1.1"));
}

#[tokio::test]
async fn stop_all_skips_terminal_forwards_outside_selected_session() {
    let mut terminal = forward_json("expired");
    terminal["id"] = serde_json::json!("33333333-3333-4333-8333-333333333333");
    let mut other_session = forward_json("active");
    other_session["id"] = serde_json::json!("44444444-4444-4444-8444-444444444444");
    other_session["session_id"] = serde_json::json!("55555555-5555-4555-8555-555555555555");
    let listed = serde_json::json!({
        "data": {"items": [forward_json("active"), terminal, other_session]}
    });
    let stopped = serde_json::json!({"data": forward_json("stopped")});
    let (server_url, server) =
        fake_control_plane(vec![listed.to_string(), stopped.to_string()]).await;
    let directory = tempfile::tempdir().unwrap();
    let paths = authenticated_paths(&directory, &server_url);
    let args = forward_args(ForwardAction::Stop(ForwardStopArgs {
        forward_id: None,
        session: Some("22222222".to_string()),
        all: true,
    }));

    super::run(&paths, &args, None).await.unwrap();

    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1]
        .starts_with("DELETE /api/v1/port-forwards/11111111-1111-4111-8111-111111111111 HTTP/1.1"));
    assert!(!requests[1].contains("33333333-3333-4333-8333-333333333333"));
    assert!(!requests[1].contains("44444444-4444-4444-8444-444444444444"));
}

#[tokio::test]
async fn explicit_session_resolution_requires_a_running_visible_session() {
    let body = serde_json::json!({"data": {"items": [session_json()]}});
    let (server_url, server) = fake_control_plane(vec![body.to_string()]).await;
    let client = ApiClient::new(server_url).unwrap();

    let session = resolve_session(&client, "device-token", Some("22222222"), None)
        .await
        .unwrap();

    assert_eq!(session.id, "22222222-2222-4222-8222-222222222222");
    let requests = server.await.unwrap();
    assert!(requests[0].starts_with("GET /api/v1/sessions HTTP/1.1"));
}

#[cfg(unix)]
#[tokio::test]
async fn start_command_cleans_up_created_forward_after_terminal_handshake() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("fake-ssh");
    let leaked = directory.path().join("token-in-argv");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nfor arg in \"$@\"; do [ \"$arg\" = \"initial-connect-secret\" ] && touch '{}'; done\ndd bs=1 count={} of=/dev/null 2>/dev/null\nprintf 'ARPF\\000\\001\\000\\000\\000\\050{{\"ok\":false,\"error_code\":\"AUTH_INVALID\"}}'\n",
            leaked.display(),
            client_handshake_size(
                "11111111-1111-4111-8111-111111111111",
                "initial-connect-secret"
            )
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

    let sessions = serde_json::json!({"data": {"items": [session_json()]}});
    let mut created = forward_json("pending");
    created["node_wireguard_ip"] = serde_json::json!("10.77.0.20");
    created["ssh_user"] = serde_json::json!("agent-remote");
    created["ssh_port"] = serde_json::json!(22);
    created["connection"] = serde_json::json!({
        "token": "initial-connect-secret",
        "expires_at": "2026-07-30T00:01:00Z"
    });
    let created = serde_json::json!({"data": created});
    let stopped = serde_json::json!({"data": forward_json("stopped")});
    let (server_url, server) = fake_control_plane(vec![
        sessions.to_string(),
        created.to_string(),
        stopped.to_string(),
    ])
    .await;
    let paths = authenticated_paths(&directory, &server_url);
    let args = ForwardArgs {
        remote_port: Some(5173),
        session: Some("22222222".to_string()),
        local_port: "auto".to_string(),
        open: false,
        ttl_seconds: Some(3600),
        action: None,
    };

    let error = start_with_ssh(&paths, &args, None, script)
        .await
        .expect_err("terminal tunnel authorization must fail start");
    let message = error.to_string();
    assert!(
        message.contains("AUTH_INVALID"),
        "unexpected start failure: {message}"
    );
    assert!(!leaked.exists(), "connection token was passed in SSH argv");

    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/v1/sessions HTTP/1.1"));
    assert!(requests[1].starts_with(
        "POST /api/v1/sessions/22222222-2222-4222-8222-222222222222/port-forwards HTTP/1.1"
    ));
    assert!(requests.iter().any(|request| request.starts_with(
        "DELETE /api/v1/port-forwards/11111111-1111-4111-8111-111111111111 HTTP/1.1"
    )));
    assert!(requests
        .iter()
        .all(|request| !request.contains("initial-connect-secret")));
}

#[test]
fn parses_same_auto_and_explicit_local_ports() {
    assert_eq!(parse_local_port("same", 5173).unwrap(), 5173);
    assert_eq!(parse_local_port("auto", 5173).unwrap(), 0);
    assert_eq!(parse_local_port("8080", 5173).unwrap(), 8080);
    assert!(parse_local_port("0", 5173).is_err());
    assert!(parse_local_port("invalid", 5173).is_err());
}

#[test]
fn client_instance_ids_are_random_and_bounded() {
    let first = client_instance_id();
    let second = client_instance_id();
    assert_ne!(first, second);
    assert!(first.starts_with("ci_"));
    assert_eq!(first.len(), 35);
}

#[tokio::test]
async fn handshake_reader_rejects_oversized_payload() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    tokio::spawn(async move {
        writer.write_all(super::PROTOCOL_MAGIC).await.unwrap();
        writer
            .write_u32((super::MAX_HANDSHAKE_BYTES + 1) as u32)
            .await
            .unwrap();
    });
    assert!(read_server_handshake(&mut reader).await.is_err());
}

#[test]
fn server_handshake_does_not_require_optional_success_fields_on_error() {
    let value: ServerHandshake =
        serde_json::from_str(r#"{"ok":false,"error_code":"AUTH_INVALID"}"#).unwrap();
    assert!(!value.ok);
    assert_eq!(value.error_code.as_deref(), Some("AUTH_INVALID"));
}

#[test]
fn server_handshake_rejects_unknown_fields() {
    let value = serde_json::from_str::<ServerHandshake>(
        r#"{"ok":true,"protocol":1,"max_streams":8,"target":"host"}"#,
    );
    assert!(value.is_err());
}

#[tokio::test]
async fn loopback_listener_supports_auto_and_rejects_collisions() {
    let listeners = bind_loopback_listeners("auto", 5173).await.unwrap();
    let port = listeners[0].local_addr().unwrap().port();
    assert_ne!(port, 0);
    assert!(listeners
        .iter()
        .all(|listener| listener.local_addr().unwrap().ip().is_loopback()));
    assert!(bind_loopback_listeners(&port.to_string(), 5173)
        .await
        .is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn ssh_tunnel_keeps_token_off_argv_and_redacts_terminal_errors() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("fake-ssh");
    let leaked = directory.path().join("token-in-argv");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nfor arg in \"$@\"; do [ \"$arg\" = \"secret-connect-token\" ] && touch '{}'; done\ndd bs=1 count={} of=/dev/null 2>/dev/null\nprintf 'ARPF\\000\\001\\000\\000\\000\\050{{\"ok\":false,\"error_code\":\"AUTH_INVALID\"}}'\n",
            leaked.display(),
            client_handshake_size("forward-1", "secret-connect-token")
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let paths = AppPaths::new(Some(directory.path().join("config"))).unwrap();
    let created: CreatedPortForwardData = serde_json::from_value(serde_json::json!({
        "id": "forward-1",
        "user_id": "user-1",
        "device_id": "device-1",
        "session_id": "session-1",
        "node_id": "node-1",
        "remote_port": 5173,
        "requested_local_port": 5173,
        "client_instance_id": "client-1",
        "status": "pending",
        "bytes_up": 0,
        "bytes_down": 0,
        "connection_count": 0,
        "last_connected_at": null,
        "lease_expires_at": null,
        "expires_at": "2026-07-31T00:00:00Z",
        "stopped_at": null,
        "stop_reason": null,
        "created_at": "2026-07-30T00:00:00Z",
        "updated_at": "2026-07-30T00:00:00Z",
        "node_wireguard_ip": "10.77.0.20",
        "ssh_user": "agent-remote",
        "ssh_port": 22,
        "connection": {
            "token": "unused-initial-token",
            "expires_at": "2026-07-30T00:01:00Z"
        }
    }))
    .unwrap();
    let result = connect_ssh_tunnel(
        &script,
        &paths,
        &created,
        PortForwardConnectionData {
            token: "secret-connect-token".to_string(),
            expires_at: "2026-07-30T00:01:00Z".to_string(),
        },
    )
    .await;
    let error = match result {
        Ok(_) => panic!("terminal authorization response must fail"),
        Err(error) => error,
    };
    assert!(error.terminal);
    assert!(!error.error.to_string().contains("secret-connect-token"));
    assert!(!leaked.exists(), "connection token was passed in SSH argv");
}

#[cfg(unix)]
#[tokio::test]
async fn tunnel_supervisor_reissues_token_after_retryable_ssh_failure() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("fake-ssh");
    let count = directory.path().join("ssh-count");
    let leaked = directory.path().join("token-in-argv");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nfor arg in \"$@\"; do case \"$arg\" in initial-secret|reconnect-secret) touch '{}' ;; esac; done\ncount=$(cat '{}' 2>/dev/null || echo 0)\ncount=$((count + 1))\nprintf '%s' \"$count\" > '{}'\n[ \"$count\" -eq 1 ] && exit 1\ndd bs=1 count={} of=/dev/null 2>/dev/null\nprintf 'ARPF\\000\\001\\000\\000\\000\\050{{\"ok\":false,\"error_code\":\"AUTH_INVALID\"}}'\n",
            leaked.display(),
            count.display(),
            count.display(),
            client_handshake_size("forward-1", "reconnect-secret"),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_address = api_listener.local_addr().unwrap();
    let api_task = tokio::spawn(async move {
        let (mut connection, _) = api_listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = connection.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let body = r#"{"data":{"token":"reconnect-secret","expires_at":"2026-07-30T00:01:00Z"}}"#;
        connection
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        String::from_utf8(request).unwrap()
    });

    let paths = AppPaths::new(Some(directory.path().join("config"))).unwrap();
    let mut created: CreatedPortForwardData = serde_json::from_value(serde_json::json!({
        "id": "forward-1", "user_id": "user-1", "device_id": "device-1",
        "session_id": "session-1", "node_id": "node-1", "remote_port": 5173,
        "requested_local_port": 5173, "client_instance_id": "client-1",
        "status": "pending", "bytes_up": 0, "bytes_down": 0, "connection_count": 0,
        "last_connected_at": null, "lease_expires_at": null,
        "expires_at": "2026-07-31T00:00:00Z", "stopped_at": null, "stop_reason": null,
        "created_at": "2026-07-30T00:00:00Z", "updated_at": "2026-07-30T00:00:00Z",
        "node_wireguard_ip": "10.77.0.20", "ssh_user": "agent-remote", "ssh_port": 22,
        "connection": {"token": "initial-secret", "expires_at": "2026-07-30T00:01:00Z"}
    }))
    .unwrap();
    created.connection.token = "initial-secret".to_string();
    let client = ApiClient::new(format!("http://{api_address}")).unwrap();
    let (sender_tx, _sender_rx) = tokio::sync::watch::channel(None);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (status_tx, mut status_rx) = tokio::sync::mpsc::channel(1);
    let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
    let supervisor = tokio::spawn(supervise_tunnel(
        paths,
        script,
        client,
        "device-api-token".to_string(),
        created,
        sender_tx,
        shutdown_rx,
        status_tx,
        probe_tx,
    ));
    // Process startup can be delayed by concurrent integration tests on macOS.
    // Keep the exact retry/token assertions below while bounding a stalled supervisor.
    let status = timeout(Duration::from_secs(15), status_rx.recv())
        .await
        .expect("supervisor did not report terminal retry result")
        .expect("supervisor status channel closed unexpectedly")
        .expect_err("second SSH response must be terminal");
    assert!(status.to_string().contains("AUTH_INVALID"));
    supervisor.await.unwrap();
    assert!(probe_rx.await.is_err());
    assert_eq!(std::fs::read_to_string(&count).unwrap(), "2");
    assert!(
        !leaked.exists(),
        "a connection token was passed in SSH argv"
    );
    let request = api_task.await.unwrap();
    assert!(request.starts_with("POST /api/v1/port-forwards/forward-1/connections "));
    assert!(!request.contains("initial-secret"));
    assert!(!request.contains("reconnect-secret"));
}

#[tokio::test]
async fn proxy_stream_carries_duplex_data_and_half_close_over_http2() {
    let (client_io, server_io) = tokio::io::duplex(64 << 10);
    let (sender, client_connection) = h2::client::handshake(client_io).await.unwrap();
    let client_task = tokio::spawn(async move { client_connection.await.unwrap() });
    let server_task = tokio::spawn(async move {
        let mut server = h2::server::handshake(server_io).await.unwrap();
        if let Some(stream) = server.accept().await {
            let (request, mut respond) = stream.unwrap();
            let mut stream_task = tokio::spawn(async move {
                assert_eq!(request.method(), http::Method::CONNECT);
                assert_eq!(
                    request.headers().get("x-agent-remote-forward-id").unwrap(),
                    "forward-1"
                );
                let mut request_body = request.into_body();
                let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
                let mut response_body = respond.send_response(response, false).unwrap();
                while let Some(data) = request_body.data().await {
                    let mut data = data.unwrap();
                    request_body
                        .flow_control()
                        .release_capacity(data.len())
                        .unwrap();
                    while data.has_remaining() {
                        response_body.reserve_capacity(data.remaining());
                        let capacity = poll_fn(|context| response_body.poll_capacity(context))
                            .await
                            .unwrap()
                            .unwrap();
                        let size = min(capacity, data.remaining());
                        if size > 0 {
                            response_body.send_data(data.split_to(size), false).unwrap();
                        }
                    }
                }
                response_body.send_data(Bytes::new(), true).unwrap();
            });
            tokio::select! {
                result = &mut stream_task => result.unwrap(),
                next = server.accept() => {
                    assert!(next.is_none(), "unexpected additional HTTP/2 stream");
                    stream_task.await.unwrap();
                    return;
                },
            }
            if let Some(next) = server.accept().await {
                next.unwrap();
                panic!("unexpected additional HTTP/2 stream");
            }
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut local_client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (proxy_connection, _) = listener.accept().await.unwrap();
    let proxy_task = tokio::spawn(proxy_stream(proxy_connection, sender, "forward-1"));

    local_client.write_all(b"vite-hmr").await.unwrap();
    local_client.shutdown().await.unwrap();
    let mut echoed = [0_u8; 8];
    timeout(Duration::from_secs(2), local_client.read_exact(&mut echoed))
        .await
        .expect("local tunnel response timed out")
        .unwrap();
    assert_eq!(&echoed, b"vite-hmr");
    let mut eof = [0_u8; 1];
    let read = timeout(Duration::from_secs(2), local_client.read(&mut eof))
        .await
        .expect("local tunnel half-close timed out")
        .unwrap();
    assert_eq!(read, 0);

    timeout(Duration::from_secs(2), proxy_task)
        .await
        .expect("local proxy task did not stop")
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), server_task)
        .await
        .expect("HTTP/2 test server did not stop")
        .unwrap();
    client_task.abort();
}
