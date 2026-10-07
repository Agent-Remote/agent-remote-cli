// Tests for src/api.rs.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{decode_ego_browser_policy, ApiClient, AttachSessionData, RegisterDeviceRequest};

#[test]
fn policy_requires_separated_admission_fields() {
    let error = decode_ego_browser_policy(serde_json::json!({
        "enabled": true,
        "protocol": "ego-browser-bridge-v1"
    }))
    .unwrap_err();
    assert_eq!(error.code(), Some("SERVER_CAPABILITY_UNAVAILABLE"));

    let policy = decode_ego_browser_policy(serde_json::json!({
        "enabled": true,
        "enrollment_enabled": true,
        "execution_admission": false,
        "protocol": "ego-browser-bridge-v1"
    }))
    .unwrap();
    assert!(policy.enrollment_is_admitted());
    assert!(!policy.execution_is_admitted());
}

#[test]
fn attach_authorization_defaults_to_ready_for_older_servers() {
    let attach: AttachSessionData = serde_json::from_str(
        r#"{
            "session_id":"session_1",
            "node_id":"node_1",
            "node_wireguard_ip":"10.77.0.1",
            "ssh_host":"10.77.0.1",
            "ssh_port":22,
            "ssh_user":"agent-remote",
            "tmux_session_name":"claude-test",
            "command_args":[],
            "ssh_command":"ssh agent-remote@10.77.0.1",
            "authorization_task_id":"task_1",
            "expires_in":300
        }"#,
    )
    .unwrap();
    assert_eq!(attach.authorization_task_status, "succeeded");
}

#[test]
fn device_registration_reports_version_and_optional_existing_device() {
    let request = RegisterDeviceRequest {
        name: "laptop".to_string(),
        platform: "linux".to_string(),
        cli_version: "0.0.5-fix.7".to_string(),
        ssh_public_key: "ssh-ed25519 AAAA".to_string(),
        wireguard_public_key: None,
        existing_device_id: None,
    };

    let payload = serde_json::to_value(request).unwrap();
    assert_eq!(payload["cli_version"], "0.0.5-fix.7");
    assert!(payload.get("existing_device_id").is_none());

    let existing_request = RegisterDeviceRequest {
        name: "laptop".to_string(),
        platform: "linux".to_string(),
        cli_version: "0.1.5".to_string(),
        ssh_public_key: "ssh-ed25519 AAAA".to_string(),
        wireguard_public_key: None,
        existing_device_id: Some("device-1".to_string()),
    };
    let existing_payload = serde_json::to_value(existing_request).unwrap();
    assert_eq!(existing_payload["existing_device_id"], "device-1");
}

#[tokio::test]
async fn device_revoke_uses_the_authenticated_versioned_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "request ended before its headers were complete");
            request.extend_from_slice(&chunk[..read]);
            assert!(request.len() <= 8192, "request headers exceeded 8 KiB");
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("POST /api/v1/devices/device-123/revoke HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer test-user-token\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
            )
            .await
            .unwrap();
    });

    ApiClient::new(format!("http://{address}"))
        .unwrap()
        .revoke_device("test-user-token", "device-123")
        .await
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn device_token_rotation_uses_user_auth_and_redacts_the_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "request ended before its headers were complete");
            request.extend_from_slice(&chunk[..read]);
            assert!(request.len() <= 8192, "request headers exceeded 8 KiB");
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("POST /api/v1/devices/device-123/rotate-token HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer test-user-token\r\n"));
        let body = r#"{"data":{"access_token":"new-device-token-that-must-remain-redacted","expires_in":3600}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });

    let token = ApiClient::new(format!("http://{address}"))
        .unwrap()
        .rotate_device_token("test-user-token", "device-123")
        .await
        .unwrap();
    assert_eq!(token.expires_in, 3600);
    assert!(!format!("{token:?}").contains("new-device-token"));
    server.await.unwrap();
}

#[tokio::test]
async fn ego_browser_request_cancel_uses_exact_path_identity_and_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let (header_end, content_length) = loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "request ended before its body was complete");
            request.extend_from_slice(&chunk[..read]);
            assert!(request.len() <= 8192, "request exceeded 8 KiB");
            if let Some(header_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
            {
                let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap();
                break (header_end, content_length);
            }
        };
        while request.len() < header_end + content_length {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "request ended before its body was complete");
            request.extend_from_slice(&chunk[..read]);
        }

        let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
        assert!(headers.starts_with(
            "POST /api/v1/ego-browser/bindings/binding%20123/requests/request%2F123/cancel HTTP/1.1\r\n"
        ));
        assert!(headers
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer test-user-token\r\n"));
        let body: serde_json::Value =
            serde_json::from_slice(&request[header_end..header_end + content_length]).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "binding_generation": 7,
                "generation": 7,
                "sequence": 19
            })
        );

        let response_body = r#"{"data":{"id":"ledger-123","binding_id":"binding 123","generation":7,"request_id":"request/123","sequence":19,"message_type":"execute","payload_bytes":321,"status":"cancel_requested","created_at":"2026-09-07T00:00:00Z"}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
            response_body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });

    let result = ApiClient::new(format!("http://{address}"))
        .unwrap()
        .cancel_ego_browser_request("test-user-token", "binding 123", "request/123", 7, 19)
        .await
        .unwrap();
    assert_eq!(result.id, "ledger-123");
    assert_eq!(result.status, "cancel_requested");
    server.await.unwrap();
}
