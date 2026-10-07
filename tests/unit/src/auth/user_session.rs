// Tests for src/auth/user_session.rs.

use super::*;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn server(
    responses: Vec<(u16, serde_json::Value)>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(bytes).unwrap());
            let body = body.to_string();
            stream.write_all(format!("HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
        requests
    });
    (url, handle)
}

fn pair(access: &str, refresh: &str) -> serde_json::Value {
    json!({"data": {"access_token": access, "expires_in": 3600, "refresh_token": refresh, "refresh_expires_in": 2592000}})
}

#[tokio::test]
async fn migrates_then_refreshes_expired_access_without_login() {
    let (url, server) = server(vec![
        (200, pair("access-one", "refresh-one")),
        (200, pair("access-two", "refresh-two")),
    ])
    .await;
    let temp = tempfile::tempdir().unwrap();
    let store = SecretStore::file_only(AppPaths::from_home(temp.path().to_owned()));
    let key = user_token_key(&url);
    store.set_secret(&key, "legacy-access").unwrap();
    assert_eq!(
        load_locked(&store, &url).await.unwrap().as_deref(),
        Some("access-one")
    );
    let mut stored: UserSession =
        serde_json::from_str(&store.get_secret(&key).unwrap().unwrap()).unwrap();
    assert!(!format!("{:?}", stored.token).contains("refresh-one"));
    stored.refresh_at = 0;
    stored.expires_at = 0;
    store
        .set_secret(&key, &serde_json::to_string(&stored).unwrap())
        .unwrap();
    assert_eq!(
        load_locked(&store, &url).await.unwrap().as_deref(),
        Some("access-two")
    );
    assert_eq!(
        load_locked(&store, &url).await.unwrap().as_deref(),
        Some("access-two")
    );
    let requests = server.await.unwrap();
    assert!(requests[0].starts_with("POST /api/v1/auth/cli/session "));
    assert!(requests[1].starts_with("POST /api/v1/auth/cli/refresh "));
    assert!(requests[1].contains("refresh-one"));
    assert!(!requests[1].to_lowercase().contains("authorization:"));
}

#[tokio::test]
async fn concurrent_commands_consume_refresh_once() {
    let (url, server) = server(vec![(200, pair("renewed", "next-refresh"))]).await;
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(temp.path().to_owned());
    let store = SecretStore::file_only(paths.clone());
    let stored = UserSession {
        version: 1,
        token: serde_json::from_value(pair("expired", "refresh")["data"].clone()).unwrap(),
        refresh_at: 0,
        expires_at: 0,
        session_expires_at: 4102444800,
    };
    store
        .set_secret(
            &user_token_key(&url),
            &serde_json::to_string(&stored).unwrap(),
        )
        .unwrap();
    let first = async {
        let _lock = user_credential_lock(&paths, &url).await.unwrap();
        load_locked(&store, &url).await.unwrap()
    };
    let second = async {
        let _lock = user_credential_lock(&paths, &url).await.unwrap();
        load_locked(&store, &url).await.unwrap()
    };
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first, second);
    assert_eq!(first.as_deref(), Some("renewed"));
    assert_eq!(server.await.unwrap().len(), 1);
}

#[tokio::test]
async fn revoked_login_has_clear_error_and_does_not_replay() {
    let (url, server) = server(vec![(
        401,
        json!({"error": {"code":"AUTH_TOKEN_EXPIRED", "message":"private server detail"}}),
    )])
    .await;
    let temp = tempfile::tempdir().unwrap();
    let store = SecretStore::file_only(AppPaths::from_home(temp.path().to_owned()));
    store
        .set_secret(&user_token_key(&url), "legacy-expired")
        .unwrap();
    let error = load_locked(&store, &url).await.unwrap_err().to_string();
    assert!(error.contains("error_code=login_required"));
    assert!(!error.contains("private server detail"));
    assert!(!error.contains("legacy-expired"));
    assert_eq!(server.await.unwrap().len(), 1);
}

#[tokio::test]
async fn old_server_remains_compatible() {
    let (url, server) = server(vec![(
        404,
        json!({"error": {"code":"COMMON_NOT_FOUND", "message":"not found"}}),
    )])
    .await;
    let temp = tempfile::tempdir().unwrap();
    let store = SecretStore::file_only(AppPaths::from_home(temp.path().to_owned()));
    store.set_secret(&user_token_key(&url), "legacy").unwrap();
    assert_eq!(
        load_locked(&store, &url).await.unwrap().as_deref(),
        Some("legacy")
    );
    assert_eq!(server.await.unwrap().len(), 1);
}
