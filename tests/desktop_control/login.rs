use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

use agent_remote_cli::config::{AppPaths, Config};
use serde_json::{json, Value};

pub(super) fn params(server: &str, key: Option<&Path>) -> Value {
    json!({"server_url":server,"username":"desktop-user","password":"private-password","totp_code":"123456",
        "device_name":"Desktop","ssh_public_key":key,"wireguard_public_key":null,
        "skip_device_registration":key.is_none(),"confirmed":true,
        "expected_context":{"server_url":null,"active_device_id":null}})
}

pub(super) fn token() -> Value {
    json!({"data":{"access_token":"private-access","expires_in":3600}})
}
pub(super) fn pair() -> Value {
    json!({"data":{"access_token":"private-session","expires_in":3600,"refresh_token":"private-refresh","refresh_expires_in":2592000}})
}
pub(super) fn registered(id: &str) -> Value {
    json!({"data":{"device":{"id":id,"name":"Desktop","platform":"macos","status":"active","created_at":"2026-10-18T00:00:00Z"},
        "device_token":{"access_token":"private-device","expires_in":3600},"ssh_key_id":"key-1","wireguard_peer_id":null}})
}

pub(super) fn server(
    responses: Vec<(u16, Value)>,
) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => panic!("missing expected login request: {error}"),
                }
            };
            // Accepted sockets may inherit the listener's nonblocking mode on macOS.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut block = [0; 2048];
                let count = stream.read(&mut block).unwrap();
                assert!(count > 0 && bytes.len() < 65536);
                bytes.extend_from_slice(&block[..count]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..end]);
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_lowercase()
                                .strip_prefix("content-length:")
                                .map(|s| s.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(bytes).unwrap());
            let body = body.to_string();
            write!(stream,"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        }
        requests
    });
    (url, handle)
}

pub(super) fn key(home: &Path) -> std::path::PathBuf {
    use base64::Engine;
    let mut bytes = Vec::new();
    bytes.extend(11u32.to_be_bytes());
    bytes.extend(b"ssh-ed25519");
    bytes.extend(32u32.to_be_bytes());
    bytes.extend([7u8; 32]);
    let path = home.join("test.pub");
    std::fs::write(
        &path,
        format!(
            "ssh-ed25519 {} test",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        ),
    )
    .unwrap();
    path
}

fn secret_free(response: &Value) {
    let text = response.to_string();
    for secret in [
        "private-password",
        "private-access",
        "private-session",
        "private-refresh",
        "private-device",
        "123456",
    ] {
        assert!(!text.contains(secret), "login response leaked a secret");
    }
}

#[test]
fn password_login_registers_once_and_normal_cli_reuses_the_same_device() {
    let temp = tempfile::tempdir().unwrap();
    let key = key(temp.path());
    let (url, http) = server(vec![
        (200, token()),
        (200, registered("device-1")),
        (200, pair()),
        (200, token()),
        (200, registered("device-1")),
        (200, pair()),
    ]);
    let (ok, response) = super::invoke(
        temp.path(),
        &super::request("login.password", params(&url, Some(&key))),
    );
    assert!(ok, "{response}");
    secret_free(&response);
    assert_eq!(response["result"]["registered_device_id"], "device-1");
    assert_eq!(response["result"]["operation_id"], "query-123");
    let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
    let config = Config::load(&paths).unwrap();
    assert_eq!(config.server_url.as_deref(), Some(url.as_str()));
    assert_eq!(config.active_device_id.as_deref(), Some("device-1"));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .args([
            "login",
            "--server-url",
            &url,
            "--username",
            "desktop-user",
            "--device-name",
            "Desktop",
            "--ssh-public-key",
        ])
        .arg(&key)
        .env("AGENT_REMOTE_HOME", temp.path())
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_PASSWORD", "private-password")
        .output()
        .unwrap();
    assert!(output.status.success(), "human login failed");
    assert!(String::from_utf8_lossy(&output.stdout).contains("Logged in to"));
    let requests = http.join().unwrap();
    assert!(requests[0].starts_with("POST /api/v1/auth/login "));
    assert!(requests[0].contains("private-password") && requests[0].contains("123456"));
    assert!(requests[1].starts_with("POST /api/v1/devices/register "));
    assert!(!requests[1].contains("existing_device_id"));
    assert!(requests[4].contains("\"existing_device_id\":\"device-1\""));
    let db = std::fs::read(paths.state_db_path()).unwrap();
    for secret in [
        b"private-password".as_slice(),
        b"private-access",
        b"private-device",
        b"private-refresh",
    ] {
        assert!(!db.windows(secret.len()).any(|w| w == secret));
    }
}

#[test]
fn unconfirmed_stale_context_and_private_key_are_rejected_before_network() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let mut input = params("https://unused.invalid", None);
    input["confirmed"] = json!(false);
    let (_, value) = super::invoke(&home, &super::request("login.password", input));
    assert_eq!(value["error"]["code"], "confirmation_required");
    assert!(!home.exists());
    let mut input = params("https://unused.invalid", None);
    input["expected_context"]["server_url"] = json!("https://stale.invalid");
    let (_, value) = super::invoke(&home, &super::request("login.password", input));
    assert_eq!(value["error"]["code"], "configuration_changed");
    assert!(!home.exists());
    let key = temp.path().join("private-key");
    std::fs::write(
        &key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-material",
    )
    .unwrap();
    let (_, value) = super::invoke(
        &home,
        &super::request(
            "login.password",
            params("https://unused.invalid", Some(&key)),
        ),
    );
    assert_eq!(value["error"]["code"], "ssh_public_key_required");
    assert!(!home.exists());
    secret_free(&value);
}

#[test]
fn login_rejection_and_unknown_registration_keep_existing_config() {
    let temp = tempfile::tempdir().unwrap();
    let key = key(temp.path());
    let (url, http) = server(vec![(401, json!({"error":{"message":"private-password"}}))]);
    let (_, response) = super::invoke(
        temp.path(),
        &super::request("login.password", params(&url, Some(&key))),
    );
    assert_eq!(response["error"]["code"], "login_rejected");
    secret_free(&response);
    http.join().unwrap();
    let (url, http) = server(vec![
        (200, token()),
        (503, json!({"error":{"message":"private-device"}})),
    ]);
    let (_, response) = super::invoke(
        temp.path(),
        &super::request("login.password", params(&url, Some(&key))),
    );
    assert_eq!(response["error"]["code"], "registration_outcome_unknown");
    assert_eq!(response["error"]["retryable"], false);
    secret_free(&response);
    assert_eq!(
        http.join().unwrap().len(),
        2,
        "automatically retried registration"
    );
    assert!(!temp.path().join("config.toml").exists());

    let (url, http) = server(vec![(
        200,
        json!({"data":{"access_token":"","expires_in":3600}}),
    )]);
    let (_, response) = super::invoke(
        temp.path(),
        &super::request("login.password", params(&url, Some(&key))),
    );
    assert_eq!(response["error"]["code"], "login_outcome_unknown");
    assert!(!temp.path().join("config.toml").exists());
    assert_eq!(http.join().unwrap().len(), 1);
}

#[test]
fn user_only_login_clears_a_foreign_device_without_registering() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
    let old = Config {
        server_url: Some("https://old.invalid".into()),
        active_device_id: Some("old-device".into()),
    };
    old.save(&paths).unwrap();
    let (url, http) = server(vec![(200, token()), (200, pair())]);
    let mut input = params(&url, None);
    input["expected_context"] = serde_json::to_value(old).unwrap();
    let (ok, value) = super::invoke(temp.path(), &super::request("login.password", input));
    assert!(ok, "{value}");
    secret_free(&value);
    assert!(value["result"]["registered_device_id"].is_null());
    assert_eq!(Config::load(&paths).unwrap().active_device_id, None);
    assert_eq!(http.join().unwrap().len(), 2);
}

#[tokio::test]
async fn configuration_switch_while_login_waits_prevents_device_registration() {
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let key = key(temp.path());
    let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
    let guard = agent_remote_cli::auth::login::lock(&paths).await.unwrap();
    let (url, http) = server(vec![(200, token())]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", temp.path())
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&super::request("login.password", params(&url, Some(&key))))
        .unwrap();
    assert_eq!(
        tokio::task::spawn_blocking(move || http.join().unwrap())
            .await
            .unwrap()
            .len(),
        1
    );
    let changed = Config {
        server_url: Some("https://changed.invalid".into()),
        active_device_id: None,
    };
    changed.save(&paths).unwrap();
    drop(guard);
    let output = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["error"]["code"], "configuration_changed");
    assert_eq!(Config::load(&paths).unwrap(), changed);
    secret_free(&response);
}

#[tokio::test]
async fn device_credential_reads_wait_for_the_login_publication_lock() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
    let guard = agent_remote_cli::auth::login::lock(&paths).await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        agent_remote_cli::auth::load_device_token(&paths)
    )
    .await
    .is_err());
    drop(guard);
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        agent_remote_cli::auth::load_device_token(&paths),
    )
    .await
    .unwrap();
    assert!(result.is_err(), "unconfigured home must not authenticate");
}

#[cfg(unix)]
#[test]
fn ssh_public_key_fifo_is_rejected_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("key.pipe");
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let start = Instant::now();
    assert!(agent_remote_cli::auth::login::read_ssh_public_key(Some(&path)).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
}
