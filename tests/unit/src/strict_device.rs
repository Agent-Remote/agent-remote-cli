use std::sync::atomic::AtomicBool;

use super::load_mode;
use super::load_with_store;
use crate::auth::{login, record_refresh_time};
use crate::config::{AppPaths, Config};
use crate::secrets::{device_token_key, SecretStore, SecretValue};

fn fixture() -> (tempfile::TempDir, AppPaths, SecretStore) {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("home"));
    paths.ensure_base_dirs().unwrap();
    let store = SecretStore::file_only(paths.clone());
    (dir, paths, store)
}

#[tokio::test]
async fn uses_existing_login_lock_and_reuses_unexpired_device_token() {
    let (_dir, paths, store) = fixture();
    let config = Config {
        server_url: Some("https://test.invalid".into()),
        active_device_id: Some("device".into()),
    };
    config.save(&paths).unwrap();
    let key = device_token_key("https://test.invalid", "device");
    let cancel = AtomicBool::new(false);
    store
        .write_strict(
            &key,
            &SecretValue::new("fixture-token".into()).unwrap(),
            &cancel,
        )
        .await
        .unwrap();
    record_refresh_time(&paths, "https://test.invalid", "device", 3600).unwrap();
    let guard = login::lock(&paths).await.unwrap();
    let token = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        load_with_store(&paths, &guard, &config, &cancel, &store),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(token.token.as_str(), "fixture-token");
}

#[tokio::test]
async fn rejects_changed_context_and_lock_from_another_home_before_credentials() {
    let (dir, paths, store) = fixture();
    let config = Config {
        server_url: Some("https://test.invalid".into()),
        active_device_id: Some("device".into()),
    };
    config.save(&paths).unwrap();
    let guard = login::lock(&paths).await.unwrap();
    let mut changed = config.clone();
    changed.active_device_id = Some("other-device".into());
    assert!(
        load_with_store(&paths, &guard, &changed, &AtomicBool::new(false), &store)
            .await
            .is_err()
    );
    let other = AppPaths::from_home(dir.path().join("other-home"));
    config.save(&other).unwrap();
    assert!(
        load_with_store(&other, &guard, &config, &AtomicBool::new(false), &store)
            .await
            .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_config_fifo_links_and_oversize_before_credential_loading() {
    use std::os::unix::fs::symlink;
    let (dir, paths, store) = fixture();
    let config = Config {
        server_url: Some("https://test.invalid".into()),
        active_device_id: Some("device".into()),
    };
    config.save(&paths).unwrap();
    let guard = login::lock(&paths).await.unwrap();
    let path = paths.config_path();
    std::fs::remove_file(&path).unwrap();
    let fifo = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(
        load_with_store(&paths, &guard, &config, &AtomicBool::new(false), &store)
            .await
            .is_err()
    );
    std::fs::remove_file(&path).unwrap();
    let target = dir.path().join("config-source");
    std::fs::write(&target, toml::to_string(&config).unwrap()).unwrap();
    symlink(&target, &path).unwrap();
    assert!(
        load_with_store(&paths, &guard, &config, &AtomicBool::new(false), &store)
            .await
            .is_err()
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(&target, &path).unwrap();
    assert!(
        load_with_store(&paths, &guard, &config, &AtomicBool::new(false), &store)
            .await
            .is_err()
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, vec![b'a'; 64 * 1024 + 1]).unwrap();
    assert!(
        load_with_store(&paths, &guard, &config, &AtomicBool::new(false), &store)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn refreshes_and_persists_token_once_under_the_existing_lock() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut data = vec![0; 4096];
        let size = socket.read(&mut data).await.unwrap();
        let request = String::from_utf8_lossy(&data[..size]);
        assert!(request.starts_with("POST /api/v1/auth/refresh "));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer original-fixture-token"));
        let body = r#"{"data":{"access_token":"refreshed-fixture-token","token_type":"Bearer","expires_in":3600}}"#;
        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        socket.write_all(response.as_bytes()).await.unwrap();
    });
    let (_dir, paths, store) = fixture();
    let config = Config {
        server_url: Some(server_url.clone()),
        active_device_id: Some("device".into()),
    };
    config.save(&paths).unwrap();
    let key = device_token_key(&server_url, "device");
    let cancel = AtomicBool::new(false);
    store
        .write_strict(
            &key,
            &SecretValue::new("original-fixture-token".into()).unwrap(),
            &cancel,
        )
        .await
        .unwrap();
    let guard = login::lock(&paths).await.unwrap();
    let result = load_with_store(&paths, &guard, &config, &cancel, &store)
        .await
        .unwrap();
    assert_eq!(result.token.as_str(), "refreshed-fixture-token");
    server.await.unwrap();
    let next = load_with_store(&paths, &guard, &config, &cancel, &store)
        .await
        .unwrap();
    assert_eq!(next.token.as_str(), "refreshed-fixture-token");
    assert_eq!(
        store
            .read_strict(&key, &cancel)
            .await
            .unwrap()
            .unwrap()
            .as_str(),
        "refreshed-fixture-token"
    );
}

#[tokio::test]
async fn existing_mode_rejects_missing_refresh_record_without_schema_changes_or_http() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_dir, paths, store) = fixture();
    let config = Config {
        server_url: Some(format!("http://{}", listener.local_addr().unwrap())),
        active_device_id: Some("device".into()),
    };
    config.save(&paths).unwrap();
    let guard = login::lock(&paths).await.unwrap();
    let state = crate::local_state::LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    let before = std::fs::read(paths.state_db_path()).unwrap();
    assert!(load_mode(
        &paths,
        &guard,
        &config,
        &AtomicBool::new(false),
        &store,
        true
    )
    .await
    .is_err());
    assert_eq!(before, std::fs::read(paths.state_db_path()).unwrap());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn existing_mode_refresh_commit_failure_returns_error_after_secret_publication() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let (_dir, paths, store) = fixture();
    let config = Config {
        server_url: Some(server_url.clone()),
        active_device_id: Some("device".into()),
    };
    config.save(&paths).unwrap();
    let state = crate::local_state::LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    let refresh_key = super::device_token_refresh_key(&server_url, "device");
    state.set_kv(&refresh_key, "0").unwrap();
    let reader = rusqlite::Connection::open(paths.state_db_path()).unwrap();
    reader.execute_batch("BEGIN; SELECT * FROM kv;").unwrap();
    let cancel = AtomicBool::new(false);
    let key = device_token_key(&server_url, "device");
    store
        .write_strict(
            &key,
            &SecretValue::new("original-fixture-token".into()).unwrap(),
            &cancel,
        )
        .await
        .unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut data = vec![0; 4096];
        let n = socket.read(&mut data).await.unwrap();
        assert!(data[..n].starts_with(b"POST /api/v1/auth/refresh "));
        let body = r#"{"data":{"access_token":"refreshed-fixture-token","token_type":"Bearer","expires_in":3600}}"#;
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
    });
    let guard = login::lock(&paths).await.unwrap();
    assert!(load_mode(&paths, &guard, &config, &cancel, &store, true)
        .await
        .is_err());
    server.await.unwrap();
    reader.execute_batch("ROLLBACK;").unwrap();
    assert_eq!(state.get_kv(&refresh_key).unwrap().as_deref(), Some("0"));
    assert_eq!(
        store
            .read_strict(&key, &cancel)
            .await
            .unwrap()
            .unwrap()
            .as_str(),
        "refreshed-fixture-token"
    );
}
