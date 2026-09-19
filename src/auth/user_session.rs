use std::fs::{File, OpenOptions};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::{ApiClient, ApiError, AuthToken};
use crate::config::AppPaths;
use crate::secrets::{user_token_key, SecretBackend, SecretStore};

#[derive(Serialize, Deserialize)]
struct UserSession {
    version: u8,
    token: AuthToken,
    refresh_at: u64,
    expires_at: u64,
    session_expires_at: u64,
}

pub fn user_login_error() -> anyhow::Error {
    anyhow::anyhow!("error_code=login_required state=installed admission=unknown next_action=login next_command=agent-remote login stale=false")
}

async fn user_credential_lock(paths: &AppPaths, server_url: &str) -> Result<File> {
    paths.ensure_base_dirs()?;
    let name = format!(
        "user-session-{:x}.lock",
        Sha256::digest(server_url.as_bytes())
    );
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(paths.secrets_dir().join(name))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            bail!("user credential lock has unsafe ownership or permissions")
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => bail!("user credential is busy or unavailable; retry the command"),
        }
    }
}

pub async fn store_user_token(
    paths: &AppPaths,
    server_url: &str,
    token: &AuthToken,
) -> Result<SecretBackend> {
    let _lock = user_credential_lock(paths, server_url).await?;
    let store = SecretStore::new(paths.clone());
    let backend = store.set_secret(&user_token_key(server_url), &token.access_token)?;
    load_locked(&store, server_url).await?;
    Ok(backend)
}

pub async fn load_user_token(paths: &AppPaths, server_url: &str) -> Result<Option<String>> {
    let _lock = user_credential_lock(paths, server_url).await?;
    let store = SecretStore::new(paths.clone());
    load_locked(&store, server_url).await
}

async fn load_locked(store: &SecretStore, server_url: &str) -> Result<Option<String>> {
    let key = user_token_key(server_url);
    let Some(raw) = store.get_secret(&key)? else {
        return Ok(None);
    };
    let client = ApiClient::new(server_url.to_owned())?;
    let now = super::unix_time_seconds()?;
    let token = if raw.starts_with('{') {
        let session: UserSession = serde_json::from_str(&raw).map_err(|_| {
            anyhow::anyhow!("stored user credential is malformed; run agent-remote login")
        })?;
        if session.version != 1 || session.session_expires_at <= now {
            return Err(user_login_error());
        }
        if session.refresh_at > now && session.expires_at > now {
            return Ok(Some(session.token.access_token));
        }
        let refresh = session
            .token
            .refresh_token
            .as_deref()
            .context("stored refresh credential is missing; run agent-remote login")?;
        client
            .refresh_cli_session(refresh)
            .await
            .map_err(refresh_error)?
    } else {
        match client.create_cli_session(&raw).await {
            Ok(token) => token,
            Err(error) if error.status_code() == Some(404) => return Ok(Some(raw)),
            Err(error) => return Err(refresh_error(error)),
        }
    };
    let session_ttl = token
        .refresh_expires_in
        .filter(|ttl| *ttl > 0)
        .context("Server returned an invalid CLI session lifetime")?;
    if token.access_token.is_empty()
        || token.expires_in == 0
        || token
            .refresh_token
            .as_ref()
            .is_none_or(|value| value.is_empty())
    {
        bail!("Server returned an incomplete CLI credential pair")
    }
    let result = token.access_token.clone();
    let session = UserSession {
        version: 1,
        refresh_at: now.saturating_add((token.expires_in / 2).max(1)),
        expires_at: now.saturating_add(token.expires_in),
        session_expires_at: now.saturating_add(session_ttl),
        token,
    };
    store.set_secret(&key, &serde_json::to_string(&session)?)?;
    Ok(Some(result))
}

pub async fn logout_user(paths: &AppPaths, server_url: &str, revoke: bool) -> Result<()> {
    let _lock = user_credential_lock(paths, server_url).await?;
    let store = SecretStore::new(paths.clone());
    let result = if revoke {
        match load_locked(&store, server_url).await {
            Ok(Some(token)) => ApiClient::new(server_url.to_owned())?
                .logout(&token)
                .await
                .map_err(anyhow::Error::from),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        }
    } else {
        Ok(())
    };
    store.delete_secret(&user_token_key(server_url))?;
    result
}

fn refresh_error(error: ApiError) -> anyhow::Error {
    if matches!(error.status_code(), Some(401 | 403)) {
        user_login_error()
    } else {
        anyhow::anyhow!(
            "CLI credential renewal failed; retry when the server is reachable (HTTP {:?})",
            error.status_code()
        )
    }
}

#[cfg(test)]
mod tests {
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
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
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
}
