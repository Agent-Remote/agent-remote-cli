use agent_remote_cli::{
    config::{AppPaths, Config},
    secrets::{device_token_key, user_token_key, SecretStore},
};
use serde_json::{json, Value};

fn params(server: &str, revoke: bool) -> Value {
    json!({"confirmed":true,"revoke_remote":revoke,"expected_context":{"server_url":server,"active_device_id":"device-1"}})
}

#[test]
fn logout_confirmation_and_context_are_checked_before_any_change() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let mut input = params("https://unused.invalid", true);
    input["confirmed"] = json!(false);
    let (_, result) = super::invoke(&home, &super::request("logout", input));
    assert_eq!(result["error"]["code"], "confirmation_required");
    let (_, result) = super::invoke(
        &home,
        &super::request("logout", params("https://unused.invalid", false)),
    );
    assert_eq!(result["error"]["code"], "configuration_changed");
    assert!(!home.exists());
}

#[test]
fn logout_reports_revocation_separately_and_removes_shared_credentials() {
    for status in [200, 503] {
        let temp = tempfile::tempdir().unwrap();
        let key = super::login::key(temp.path());
        let (url, http) = super::login::server(vec![
            (200, super::login::token()),
            (200, super::login::registered("device-1")),
            (200, super::login::pair()),
            (status, json!({})),
            (status, json!({})),
        ]);
        let (ok, result) = super::invoke(
            temp.path(),
            &super::request("login.password", super::login::params(&url, Some(&key))),
        );
        assert!(ok, "{result}");
        let (ok, result) =
            super::invoke(temp.path(), &super::request("logout", params(&url, true)));
        assert!(ok, "{result}");
        let receipt = &result["result"];
        assert_eq!(receipt["local_complete"], true);
        assert_eq!(receipt["operation_id"], "query-123");
        let expected = if status == 200 {
            "confirmed"
        } else {
            "unconfirmed"
        };
        assert_eq!(receipt["user"]["remote"], expected);
        assert_eq!(receipt["device"]["remote"], expected);
        assert!(!result.to_string().contains("private-"));
        let requests = http.join().unwrap();
        assert_eq!(
            requests.len(),
            5,
            "logout must not replay a failed revocation"
        );
        assert!(requests[3].starts_with("POST /api/v1/auth/logout "));
        assert!(requests[4].starts_with("POST /api/v1/auth/logout "));
        assert!(requests[3].contains("private-device"));
        assert!(requests[4].contains("private-session"));
        let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
        let config = Config::load(&paths).unwrap();
        assert_eq!(config.server_url.as_deref(), Some(url.as_str()));
        assert!(config.active_device_id.is_none());
        // Inspect through a child with the file backend, never the developer's keychain.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "logout::assert_credentials_removed"])
            .env("DESKTOP_LOGOUT_TEST_SERVER", &url)
            .env("AGENT_REMOTE_HOME", temp.path())
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .output()
            .unwrap();
        assert!(output.status.success());
    }
}

#[test]
fn assert_credentials_removed() {
    let Ok(server) = std::env::var("DESKTOP_LOGOUT_TEST_SERVER") else {
        return;
    };
    let store = SecretStore::new(AppPaths::new(None).unwrap());
    assert!(store
        .get_secret(&user_token_key(&server))
        .unwrap()
        .is_none());
    assert!(store
        .get_secret(&device_token_key(&server, "device-1"))
        .unwrap()
        .is_none());
}

#[test]
fn failed_local_removal_is_reported_without_hiding_other_cleanup() {
    for user in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let key = super::login::key(temp.path());
        let (url, http) = super::login::server(vec![
            (200, super::login::token()),
            (200, super::login::registered("device-1")),
            (200, super::login::pair()),
        ]);
        let (ok, result) = super::invoke(
            temp.path(),
            &super::request("login.password", super::login::params(&url, Some(&key))),
        );
        assert!(ok, "{result}");
        http.join().unwrap();
        let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
        let prefix = if user { "user-token_" } else { "device-token_" };
        let secret_path = std::fs::read_dir(paths.secrets_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(prefix)
            })
            .unwrap();
        std::fs::remove_file(&secret_path).unwrap();
        std::fs::create_dir(&secret_path).unwrap(); // An undeletable-as-file credential entry.
        let (ok, result) =
            super::invoke(temp.path(), &super::request("logout", params(&url, false)));
        assert!(
            ok,
            "a partial receipt still completes the protocol: {result}"
        );
        assert_eq!(result["result"]["local_complete"], false);
        assert_eq!(result["result"]["user"]["local_removed"], !user);
        assert_eq!(result["result"]["device"]["local_removed"], user);
        assert_eq!(result["result"]["config_cleared"], user);
        assert_eq!(
            Config::load(&paths).unwrap().active_device_id.is_none(),
            user,
            "failed device cleanup must retain the selection for explicit repair"
        );
        assert!(secret_path.is_dir());
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_agent-remote"))
            .args(["logout", "--no-revoke-remote"])
            .env("AGENT_REMOTE_HOME", temp.path())
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Logged out from"));
    }
}

#[tokio::test]
async fn logout_waiting_for_login_lock_rechecks_configuration() {
    use agent_remote_cli::auth;
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
    let original = Config {
        server_url: Some("https://old.invalid".into()),
        active_device_id: None,
    };
    original.save(&paths).unwrap();
    let guard = auth::login::lock(&paths).await.unwrap();
    let task = auth::logout::execute(&paths, false, Some(&original));
    tokio::pin!(task);
    tokio::select! {
        result = &mut task => panic!("logout did not wait for login lock: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
    }
    let changed = Config {
        server_url: Some("https://changed.invalid".into()),
        active_device_id: Some("other-device".into()),
    };
    changed.save(&paths).unwrap();
    drop(guard);
    let error = task.await.unwrap_err();
    assert!(error.is::<auth::logout::ContextChanged>());
    assert_eq!(Config::load(&paths).unwrap(), changed);
}

#[test]
fn local_only_logout_is_offline_and_regular_cli_uses_the_same_cleanup() {
    for desktop in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let key = super::login::key(temp.path());
        let (url, http) = super::login::server(vec![
            (200, super::login::token()),
            (200, super::login::registered("device-1")),
            (200, super::login::pair()),
        ]);
        let (ok, result) = super::invoke(
            temp.path(),
            &super::request("login.password", super::login::params(&url, Some(&key))),
        );
        assert!(ok, "{result}");
        assert_eq!(http.join().unwrap().len(), 3); // Server is gone; no refresh or revocation may be needed.
        if desktop {
            let (ok, result) =
                super::invoke(temp.path(), &super::request("logout", params(&url, false)));
            assert!(ok, "{result}");
            assert_eq!(result["result"]["local_complete"], true);
            assert_eq!(result["result"]["user"]["remote"], "not_requested");
            assert_eq!(result["result"]["device"]["remote"], "not_requested");
        } else {
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_agent-remote"))
                .args(["logout", "--no-revoke-remote"])
                .env("AGENT_REMOTE_HOME", temp.path())
                .env("AGENT_REMOTE_SECRET_BACKEND", "file")
                .output()
                .unwrap();
            assert!(output.status.success());
            assert!(String::from_utf8_lossy(&output.stdout).contains("Logged out from"));
        }
        let paths = AppPaths::new(Some(temp.path().to_owned())).unwrap();
        assert!(Config::load(&paths).unwrap().active_device_id.is_none());
        assert!(std::fs::read_dir(paths.secrets_dir()).unwrap().all(|e| e
            .unwrap()
            .path()
            .extension()
            .is_none_or(|s| s != "secret")));
    }
}
