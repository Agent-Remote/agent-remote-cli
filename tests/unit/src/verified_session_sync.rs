use super::*;

fn target(path: &std::path::Path) -> Target {
    Target {
        local_path: path.to_string_lossy().into(),
        project_key: "project".into(),
        workspace_id: Some("12345678-1234-1234-1234-123456789abc".into()),
        sync_session_id: Some("87654321-1234-1234-1234-123456789abc".into()),
        fingerprint: Some(format!("sha256:{}", "a".repeat(64))),
    }
}

#[tokio::test]
async fn context_mismatch_precedes_state_credentials_and_network() {
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(root.path().join("home"));
    std::fs::create_dir(paths.home()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let initial = Config {
        server_url: Some(format!("http://{}", listener.local_addr().unwrap())),
        active_device_id: Some("device".into()),
    };
    std::fs::write(paths.config_path(), toml::to_string(&initial).unwrap()).unwrap();
    let context = Context {
        home: paths.home().into(),
        server_url: initial.server_url.clone(),
        active_device_id: Some("another-device".into()),
    };
    let result = flush_verified(
        &paths,
        &context,
        &target(root.path()),
        &AtomicBool::new(false),
    )
    .await
    .unwrap_err();
    assert_eq!(result.code, "configuration_changed");
    assert!(!result.flush_may_have_run);
    assert!(!paths.state_db_path().exists());
    assert!(!paths.secrets_dir().exists());
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_initialized_state_is_not_created_and_pre_cancellation_has_no_effects() {
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(root.path().join("home"));
    std::fs::create_dir(paths.home()).unwrap();
    let initial = Config {
        server_url: Some("https://test.invalid".into()),
        active_device_id: Some("device".into()),
    };
    std::fs::write(paths.config_path(), toml::to_string(&initial).unwrap()).unwrap();
    let context = Context {
        home: paths.home().into(),
        server_url: initial.server_url,
        active_device_id: initial.active_device_id,
    };
    for (cancel, expected) in [
        (false, "sync_setup_required"),
        (true, "sync_flush_canceled"),
    ] {
        let result = flush_verified(
            &paths,
            &context,
            &target(root.path()),
            &AtomicBool::new(cancel),
        )
        .await
        .unwrap_err();
        assert_eq!(result.code, expected);
        assert!(!result.flush_may_have_run);
        assert_eq!(std::fs::read_dir(paths.home()).unwrap().count(), 1);
    }
}
