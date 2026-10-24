use super::*;

fn native() -> TargetObservation {
    TargetObservation::present(
        "wg0",
        TargetIdentity::LinuxInterface {
            name: "wg0".into(),
            index: 42,
            namespace: "a".repeat(64),
            public_key: None,
        },
    )
}
fn snapshot(state: &'static str) -> status::StatusResult {
    status::StatusResult {
        home: PathBuf::from("/isolated"),
        platform: "linux".into(),
        elevation: "standard",
        tool: crate::wireguard::tools::ToolInfo {
            name: "wg",
            state: "available",
            path: Some(PathBuf::from("/fixture/wg")),
        },
        state,
        interfaces: Vec::new(),
    }
}

#[test]
fn logical_names_obey_the_platform_backend_limits() {
    for name in ["agent-remote", "wg_1=+.-", "0"] {
        assert!(valid_name(name));
    }
    for name in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "line\n",
        "a b",
        "隧道",
        "$name",
        &"x".repeat(33),
    ] {
        assert!(!valid_name(name));
    }
    #[cfg(not(windows))]
    assert!(!valid_name(&"x".repeat(16)));
    #[cfg(windows)]
    {
        assert!(valid_name(&"x".repeat(32)));
        for name in ["CON", "con.txt", "LPT9", "aux.conf", ".wg", "wg."] {
            assert!(!valid_name(name));
        }
    }
}

#[test]
fn only_matching_native_snapshots_receive_a_public_key() {
    let before = native();
    let mut status = snapshot("observed");
    status.interfaces.push(status::Interface {
        name: "wg0".into(),
        public_key: Some("public-fixture".into()),
        listen_port: 0,
        fwmark: 0,
        peers: vec![],
    });
    let result = combine(before.clone(), before.clone(), &status);
    assert_eq!(result.state, TargetState::Present);
    assert!(
        matches!(result.identity,Some(TargetIdentity::LinuxInterface {public_key:Some(key),..}) if key=="public-fixture")
    );
    let mut changed = before.clone();
    changed.identity = Some(TargetIdentity::LinuxInterface {
        name: "wg0".into(),
        index: 43,
        namespace: "a".repeat(64),
        public_key: None,
    });
    let result = combine(before, changed, &status);
    assert_eq!(result.state, TargetState::Unknown);
    assert_eq!(result.reason, Some(TargetReason::TargetChanged));
    assert!(result.identity.is_none());
}

#[test]
fn failed_or_empty_status_never_turns_existing_native_target_into_absence() {
    for (state, reason) in [
        ("query_failed", TargetReason::StatusUnavailable),
        ("observed", TargetReason::TargetNotInStatus),
    ] {
        let before = native();
        let result = combine(before.clone(), before, &snapshot(state));
        assert_eq!(result.state, TargetState::Present);
        assert_eq!(result.reason, Some(reason));
        assert!(result.identity.is_some());
    }
}

#[tokio::test]
async fn canceled_and_invalid_observations_never_require_a_tool_or_create_home() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("absent"));
    assert!(matches!(
        observe(&paths, "wg0", Arc::new(AtomicBool::new(true))).await,
        Err(ConfigError("canceled"))
    ));
    let invalid = observe(&paths, "invalid/name", Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(invalid.logical_name, "");
    assert_eq!(invalid.reason, Some(TargetReason::InvalidName));
    assert_eq!(invalid.status_state, "not_queried");
    assert!(!paths.home().exists());
}

#[test]
fn identity_domains_prevent_cross_kind_hash_reuse() {
    let left = fingerprint(b"mapping\0", b"same-native-object");
    let right = fingerprint(b"socket\0", b"same-native-object");
    assert_ne!(left, right);
    assert_eq!(left.len(), 64);
    assert!(left
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
}
