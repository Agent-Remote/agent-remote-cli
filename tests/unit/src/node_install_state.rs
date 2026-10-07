// Tests for src/node_install_state.rs.

use super::{clear, load, save, NodeInstallExchangeState, NodeInstallStage};
use crate::config::AppPaths;
use std::fs;

#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

fn state() -> NodeInstallExchangeState {
    NodeInstallExchangeState {
        version: 2,
        server_url: "https://control.example".to_owned(),
        node_id: "node-1".to_owned(),
        node_fingerprint_sha256: "a".repeat(64),
        exchange_id: "b".repeat(32),
        enable_ego_browser: false,
        release_version: "0.2.20".to_owned(),
        release_target: "linux-amd64-glibc".to_owned(),
        release_sha256: Some("c".repeat(64)),
        stage: NodeInstallStage::Issued,
        created_at_unix: 1,
        expires_at: Some("2099-01-02T03:04:05Z".to_owned()),
    }
}

#[test]
fn owner_only_state_round_trips_without_secrets() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(temporary.path().join("state"));
    let state = state();
    save(&paths, &state).unwrap();
    assert_eq!(load(&paths).unwrap(), Some(state));
    let bytes = fs::read(paths.home().join("node-install-exchange.json")).unwrap();
    assert!(!bytes.windows(9).any(|window| window == b"join-code"));
    assert!(!bytes.windows(10).any(|window| window == b"node-token"));
    #[cfg(unix)]
    {
        let metadata = fs::metadata(paths.home().join("node-install-exchange.json")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
    clear(&paths).unwrap();
    assert!(load(&paths).unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn state_rejects_parent_symlinks_and_hard_links() {
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target");
    fs::create_dir(&target).unwrap();
    let linked_home = temporary.path().join("linked-home");
    symlink(&target, &linked_home).unwrap();
    let linked_paths = AppPaths::from_home(linked_home);
    assert!(save(&linked_paths, &state()).is_err());
    assert!(!target.join("node-install-exchange.json").exists());

    let paths = AppPaths::from_home(temporary.path().join("safe-home"));
    save(&paths, &state()).unwrap();
    fs::hard_link(
        paths.home().join("node-install-exchange.json"),
        paths.home().join("state-alias.json"),
    )
    .unwrap();
    assert!(load(&paths).is_err());
    assert!(clear(&paths).is_err());
}
