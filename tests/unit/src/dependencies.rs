// Tests for src/dependencies.rs.

use std::path::PathBuf;

use tempfile::tempdir;

use crate::config::AppPaths;

use super::{platform_binary, DependencyManager};

#[test]
fn preserves_packaged_installer_extensions() {
    assert_eq!(
        platform_binary("dependencies/installers/wireguard.msi"),
        PathBuf::from("dependencies/installers/wireguard.msi")
    );
}

#[test]
fn creates_default_manifest_and_reports_missing_binaries() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    let manager = DependencyManager::new(paths.clone());
    manager.ensure_manifest().unwrap();
    assert!(paths.dependency_manifest_path().exists());

    let statuses = manager.check_all().unwrap();
    let expected_count = if cfg!(target_os = "macos") {
        7
    } else if cfg!(windows) {
        5
    } else {
        6
    };
    assert_eq!(statuses.len(), expected_count);
    assert!(statuses.iter().all(|status| !status.installed));
    assert!(statuses.iter().any(|status| status.name == "mutagen"));
    assert!(statuses.iter().any(|status| status.name == "scp-proxy"));
    assert!(statuses.iter().any(|status| status.name == "ssh-proxy"));
}
