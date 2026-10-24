// Tests for src/dependencies.rs.

use std::path::PathBuf;

use tempfile::tempdir;

use crate::config::AppPaths;

use super::{platform_binary, DependencyManager};

#[test]
fn local_manifest_initialization_preserves_existing_bytes_and_never_runs_tools() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    std::fs::create_dir(paths.dependencies_dir()).unwrap();
    let manager = DependencyManager::new(paths.clone());
    assert_eq!(
        manager.initialize_local_manifest().unwrap(),
        super::ManifestInitialization::Applied
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(paths.dependency_manifest_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let bytes = b"{\n \"schema_version\":1, \"dependencies\":[]\n}\n";
    std::fs::write(paths.dependency_manifest_path(), bytes).unwrap();
    assert_eq!(
        manager.initialize_local_manifest().unwrap(),
        super::ManifestInitialization::Ready
    );
    assert_eq!(
        std::fs::read(paths.dependency_manifest_path()).unwrap(),
        bytes
    );
    assert_eq!(std::fs::read_dir(paths.home()).unwrap().count(), 1);
}

#[test]
fn local_manifest_initialization_rejects_invalid_and_future_metadata_unchanged() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    std::fs::create_dir(paths.dependencies_dir()).unwrap();
    let manager = DependencyManager::new(paths.clone());
    for bytes in [
        b"{bad json".to_vec(),
        br#"{"schema_version":2,"dependencies":[]}"#.to_vec(),
        vec![b' '; 256 * 1024 + 1],
    ] {
        std::fs::write(paths.dependency_manifest_path(), &bytes).unwrap();
        let error = manager.initialize_local_manifest().unwrap_err();
        assert!(error
            .downcast_ref::<super::ManifestInitializationError>()
            .is_some());
        assert_eq!(
            std::fs::read(paths.dependency_manifest_path()).unwrap(),
            bytes
        );
    }
    let mut manifest = super::DependencyManifest::default_managed();
    manifest.dependencies[0].binary = "../outside".into();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(paths.dependency_manifest_path(), &bytes).unwrap();
    assert!(manager.initialize_local_manifest().is_err());
    assert_eq!(
        std::fs::read(paths.dependency_manifest_path()).unwrap(),
        bytes
    );
}

#[test]
fn concurrent_manifest_initializers_publish_exactly_once() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    std::fs::create_dir(paths.dependencies_dir()).unwrap();
    let manager = DependencyManager::new(paths.clone());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let jobs: Vec<_> = (0..8)
        .map(|_| {
            let manager = manager.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                manager.initialize_local_manifest().unwrap()
            })
        })
        .collect();
    let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
    assert_eq!(
        results
            .iter()
            .filter(|&&status| status == super::ManifestInitialization::Applied)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|&&status| status == super::ManifestInitialization::Ready)
            .count(),
        7
    );
    assert_eq!(
        std::fs::read_dir(paths.dependencies_dir()).unwrap().count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn local_manifest_initialization_rejects_links_and_fifo_without_blocking() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    std::fs::create_dir(paths.dependencies_dir()).unwrap();
    let target = dir.path().join("outside");
    let bytes = br#"{"schema_version":1,"dependencies":[]}"#;
    std::fs::write(&target, bytes).unwrap();
    let manager = DependencyManager::new(paths.clone());
    for kind in ["symlink", "hardlink", "directory", "fifo"] {
        let path = paths.dependency_manifest_path();
        match kind {
            "symlink" => symlink(&target, &path).unwrap(),
            "hardlink" => std::fs::hard_link(&target, &path).unwrap(),
            "directory" => std::fs::create_dir(&path).unwrap(),
            "fifo" => {
                let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }
        let error = manager.initialize_local_manifest().unwrap_err();
        assert_eq!(
            error.downcast_ref::<super::ManifestInitializationError>(),
            Some(&super::ManifestInitializationError::InvalidPath)
        );
        if kind == "directory" {
            std::fs::remove_dir(path).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
    }
    assert_eq!(std::fs::read(target).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn local_manifest_initialization_never_executes_existing_dependency() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    std::fs::create_dir(paths.dependencies_dir()).unwrap();
    std::fs::create_dir(paths.bin_dir()).unwrap();
    let executable = paths.bin_dir().join("probe");
    std::fs::write(&executable, b"#!/bin/sh\necho invoked > \"$0.called\"\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut manifest = super::DependencyManifest::default_managed();
    manifest.dependencies.truncate(1);
    manifest.dependencies[0].binary = "bin/probe".into();
    std::fs::write(
        paths.dependency_manifest_path(),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let manager = DependencyManager::new(paths.clone());
    assert_eq!(
        manager.initialize_local_manifest().unwrap(),
        super::ManifestInitialization::Ready
    );
    assert!(!paths.bin_dir().join("probe.called").exists());
}

#[cfg(unix)]
#[test]
fn manifest_initialization_rejects_home_link_aliases_before_any_writes() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let link = dir.path().join("linked-home");
    symlink(&target, &link).unwrap();
    for suffix in ["", "/", "/.", "/./"] {
        let mut spelling = link.as_os_str().to_os_string();
        spelling.push(suffix);
        let paths = AppPaths::from_home(spelling.into());
        let manager = DependencyManager::new(paths);
        assert!(manager.initialize_local_manifest().is_err(), "{suffix}");
        assert!(manager.ensure_manifest().is_err(), "{suffix}");
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0, "{suffix}");
    }
    std::fs::create_dir(target.join("dependencies")).unwrap();
    for suffix in ["/", "/."] {
        let mut spelling = target.as_os_str().to_os_string();
        spelling.push(suffix);
        let paths = AppPaths::from_home(spelling.into());
        let manager = DependencyManager::new(paths);
        manager.initialize_local_manifest().unwrap();
        manager.ensure_manifest().unwrap();
    }
}

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
