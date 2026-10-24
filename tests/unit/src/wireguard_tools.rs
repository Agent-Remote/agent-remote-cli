use super::*;

#[test]
fn missing_empty_and_directory_paths_are_passively_classified() {
    let dir = tempfile::tempdir().unwrap();
    assert!(inspect_candidate("wg", Path::new("")).is_none());
    assert!(inspect_candidate("wg", &dir.path().join("absent")).is_none());
    let info = inspect_candidate("wg", dir.path()).unwrap();
    assert_eq!(info.state, "not_executable");
    assert!(info.path.unwrap().is_absolute());
}

#[cfg(unix)]
#[test]
fn executable_symlinks_are_canonicalized_without_running_the_tool() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("wg");
    // Execution would leave evidence, discovery must not run this.
    let marker = dir.path().join("unexpected-execution");
    std::fs::write(&file, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        inspect_candidate("wg", &file).unwrap().state,
        "not_executable"
    );
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = dir.path().join("linked-wg");
    symlink(&file, &link).unwrap();
    let info = inspect_candidate("wg", &link).unwrap();
    assert_eq!(info.state, "available");
    assert_eq!(info.path.unwrap(), std::fs::canonicalize(&file).unwrap());
    assert!(!marker.exists());
}

#[cfg(windows)]
#[test]
fn windows_discovery_accepts_only_executable_extension() {
    let dir = tempfile::tempdir().unwrap();
    for (name, state) in [("wg.EXE", "available"), ("wg.cmd", "not_executable")] {
        let path = dir.path().join(name);
        std::fs::write(&path, b"not executed by discovery").unwrap();
        assert_eq!(inspect_candidate("wg", &path).unwrap().state, state);
    }
}

#[test]
fn elevation_has_only_process_observation_states() {
    assert!(matches!(elevation(), "elevated" | "standard" | "unknown"));
}

#[cfg(unix)]
#[test]
fn tool_paths_outside_protocol_constraints_are_never_advertised() {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let non_utf8 = dir.path().join(std::ffi::OsString::from_vec(vec![0xff]));
    assert!(protocol_path(&non_utf8).is_none());
    assert!(inspect_candidate("wg", &non_utf8).is_none());
    {
        let path = dir.path().join("tool\nname");
        std::fs::write(&path, b"fixture only").unwrap();
        assert!(inspect_candidate("wg", &path).is_none());
        let link = dir.path().join("alias");
        symlink(&path, &link).unwrap();
        assert!(inspect_candidate("wg", &link).is_none());
        std::fs::remove_file(&link).unwrap();
    }
    let display_only = unavailable("wg", &dir.path().join("unreadable/../tool"));
    assert_eq!(display_only.path.unwrap(), dir.path().join("tool"));
}
