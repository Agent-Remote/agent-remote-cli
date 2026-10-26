// Tests for src/workspace.rs.

use std::fs;

use tempfile::tempdir;

use super::{check_git_locks, ensure_git_ready, identify_workspace, DEFAULT_EXCLUDES};

#[test]
fn excludes_agent_remote_workspace_marker() {
    assert!(DEFAULT_EXCLUDES.contains(&".agent-remote-workspace.json"));
    assert!(DEFAULT_EXCLUDES.contains(&".git/index"));
    assert!(DEFAULT_EXCLUDES.contains(&".git/logs"));
    for generated in [
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".coverage",
        ".coverage.*",
        "htmlcov",
    ] {
        assert!(DEFAULT_EXCLUDES.contains(&generated));
    }
}

#[test]
fn computes_stable_project_key() {
    let dir = tempdir().unwrap();
    let first = identify_workspace(Some(dir.path())).unwrap();
    let second = identify_workspace(Some(dir.path())).unwrap();
    assert_eq!(first.project_key, second.project_key);
    assert!(first.project_key.starts_with("sha256:"));
    if cfg!(windows) {
        assert!(!first.local_path.to_string_lossy().starts_with(r"\\?\"));
    }
}

#[test]
fn ignores_cursor_metadata_locks_but_blocks_real_git_locks() {
    let dir = tempdir().unwrap();
    let git = dir.path().join(".git");
    fs::create_dir_all(git.join("cursor/crepe")).unwrap();
    fs::write(git.join("cursor/crepe/build.lock"), "").unwrap();

    assert!(check_git_locks(dir.path())
        .unwrap()
        .unwrap()
        .lock_paths
        .is_empty());
    ensure_git_ready(dir.path()).unwrap();

    fs::write(git.join("index.lock"), "").unwrap();
    let status = check_git_locks(dir.path()).unwrap().unwrap();
    assert_eq!(status.lock_paths, vec![git.join("index.lock")]);
    assert!(ensure_git_ready(dir.path()).is_err());
}
