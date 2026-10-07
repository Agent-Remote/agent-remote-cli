// Tests for src/workspace.rs.

use tempfile::tempdir;

use super::{identify_workspace, DEFAULT_EXCLUDES};

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
