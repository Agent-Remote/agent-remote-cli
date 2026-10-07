// Tests for src/mutagen.rs.

use std::env;
use std::path::Path;

use crate::api::SyncSessionData;
use crate::config::AppPaths;

use super::{
    combine_output, configured_mutagen_command, create_args, daemon_was_not_running,
    is_missing_session_output, mutagen_path, session_name,
};

fn sync_session() -> SyncSessionData {
    SyncSessionData {
        id: "sync_1".to_string(),
        user_id: "user_1".to_string(),
        workspace_id: "workspace_1".to_string(),
        node_id: Some("node_1".to_string()),
        local_path: "/tmp/project".to_string(),
        remote_path: "/var/lib/agent-remote/users/u/workspaces/w/files".to_string(),
        status: "starting".to_string(),
        conflict_status: "none".to_string(),
        sync_mode: "two_way".to_string(),
        sync_git: true,
        exclude: Vec::new(),
        mutagen_session_id: Some("agent-remote-sync".to_string()),
        remote_endpoint: Some(
            "agent-remote@10.42.0.10:22:/var/lib/agent-remote/users/u/workspaces/w/files"
                .to_string(),
        ),
        prepare_task_id: Some("prepare_workspace:sync_1".to_string()),
        created_at: "2026-07-04T00:00:00Z".to_string(),
        updated_at: "2026-07-04T00:00:00Z".to_string(),
    }
}

#[test]
fn uses_control_plane_session_name() {
    let sync = sync_session();
    assert_eq!(session_name(&sync).unwrap(), "agent-remote-sync");
}

#[test]
fn isolates_git_index_from_two_way_sync() {
    let sync = sync_session();
    let args = create_args(
        &sync,
        sync.remote_endpoint.as_deref().unwrap(),
        sync.mutagen_session_id.as_deref().unwrap(),
        "two-way-safe",
    );
    assert!(args
        .windows(2)
        .any(|values| values == ["--ignore", ".git/index"]));
}

#[test]
fn prepends_managed_bin_to_mutagen_path() {
    let paths = AppPaths::from_home("/tmp/agent-remote-test".into());
    let path = mutagen_path(&paths).unwrap();
    let entries: Vec<_> = env::split_paths(&path).collect();
    assert_eq!(entries.first(), Some(&paths.bin_dir()));
}

#[test]
fn recognizes_missing_session_errors() {
    assert!(is_missing_session_output(
        "error: unable to locate requested sessions: specification did not match any sessions"
    ));
    assert!(!is_missing_session_output(
        "error: unable to connect to daemon"
    ));
}

#[test]
fn preserves_stdout_and_stderr_for_status_diagnostics() {
    assert_eq!(
        combine_output(
            "Started Mutagen daemon".to_string(),
            "unable to locate requested sessions".to_string()
        ),
        "Started Mutagen daemon\nunable to locate requested sessions"
    );
}

#[test]
fn configures_mutagen_to_use_managed_ssh_commands() {
    let paths = AppPaths::from_home("/tmp/agent-remote-test".into());
    let command = configured_mutagen_command(
        &paths,
        Path::new("/opt/agent-remote/bin/mutagen"),
        Path::new("/opt/agent-remote/bin"),
    )
    .unwrap();
    let environment: std::collections::HashMap<_, _> = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
        .collect();
    assert_eq!(
        environment.get(std::ffi::OsStr::new("MUTAGEN_SSH_PATH")),
        Some(&std::ffi::OsStr::new("/opt/agent-remote/bin"))
    );
}

#[test]
fn recognizes_an_absent_daemon_during_environment_migration() {
    assert!(daemon_was_not_running(
        "error: unable to connect to daemon: connection timed out (is the daemon running?)"
    ));
    assert!(!daemon_was_not_running("error: access denied"));
}
