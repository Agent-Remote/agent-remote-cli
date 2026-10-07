// Tests for src/local_state.rs.

use tempfile::tempdir;

use crate::config::AppPaths;

use super::{LocalDevice, LocalEgoBrowserBinding, LocalState, LocalSyncSession, LocalWorkspace};

#[test]
fn stores_device_metadata_without_token_columns() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();

    state
        .upsert_device(&LocalDevice {
            id: "dev_1".to_string(),
            server_url: "https://example.test".to_string(),
            name: "laptop".to_string(),
            platform: "macos".to_string(),
            status: "active".to_string(),
            ssh_key_id: Some("ssh_1".to_string()),
            wireguard_peer_id: None,
            created_at: Some("2026-07-04T00:00:00Z".to_string()),
            last_seen_at: None,
        })
        .unwrap();

    let device = state.get_device("dev_1").unwrap().unwrap();
    assert_eq!(device.name, "laptop");
    let columns = state.table_columns("devices").unwrap();
    assert!(!columns.iter().any(|column| column.contains("token")));
    assert!(!columns.iter().any(|column| column.contains("secret")));
}

#[test]
fn stores_ego_browser_metadata_without_connection_secrets() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    let binding = LocalEgoBrowserBinding {
        id: "11111111-2222-3333-4444-555555555555".to_string(),
        server_url: "https://example.test".to_string(),
        ego_browser_device_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
        tool_session_id: "99999999-8888-7777-6666-555555555555".to_string(),
        node_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
        status: "active".to_string(),
        generation: 7,
        relay_binding_kind: "ego_browser".to_string(),
        lease_until: Some("2026-09-06T12:00:00Z".to_string()),
    };

    state.upsert_ego_browser_binding(&binding).unwrap();
    assert_eq!(
        state.get_ego_browser_binding(&binding.id).unwrap(),
        Some(binding)
    );
    let columns = state.table_columns("ego_browser_bindings").unwrap();
    assert!(!columns.iter().any(|column| {
        column.contains("token") || column.contains("script") || column.contains("secret")
    }));
}

#[test]
fn stores_key_value_metadata() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state.set_kv("last_login_mode", "device_token").unwrap();
    assert_eq!(
        state.get_kv("last_login_mode").unwrap().as_deref(),
        Some("device_token")
    );
}

#[test]
fn stores_workspace_and_sync_metadata() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();

    state
        .upsert_workspace(&LocalWorkspace {
            id: "workspace_1".to_string(),
            server_url: "https://example.test".to_string(),
            project_key: "sha256:test".to_string(),
            local_path: "/tmp/project".to_string(),
            display_name: "project".to_string(),
            remote_path: Some("/var/lib/agent-remote/users/u/workspaces/w/files".to_string()),
        })
        .unwrap();
    state
        .upsert_sync_session(&LocalSyncSession {
            id: "sync_1".to_string(),
            server_url: "https://example.test".to_string(),
            workspace_id: "workspace_1".to_string(),
            node_id: Some("node_1".to_string()),
            status: "starting".to_string(),
            conflict_status: "none".to_string(),
            mutagen_session_id: Some("agent-remote-sync".to_string()),
            remote_endpoint: Some("ssh://agent@example.test/project".to_string()),
        })
        .unwrap();

    let workspace = state
        .get_workspace_by_project_key("https://example.test", "sha256:test")
        .unwrap()
        .unwrap();
    assert_eq!(workspace.id, "workspace_1");
    let sync = state
        .get_sync_session_for_workspace("workspace_1")
        .unwrap()
        .unwrap();
    assert_eq!(sync.id, "sync_1");
}

#[test]
fn removes_stale_workspace_and_sync_mappings() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();

    state
        .upsert_workspace(&LocalWorkspace {
            id: "workspace_1".to_string(),
            server_url: "https://example.test".to_string(),
            project_key: "sha256:test".to_string(),
            local_path: "/tmp/project".to_string(),
            display_name: "project".to_string(),
            remote_path: None,
        })
        .unwrap();
    for id in ["sync_1", "sync_2"] {
        state
            .upsert_sync_session(&LocalSyncSession {
                id: id.to_string(),
                server_url: "https://example.test".to_string(),
                workspace_id: "workspace_1".to_string(),
                node_id: None,
                status: "active".to_string(),
                conflict_status: "none".to_string(),
                mutagen_session_id: None,
                remote_endpoint: None,
            })
            .unwrap();
    }

    state.delete_sync_session("sync_1").unwrap();
    assert_eq!(
        state
            .get_sync_session_for_workspace("workspace_1")
            .unwrap()
            .unwrap()
            .id,
        "sync_2"
    );
    state.delete_workspace_mapping("workspace_1").unwrap();
    assert!(state
        .get_workspace_by_project_key("https://example.test", "sha256:test")
        .unwrap()
        .is_none());
    assert!(state
        .get_sync_session_for_workspace("workspace_1")
        .unwrap()
        .is_none());
}
