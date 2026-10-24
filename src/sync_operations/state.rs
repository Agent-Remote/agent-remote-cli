use super::{Error, Result, Target};
use crate::{
    api::{SyncSessionData, WorkspaceData},
    config::AppPaths,
    local_state::{LocalState, LocalSyncSession, LocalWorkspace, SyncSnapshot},
    workspace,
};

pub(crate) fn identify(path: &str) -> Result<workspace::WorkspaceIdentity> {
    if path.is_empty()
        || path.len() > 32768
        || path.chars().any(char::is_control)
        || !std::path::Path::new(path).is_absolute()
    {
        return Err(Error::new("invalid_params"));
    }
    let identity = workspace::identify_workspace(Some(std::path::Path::new(path)))
        .map_err(|_| Error::new("sync_target_changed"))?;
    if identity.local_path.to_str() != Some(path) {
        return Err(Error::new("sync_target_changed"));
    }
    Ok(identity)
}
pub(crate) fn snapshot(paths: &AppPaths, server: &str, key: &str) -> Result<SyncSnapshot> {
    LocalState::sync_snapshot(paths, server, key).map_err(|_| Error::new("state_unavailable"))
}
pub(crate) fn target(
    identity: &workspace::WorkspaceIdentity,
    snapshot: &SyncSnapshot,
) -> Result<Target> {
    let local_path = identity
        .local_path
        .to_str()
        .ok_or_else(|| Error::new("invalid_params"))?
        .to_string();
    if let Some(workspace) = &snapshot.workspace {
        if workspace.local_path != local_path || !valid_id(&workspace.id) {
            return Err(Error::new("sync_target_changed"));
        }
    }
    if let Some(sync) = &snapshot.sync {
        if !valid_id(&sync.id)
            || snapshot
                .workspace
                .as_ref()
                .is_none_or(|w| w.id != sync.workspace_id || w.server_url != sync.server_url)
        {
            return Err(Error::new("sync_target_changed"));
        }
    }
    Ok(Target {
        local_path,
        project_key: identity.project_key.clone(),
        workspace_id: snapshot.workspace.as_ref().map(|s| s.id.clone()),
        sync_session_id: snapshot.sync.as_ref().map(|s| s.id.clone()),
        fingerprint: None,
    })
}
pub(super) fn valid_id(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|v| v.to_string() == s)
}
pub(super) fn valid_text(s: &str, n: usize) -> bool {
    !s.is_empty() && s.len() <= n && !s.chars().any(char::is_control)
}
pub(crate) fn validate_sync(sync: &SyncSessionData, target: &Target) -> Result<()> {
    if !valid_id(&sync.id)
        || !valid_id(&sync.workspace_id)
        || sync.node_id.as_deref().is_some_and(|s| !valid_id(s))
        || target.workspace_id.as_ref() != Some(&sync.workspace_id)
        || sync.local_path != target.local_path
        || target
            .sync_session_id
            .as_ref()
            .is_some_and(|id| id != &sync.id)
        || !valid_text(&sync.remote_path, 32768)
        || !matches!(
            sync.status.as_str(),
            "starting" | "active" | "paused" | "failed" | "stopped" | "healthy" | "conflicted"
        )
        || !matches!(
            sync.conflict_status.as_str(),
            "none"
                | "has_conflicts"
                | "conflict"
                | "conflicted"
                | "conflicts"
                | "unresolved"
                | "unknown"
        )
        || sync.sync_mode != "two_way"
        || sync.exclude.len() > 256
        || sync.exclude.iter().any(|s| !valid_text(s, 4096))
        || sync
            .mutagen_session_id
            .as_deref()
            .is_some_and(|s| !valid_text(s, 128))
        || sync
            .remote_endpoint
            .as_deref()
            .is_some_and(|s| !valid_text(s, 8192))
    {
        return Err(Error::new("sync_response_invalid"));
    }
    if target
        .fingerprint
        .as_ref()
        .is_some_and(|s| s != &super::fingerprint(sync))
    {
        return Err(Error::new("sync_target_changed"));
    }
    Ok(())
}
pub(super) fn persist(
    paths: &AppPaths,
    server: &str,
    target: &Target,
    expected: &SyncSnapshot,
    workspace: Option<&WorkspaceData>,
    sync: Option<&SyncSessionData>,
) -> Result<SyncSnapshot> {
    let ws = workspace.map(|w| LocalWorkspace {
        id: w.id.clone(),
        server_url: server.to_string(),
        project_key: w.project_key.clone(),
        local_path: w.local_start_path.clone(),
        display_name: w.display_name.clone(),
        remote_path: w.remote_path.clone(),
    });
    let ss = sync.map(|s| LocalSyncSession {
        id: s.id.clone(),
        server_url: server.to_string(),
        workspace_id: s.workspace_id.clone(),
        node_id: s.node_id.clone(),
        status: s.status.clone(),
        conflict_status: s.conflict_status.clone(),
        mutagen_session_id: s.mutagen_session_id.clone(),
        remote_endpoint: s.remote_endpoint.clone(),
    });
    let state = LocalState::open(paths).map_err(|_| Error::new("state_unavailable"))?;
    state
        .init_schema()
        .map_err(|_| Error::new("state_unavailable"))?;
    if !state
        .compare_sync_snapshot(
            server,
            &target.project_key,
            expected,
            ws.as_ref(),
            ss.as_ref(),
        )
        .map_err(|_| Error::new("state_unavailable"))?
    {
        return Err(Error::new("sync_target_changed"));
    }
    Ok(SyncSnapshot {
        workspace: ws.or_else(|| expected.workspace.clone()),
        sync: ss.or_else(|| expected.sync.clone()),
    })
}
