//! Confirmed workspace synchronization against the CLI's shared metadata.
pub mod recovery;
pub(crate) mod state;
mod types;
use crate::{
    account_defaults::Context,
    api::{
        ApiClient, CreateSyncSessionRequest, CreateWorkspaceRequest, GitSyncPolicy, SyncSessionData,
    },
    auth,
    config::{AppPaths, Config},
    local_state::SyncSnapshot,
};
use std::sync::atomic::AtomicBool;
pub use types::*;
struct Authority {
    _config: std::fs::File,
    _login: auth::login::LoginLock,
    client: ApiClient,
    token: auth::StrictDeviceToken,
}
fn check_context(paths: &AppPaths, expected: &Context) -> Result<Config> {
    let c = Config::load_strict(paths).map_err(|_| Error::new("configuration_unavailable"))?;
    if paths.home() != expected.home
        || c.server_url != expected.server_url
        || c.active_device_id != expected.active_device_id
    {
        return Err(Error::new("configuration_changed"));
    }
    if c.server_url.is_none() || c.active_device_id.is_none() {
        return Err(Error::new("authentication_required"));
    }
    Ok(c)
}
async fn authorize(paths: &AppPaths, expected: &Context) -> Result<Authority> {
    check_context(paths, expected)?;
    let login = auth::login::lock(paths)
        .await
        .map_err(|_| Error::new("credential_unavailable"))?;
    let c = check_context(paths, expected)?;
    let token = auth::load_device_token_strict_locked(paths, &login, &c, &AtomicBool::new(false))
        .await
        .map_err(|_| Error::new("credential_unavailable"))?;
    let config =
        crate::config::write_lock(paths).map_err(|_| Error::new("configuration_unavailable"))?;
    check_context(paths, expected)?;
    let client = ApiClient::new(token.server_url.clone())
        .map_err(|_| Error::new("configuration_unavailable"))?;
    Ok(Authority {
        _config: config,
        _login: login,
        client,
        token,
    })
}
async fn observe(
    paths: &AppPaths,
    a: &Authority,
    path: &str,
    conditional: bool,
) -> Result<(Target, SyncSnapshot, Option<SyncSessionData>)> {
    let identity = state::identify(path)?;
    let snapshot = state::snapshot(paths, &a.token.server_url, &identity.project_key)?;
    let mut target = state::target(&identity, &snapshot)?;
    let sync = match &target.sync_session_id {
        Some(id) => {
            let s = if conditional {
                a.client
                    .get_sync_session_checked(a.token.token.as_str(), id)
                    .await
            } else {
                a.client.get_sync_session(a.token.token.as_str(), id).await
            }
            .map_err(Error::read)?;
            state::validate_sync(&s, &target)?;
            target.fingerprint = Some(fingerprint(&s));
            Some(s)
        }
        None => None,
    };
    Ok((target, snapshot, sync))
}
pub async fn status(paths: &AppPaths, context: Context, path: &str) -> Result<Status> {
    state::identify(path)?;
    let a = authorize(paths, &context).await?;
    let (target, _, sync) = observe(paths, &a, path, false).await?;
    let mutagen = if let Some(s) = &sync {
        inspect(paths, s).await
    } else {
        Observation::unavailable()
    };
    Ok(Status {
        context,
        target,
        sync: sync.as_ref().map(Sync::from),
        mutagen,
    })
}
async fn inspect(paths: &AppPaths, sync: &SyncSessionData) -> Observation {
    match crate::mutagen::desktop::inspect(paths, sync).await {
        Ok(s) => Observation {
            state: s.state,
            conflicts: s.conflicts,
            paused: s.paused,
            status: s.status,
            conflict_count: s.conflict_count,
        },
        Err(_) => Observation::unavailable(),
    }
}
fn record(receipt: &mut Receipt, name: &'static str, result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => {
            receipt.stages.push(Stage {
                name,
                state: "completed",
            });
            Ok(())
        }
        Err(error) => {
            let unknown = error.code == "sync_outcome_unknown";
            receipt.stages.push(Stage {
                name,
                state: if unknown { "unknown" } else { "failed" },
            });
            receipt.outcome = if unknown { "unknown" } else { "partial" };
            receipt.error_code = Some(error.code);
            Err(error)
        }
    }
}
fn recheck(
    paths: &AppPaths,
    a: &Authority,
    target: &Target,
    snapshot: &SyncSnapshot,
) -> Result<()> {
    if state::identify(&target.local_path)?.project_key != target.project_key
        || state::snapshot(paths, &a.token.server_url, &target.project_key)? != *snapshot
    {
        return Err(Error::new("sync_target_changed"));
    }
    Ok(())
}
pub async fn mutate(
    paths: &AppPaths,
    context: Context,
    target: Target,
    method: &str,
    dry_run: bool,
) -> Result<Receipt> {
    if !matches!(
        method,
        "sync.ensure" | "sync.pause" | "sync.resume" | "sync.resolve" | "sync.reset"
    ) {
        return Err(Error::new("invalid_params"));
    }
    state::identify(&target.local_path)?;
    if target
        .workspace_id
        .as_deref()
        .is_some_and(|s| !state::valid_id(s))
        || target
            .sync_session_id
            .as_deref()
            .is_some_and(|s| !state::valid_id(s))
        || target.fingerprint.as_deref().is_some_and(|s| {
            s.len() != 71
                || !s.starts_with("sha256:")
                || !s[7..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(Error::new("invalid_params"));
    }
    let a = authorize(paths, &context).await?;
    let (actual, mut snapshot, mut sync) = observe(paths, &a, &target.local_path, true).await?;
    if target != actual {
        return Err(Error::new("sync_target_changed"));
    }
    if method != "sync.ensure" && sync.is_none() {
        return Err(Error::new("sync_not_found"));
    }
    let mut receipt = Receipt {
        context,
        method: method.to_string(),
        target: target.clone(),
        result_target: target.clone(),
        dry_run,
        outcome: "completed",
        stages: vec![],
        sync: sync.as_ref().map(Sync::from),
        mutagen: None,
        error_code: None,
    };
    let result = if method == "sync.ensure" {
        ensure(paths, &a, &mut receipt, &mut snapshot, &mut sync).await
    } else {
        action(
            paths,
            &a,
            &mut receipt,
            &mut snapshot,
            sync.as_ref().ok_or_else(|| Error::new("sync_not_found"))?,
        )
        .await
    };
    if let Err(error) = result {
        if receipt.error_code.is_none() {
            receipt.outcome = "partial";
            receipt.error_code = Some(error.code);
        }
    }
    Ok(receipt)
}
async fn local(
    paths: &AppPaths,
    a: &Authority,
    r: &mut Receipt,
    snapshot: &SyncSnapshot,
    sync: &SyncSessionData,
) -> Result<()> {
    recheck(paths, a, &r.target, snapshot)?;
    if r.dry_run {
        r.stages.push(Stage {
            name: "mutagen",
            state: "skipped",
        });
        return Ok(());
    }
    let action = r
        .method
        .strip_prefix("sync.")
        .ok_or_else(|| Error::new("invalid_params"))?;
    let result = crate::mutagen::desktop::apply(paths, sync, action, false).await;
    match result {
        Ok(s) => {
            r.mutagen = Some(Observation {
                state: s.state,
                conflicts: s.conflicts,
                paused: s.paused,
                status: s.status,
                conflict_count: s.conflict_count,
            });
            record(r, "mutagen", Ok(()))
        }
        Err(e) => {
            let changed = e.may_have_changed();
            let result = record(r, "mutagen", Err(Error::new(e.code())));
            if changed {
                r.outcome = "unknown";
                if let Some(stage) = r.stages.last_mut() {
                    stage.state = "unknown";
                }
            }
            result
        }
    }
}
async fn action(
    paths: &AppPaths,
    a: &Authority,
    r: &mut Receipt,
    snapshot: &mut SyncSnapshot,
    current: &SyncSessionData,
) -> Result<()> {
    let before = matches!(r.method.as_str(), "sync.pause" | "sync.resolve");
    if before {
        local(paths, a, r, snapshot, current).await?;
    }
    recheck(paths, a, &r.target, snapshot)?;
    let token = a.token.token.as_str();
    let action = r
        .method
        .strip_prefix("sync.")
        .ok_or_else(|| Error::new("invalid_params"))?;
    let result = a
        .client
        .confirmed_sync_session_action(token, action, current)
        .await;
    let next = match result {
        Ok(s) => s,
        Err(e) => {
            record(r, "server", Err(Error::write(e)))?;
            return Ok(());
        }
    };
    record(
        r,
        "server",
        state::validate_sync(&next, &r.target).map_err(|_| Error::new("sync_outcome_unknown")),
    )?;
    r.sync = Some(Sync::from(&next));
    if !before {
        local(paths, a, r, snapshot, &next).await?;
    }
    let persisted = state::persist(
        paths,
        &a.token.server_url,
        &r.target,
        snapshot,
        None,
        Some(&next),
    );
    record(
        r,
        "persist",
        persisted
            .as_ref()
            .map(|_| ())
            .map_err(|e| Error::new(e.code)),
    )?;
    *snapshot = persisted?;
    Ok(())
}
async fn ensure(
    paths: &AppPaths,
    a: &Authority,
    r: &mut Receipt,
    snapshot: &mut SyncSnapshot,
    sync: &mut Option<SyncSessionData>,
) -> Result<()> {
    recheck(paths, a, &r.target, snapshot)?;
    let identity = state::identify(&r.target.local_path)?;
    let token = a.token.token.as_str();
    let workspace = match a
        .client
        .create_workspace(
            token,
            &CreateWorkspaceRequest {
                device_id: a.token.device_id.clone(),
                project_key: r.target.project_key.clone(),
                local_start_path: r.target.local_path.clone(),
                display_name: identity.display_name,
                sync_git: true,
                git_sync_policy: GitSyncPolicy::default(),
            },
        )
        .await
    {
        Ok(w) => w,
        Err(e) => {
            record(r, "workspace", Err(Error::write(e)))?;
            return Ok(());
        }
    };
    let valid = state::valid_id(&workspace.id)
        && workspace.device_id == a.token.device_id
        && workspace.project_key == r.target.project_key
        && state::paths_equal(&workspace.local_start_path, &r.target.local_path)
        && r.target
            .workspace_id
            .as_ref()
            .is_none_or(|id| id == &workspace.id);
    record(
        r,
        "workspace",
        if valid {
            Ok(())
        } else {
            Err(Error::new("sync_outcome_unknown"))
        },
    )?;
    r.result_target.workspace_id = Some(workspace.id.clone());
    let persisted = state::persist(
        paths,
        &a.token.server_url,
        &r.target,
        snapshot,
        Some(&workspace),
        None,
    );
    record(
        r,
        "persist",
        persisted
            .as_ref()
            .map(|_| ())
            .map_err(|e| Error::new(e.code)),
    )?;
    *snapshot = persisted?;
    recheck(paths, a, &r.target, snapshot)?;
    let created = a
        .client
        .create_sync_session(
            token,
            &CreateSyncSessionRequest {
                workspace_id: workspace.id,
                node_id: None,
                local_path: Some(r.target.local_path.clone()),
                sync_mode: "two_way".to_string(),
                sync_git: true,
                exclude: crate::workspace::DEFAULT_EXCLUDES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            },
        )
        .await;
    let mut next = match created {
        Ok(s) => s,
        Err(e) => {
            record(r, "server", Err(Error::write(e)))?;
            return Ok(());
        }
    };
    record(
        r,
        "server",
        state::validate_sync(&next, &r.result_target)
            .map_err(|_| Error::new("sync_outcome_unknown")),
    )?;
    r.result_target.sync_session_id = Some(next.id.clone());
    r.result_target.fingerprint = Some(fingerprint(&next));
    r.sync = Some(Sync::from(&next));
    let persisted = state::persist(
        paths,
        &a.token.server_url,
        &r.target,
        snapshot,
        None,
        Some(&next),
    );
    record(
        r,
        "persist",
        persisted
            .as_ref()
            .map(|_| ())
            .map_err(|e| Error::new(e.code)),
    )?;
    *snapshot = persisted?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    // Legacy healthy and conflicted sessions already have a prepared workspace.
    // Ensuring their local relationship must not clear or wait away file conflicts.
    while !matches!(next.status.as_str(), "active" | "healthy" | "conflicted") {
        if matches!(next.status.as_str(), "failed" | "stopped" | "paused") {
            return record(r, "server", Err(Error::new("sync_prepare_failed")));
        }
        if tokio::time::Instant::now() >= deadline {
            return record(r, "server", Err(Error::new("sync_prepare_timeout")));
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        next = a
            .client
            .get_sync_session(token, &next.id)
            .await
            .map_err(Error::read)?;
        state::validate_sync(&next, &r.result_target)?;
        r.sync = Some(Sync::from(&next));
    }
    let persisted = state::persist(
        paths,
        &a.token.server_url,
        &r.target,
        snapshot,
        None,
        Some(&next),
    );
    record(
        r,
        "persist",
        persisted
            .as_ref()
            .map(|_| ())
            .map_err(|e| Error::new(e.code)),
    )?;
    *snapshot = persisted?;
    local(paths, a, r, snapshot, &next).await?;
    *sync = Some(next);
    Ok(())
}
