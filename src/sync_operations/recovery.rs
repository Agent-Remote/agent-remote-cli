//! Reviewed removal of obsolete local relationships. Remote resources and files
//! are never removed; creating a replacement is a separate confirmed operation.
use super::{authorize, recheck, state, Authority, Context, Error, Result, Stage, Target};
use crate::{
    config::AppPaths,
    local_state::{LocalState, SyncSnapshot},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub context: Context,
    pub target: Target,
    pub mapping: SyncSnapshot,
    pub mapping_fingerprint: String,
    pub server_state: String,
    pub mutagen: crate::mutagen::desktop::RecoveryObservation,
    pub recoverable: bool,
    #[serde(deserialize_with = "super::types::required_option")]
    pub error_code: Option<String>,
}
#[derive(Serialize)]
pub struct Receipt {
    pub context: Context,
    pub method: &'static str,
    pub plan: Plan,
    pub result_target: Target,
    pub outcome: &'static str,
    pub stages: Vec<Stage>,
    pub mutagen: Option<crate::mutagen::desktop::RecoveryObservation>,
    pub error_code: Option<&'static str>,
}
fn mapping_fingerprint(snapshot: &SyncSnapshot) -> Result<String> {
    let bytes = serde_json::to_vec(snapshot).map_err(|_| Error::new("state_unavailable"))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

async fn missing(a: &Authority, target: &Target) -> Result<&'static str> {
    if let Some(id) = &target.sync_session_id {
        match a.client.get_sync_session(a.token.token.as_str(), id).await {
            Err(e) if e.status_code() == Some(404) => {}
            Err(e) => return Err(Error::read(e)),
            Ok(_) => return Err(Error::new("sync_recovery_not_required")),
        }
    }
    let id = target
        .workspace_id
        .as_ref()
        .ok_or_else(|| Error::new("sync_recovery_not_required"))?;
    match a.client.get_workspace(a.token.token.as_str(), id).await {
        Err(e) if e.status_code() == Some(404) => Ok("workspace_not_found"),
        Err(e) => Err(Error::read(e)),
        Ok(w) => {
            if w.id != *id
                || w.device_id != a.token.device_id
                || w.project_key != target.project_key
                || w.local_start_path != target.local_path
            {
                return Err(Error::new("sync_target_changed"));
            }
            if target.sync_session_id.is_none() {
                return Err(Error::new("sync_recovery_not_required"));
            }
            Ok("sync_not_found")
        }
    }
}

pub async fn preview(paths: &AppPaths, context: Context, path: &str) -> Result<Plan> {
    let identity = state::identify(path)?;
    let a = authorize(paths, &context).await?;
    let snapshot = state::snapshot(paths, &a.token.server_url, &identity.project_key)?;
    let target = state::target(&identity, &snapshot)?;
    validate_mapping(&snapshot)?;
    let server_state = missing(&a, &target).await?;
    // No HTTP/daemon operation initializes or repairs metadata during this preview.
    let mutagen = inspect(paths, &snapshot, &target).await;
    recheck(paths, &a, &target, &snapshot)?;
    let recoverable = mutagen.recoverable;
    let error_code = mutagen.error_code.clone();
    Ok(Plan {
        context,
        target,
        mapping_fingerprint: mapping_fingerprint(&snapshot)?,
        mapping: snapshot,
        server_state: server_state.into(),
        mutagen,
        recoverable,
        error_code,
    })
}

pub async fn apply(paths: &AppPaths, context: Context, plan: Plan) -> Result<Receipt> {
    if context != plan.context || plan.target.fingerprint.is_some() {
        return Err(Error::new("sync_target_changed"));
    }
    let identity = state::identify(&plan.target.local_path)?;
    let a = authorize(paths, &context).await?;
    let snapshot = state::snapshot(paths, &a.token.server_url, &identity.project_key)?;
    let actual = state::target(&identity, &snapshot)?;
    validate_mapping(&snapshot)?;
    if actual != plan.target
        || snapshot != plan.mapping
        || mapping_fingerprint(&snapshot)? != plan.mapping_fingerprint
    {
        return Err(Error::new("sync_target_changed"));
    }
    if missing(&a, &actual).await? != plan.server_state {
        return Err(Error::new("sync_target_changed"));
    }
    if !plan.recoverable
        || plan.error_code.is_some()
        || !plan.mutagen.recoverable
        || plan.mutagen.error_code.is_some()
    {
        return Err(Error::new("sync_recovery_blocked"));
    }
    recheck(paths, &a, &actual, &snapshot)?;
    let mut receipt = Receipt {
        context,
        method: "sync.recovery.apply",
        result_target: actual.clone(),
        plan,
        outcome: "completed",
        stages: vec![Stage {
            name: "server",
            state: "completed",
        }],
        mutagen: None,
        error_code: None,
    };
    let terminated = terminate(paths, &snapshot, &actual, &receipt.plan.mutagen).await;
    match terminated {
        Ok(observation) => {
            receipt.mutagen = Some(observation);
            receipt.stages.push(Stage {
                name: "mutagen",
                state: "completed",
            });
        }
        Err(e) => {
            receipt.outcome = if e.may_have_changed() {
                "unknown"
            } else {
                "partial"
            };
            receipt.error_code = Some(e.code());
            receipt.stages.push(Stage {
                name: "mutagen",
                state: if e.may_have_changed() {
                    "unknown"
                } else {
                    "failed"
                },
            });
            return Ok(receipt);
        }
    }
    // The exact local session has been observed absent, but external writers may
    // have changed SQLite meanwhile. A failed CAS retains their replacement.
    let remove_workspace = receipt.plan.server_state == "workspace_not_found";
    let persisted = (|| {
        recheck(paths, &a, &actual, &snapshot)?;
        let state = LocalState::open(paths).map_err(|_| Error::new("state_unavailable"))?;
        if !state
            .remove_sync_snapshot(
                &a.token.server_url,
                &actual.project_key,
                &snapshot,
                remove_workspace,
            )
            .map_err(|_| Error::new("sync_outcome_unknown"))?
        {
            return Err(Error::new("sync_target_changed"));
        }
        Ok(())
    })();
    match persisted {
        Ok(()) => {
            receipt.stages.push(Stage {
                name: "persist",
                state: "completed",
            });
            receipt.result_target.sync_session_id = None;
            if remove_workspace {
                receipt.result_target.workspace_id = None;
            }
        }
        Err(e) => {
            let unknown = e.code == "sync_outcome_unknown";
            receipt.outcome = if unknown { "unknown" } else { "partial" };
            receipt.error_code = Some(e.code);
            receipt.stages.push(Stage {
                name: "persist",
                state: if unknown { "unknown" } else { "failed" },
            });
        }
    }
    Ok(receipt)
}

async fn inspect(
    paths: &AppPaths,
    snapshot: &SyncSnapshot,
    target: &Target,
) -> crate::mutagen::desktop::RecoveryObservation {
    let workspace = snapshot.workspace.as_ref();
    let sync = snapshot.sync.as_ref();
    match crate::mutagen::desktop::inspect_recovery(
        paths,
        &target.local_path,
        workspace.and_then(|w| w.remote_path.as_deref()),
        sync.and_then(|s| s.mutagen_session_id.as_deref()),
        sync.and_then(|s| s.remote_endpoint.as_deref()),
    )
    .await
    {
        Ok(observation) => observation,
        Err(e) => crate::mutagen::desktop::RecoveryObservation {
            state: "blocked".into(),
            recoverable: false,
            error_code: Some(e.code().into()),
            namespace_fingerprint: None,
            target: None,
        },
    }
}
async fn terminate(
    paths: &AppPaths,
    snapshot: &SyncSnapshot,
    target: &Target,
    expected: &crate::mutagen::desktop::RecoveryObservation,
) -> std::result::Result<crate::mutagen::desktop::RecoveryObservation, crate::mutagen::desktop::Error>
{
    crate::mutagen::desktop::terminate_recovery(
        paths,
        &target.local_path,
        snapshot
            .workspace
            .as_ref()
            .and_then(|w| w.remote_path.as_deref()),
        snapshot
            .sync
            .as_ref()
            .and_then(|s| s.mutagen_session_id.as_deref()),
        snapshot
            .sync
            .as_ref()
            .and_then(|s| s.remote_endpoint.as_deref()),
        expected,
    )
    .await
}

fn validate_mapping(snapshot: &SyncSnapshot) -> Result<()> {
    if let Some(w) = &snapshot.workspace {
        if !state::valid_text(&w.display_name, 4096)
            || w.remote_path
                .as_deref()
                .is_some_and(|p| !state::valid_text(p, 32768))
        {
            return Err(Error::new("sync_target_changed"));
        }
    }
    if let Some(s) = &snapshot.sync {
        if s.node_id.as_deref().is_some_and(|id| !state::valid_id(id))
            || !state::valid_text(&s.status, 128)
            || !state::valid_text(&s.conflict_status, 128)
            || s.mutagen_session_id
                .as_deref()
                .is_some_and(|v| !state::valid_text(v, 128))
            || s.remote_endpoint
                .as_deref()
                .is_some_and(|v| !state::valid_text(v, 8192))
        {
            return Err(Error::new("sync_target_changed"));
        }
    }
    Ok(())
}
