//! Flush only an existing, healthy, completely matched Mutagen identifier.

use std::sync::atomic::{AtomicBool, Ordering};

use super::{environment::ExistingEnvironmentGuard, Error, Observation, Result};
use crate::{api::SyncSessionData, config::AppPaths};

pub(crate) struct FlushObservation {
    pub identifier: String,
    pub before: Observation,
    pub after: Observation,
}

pub(crate) async fn verified_flush(
    paths: &AppPaths,
    sync: &SyncSessionData,
    environment: &ExistingEnvironmentGuard,
    attempted: &AtomicBool,
) -> Result<FlushObservation> {
    super::model::validate_target(sync)?;
    environment.recheck(paths).await?;
    check_git(sync).await?;
    let before = super::selected(paths, sync)
        .await?
        .ok_or_else(|| Error::new("sync_mutagen_session_missing"))?;
    let before_observation = before.observation();
    healthy(&before_observation)?;
    attempted.store(true, Ordering::Release);
    super::flush(paths, &before.identifier).await?;
    let verify = async {
        let after = super::selected(paths, sync)
            .await?
            .ok_or_else(|| Error::new("sync_mutagen_session_missing"))?;
        if before.identifier != after.identifier {
            return Err(Error::new("sync_mutagen_target_changed"));
        }
        let after_observation = after.observation();
        healthy(&after_observation)?;
        check_git(sync).await?;
        environment.recheck(paths).await?;
        Ok(FlushObservation {
            identifier: before.identifier,
            before: before_observation,
            after: after_observation,
        })
    };
    verify.await.map_err(Error::changed)
}

fn healthy(observation: &Observation) -> Result<()> {
    if observation.state != "available" || observation.paused != Some(false) {
        return Err(Error::new("sync_mutagen_not_running"));
    }
    match observation.conflicts {
        "detected" => Err(Error::new("sync_conflicts_remaining")),
        "none_observed"
            if observation.conflict_count == Some(0) && observation.status == Some("watching") =>
        {
            Ok(())
        }
        _ => Err(Error::new("sync_conflicts_unknown")),
    }
}

async fn check_git(sync: &SyncSessionData) -> Result<()> {
    // A worktree pointer or symlink needs a separate reviewed traversal contract;
    // absence of a directory is not evidence that its Git metadata has no locks.
    match tokio::fs::symlink_metadata(std::path::Path::new(&sync.local_path).join(".git")).await {
        Ok(metadata) if !metadata.is_dir() => return Err(Error::new("sync_git_check_failed")),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(Error::new("sync_git_check_failed"))
        }
        _ => {}
    }
    super::check_git_mode(sync, true).await
}

#[cfg(test)]
#[path = "../../../tests/unit/src/verified_mutagen_flush.rs"]
mod tests;
