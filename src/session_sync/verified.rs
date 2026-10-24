//! Instantaneous readiness of one reviewed relationship, never creation authority.
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::{
    account_defaults::Context,
    api::{ApiClient, SyncSessionData},
    auth,
    config::{AppPaths, Config},
    local_state::SyncSnapshot,
    mutagen::desktop::{self, environment::ExistingEnvironmentGuard, Observation},
    sync_operations::{self, state, Target},
};

#[derive(Debug)]
pub struct VerifiedFlush {
    pub context: Context,
    pub target: Target,
    pub mutagen_identifier: String,
    pub before: Observation,
    pub after: Observation,
}

#[derive(Debug)]
pub struct FlushError {
    pub code: &'static str,
    /// Describes flush only. Credential renewal may already have published a token.
    pub flush_may_have_run: bool,
}
impl std::fmt::Display for FlushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let action = match self.code {
            "credential_unavailable" => "inspect login state before retrying",
            "sync_setup_required" => "initialize local setup and device login separately before reviewing synchronization",
            _ => "inspect original synchronization before retrying",
        };
        write!(
            f,
            "{}; {action}; device credential renewal may already have completed",
            self.code
        )
    }
}
impl std::error::Error for FlushError {}

type Result<T> = std::result::Result<T, &'static str>;

/// Flush an existing reviewed sync without ensure, daemon startup or session creation.
/// A successful result is an observation at return time, not a reusable launch grant.
pub async fn flush_verified(
    paths: &AppPaths,
    context: &Context,
    target: &Target,
    cancel: &AtomicBool,
) -> std::result::Result<VerifiedFlush, FlushError> {
    flush_with_limit(paths, context, target, cancel, Duration::from_secs(90)).await
}

async fn flush_with_limit(
    paths: &AppPaths,
    context: &Context,
    target: &Target,
    cancel: &AtomicBool,
    limit: Duration,
) -> std::result::Result<VerifiedFlush, FlushError> {
    let attempted = AtomicBool::new(false);
    let result = tokio::select! {
        biased;
        _ = canceled(cancel) => Err("sync_flush_canceled"),
        result = tokio::time::timeout(limit, run(paths, context, target, cancel, &attempted)) =>
            result.unwrap_or(Err("sync_flush_timeout")),
    };
    result.map_err(|code| FlushError {
        code,
        flush_may_have_run: attempted.load(Ordering::Acquire),
    })
}

async fn canceled(cancel: &AtomicBool) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn config(paths: &AppPaths, expected: &Context) -> Result<Config> {
    let actual = Config::load_strict(paths).map_err(|_| "configuration_unavailable")?;
    if paths.home() != expected.home
        || actual.server_url != expected.server_url
        || actual.active_device_id != expected.active_device_id
    {
        return Err("configuration_changed");
    }
    if actual.server_url.is_none() || actual.active_device_id.is_none() {
        return Err("authentication_required");
    }
    Ok(actual)
}

struct Local {
    directory: cap_std::fs::Dir,
    identity: String,
    home: cap_std::fs::Dir,
    home_identity: String,
    snapshot: SyncSnapshot,
}
impl Local {
    fn capture(paths: &AppPaths, server: &str, target: &Target) -> Result<Self> {
        let identity = state::identify(&target.local_path).map_err(|e| e.code)?;
        let snapshot = state::snapshot(paths, server, &identity.project_key).map_err(|e| e.code)?;
        let mut actual = state::target(&identity, &snapshot).map_err(|e| e.code)?;
        actual.fingerprint = target.fingerprint.clone();
        if actual != *target
            || target.workspace_id.is_none()
            || target.sync_session_id.is_none()
            || target.fingerprint.as_deref().is_none_or(|value| {
                value.len() != 71
                    || !value.starts_with("sha256:")
                    || !value[7..]
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err("sync_target_changed");
        }
        let directory =
            cap_std::fs::Dir::open_ambient_dir(&target.local_path, cap_std::ambient_authority())
                .map_err(|_| "sync_target_changed")?;
        let identity = crate::platform::file_identity(
            &directory
                .try_clone()
                .map_err(|_| "sync_target_changed")?
                .into_std_file(),
        )
        .map_err(|_| "sync_target_changed")?;
        let home = cap_std::fs::Dir::open_ambient_dir(paths.home(), cap_std::ambient_authority())
            .map_err(|_| "configuration_changed")?;
        let home_identity = crate::platform::file_identity(
            &home
                .try_clone()
                .map_err(|_| "configuration_changed")?
                .into_std_file(),
        )
        .map_err(|_| "configuration_changed")?;
        Ok(Self {
            directory,
            identity,
            home,
            home_identity,
            snapshot,
        })
    }
    fn recheck(&self, paths: &AppPaths, server: &str, target: &Target) -> Result<()> {
        let current = Self::capture(paths, server, target)?;
        let held_home = crate::platform::file_identity(
            &self
                .home
                .try_clone()
                .map_err(|_| "configuration_changed")?
                .into_std_file(),
        )
        .map_err(|_| "configuration_changed")?;
        if current.home_identity != self.home_identity || held_home != self.home_identity {
            return Err("configuration_changed");
        }
        let held = crate::platform::file_identity(
            &self
                .directory
                .try_clone()
                .map_err(|_| "sync_target_changed")?
                .into_std_file(),
        )
        .map_err(|_| "sync_target_changed")?;
        if current.identity != self.identity
            || held != self.identity
            || current.snapshot != self.snapshot
        {
            return Err("sync_target_changed");
        }
        Ok(())
    }
}

async fn observe(client: &ApiClient, token: &str, target: &Target) -> Result<SyncSessionData> {
    let id = target
        .sync_session_id
        .as_deref()
        .ok_or("sync_target_changed")?;
    let sync = client
        .get_sync_session_checked(token, id)
        .await
        .map_err(|_| "sync_server_observation_failed")?;
    state::validate_sync(&sync, target).map_err(|e| e.code)?;
    if target.fingerprint.as_deref() != Some(sync_operations::fingerprint(&sync).as_str()) {
        return Err("sync_target_changed");
    }
    if !matches!(sync.status.as_str(), "active" | "healthy") || sync.conflict_status != "none" {
        return Err("sync_not_ready");
    }
    Ok(sync)
}

async fn run(
    paths: &AppPaths,
    context: &Context,
    target: &Target,
    cancel: &AtomicBool,
    attempted: &AtomicBool,
) -> Result<VerifiedFlush> {
    // Context mismatch must fail before credentials, locks that initialize state, or HTTP.
    let initial = config(paths, context)?;
    auth::existing_refresh_record(paths, &initial).map_err(|_| "sync_setup_required")?;
    let server = initial
        .server_url
        .as_deref()
        .ok_or("authentication_required")?;
    let local = Local::capture(paths, server, target)?;
    let login = auth::login::lock_existing(paths)
        .await
        .map_err(|_| "credential_unavailable")?;
    let _configuration =
        crate::config::write_lock_existing(paths).map_err(|_| "configuration_unavailable")?;
    if config(paths, context)? != initial {
        return Err("configuration_changed");
    }
    local.recheck(paths, server, target)?;
    let token = auth::load_device_token_existing_locked(paths, &login, &initial, cancel)
        .await
        .map_err(|_| "credential_unavailable")?;
    let client = ApiClient::new(server.to_owned()).map_err(|_| "configuration_unavailable")?;
    let before = observe(&client, token.token.as_str(), target).await?;
    let environment = ExistingEnvironmentGuard::acquire(paths)
        .await
        .map_err(|e| e.code())?;
    if config(paths, context)? != initial {
        return Err("configuration_changed");
    }
    local.recheck(paths, server, target)?;
    let flushed = desktop::verified_flush(paths, &before, &environment, attempted)
        .await
        .map_err(|e| e.code())?;
    observe(&client, token.token.as_str(), target).await?;
    environment.recheck(paths).await.map_err(|e| e.code())?;
    local.recheck(paths, server, target)?;
    if config(paths, context)? != initial {
        return Err("configuration_changed");
    }
    Ok(VerifiedFlush {
        context: context.clone(),
        target: target.clone(),
        mutagen_identifier: flushed.identifier,
        before: flushed.before,
        after: flushed.after,
    })
}

#[cfg(test)]
#[path = "../../tests/unit/src/verified_session_sync.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "../../tests/unit/src/verified_sync_contract.rs"]
mod contract_tests;
