//! Bounded, content-free Mutagen operations shared by desktop control and the CLI.
//!
//! Queries never prepare the SSH environment or autostart/stop the daemon. Commands
//! address a verified session identifier, not a potentially ambiguous name selector.

pub mod environment;
mod model;
mod process;
mod recovery;
mod verified_flush;
#[allow(unused_imports)] // Used by the library verified-sync foundation.
pub(crate) use verified_flush::verified_flush;

pub use recovery::{inspect_recovery, terminate_recovery, RecoveryObservation};

use crate::{api::SyncSessionData, config::AppPaths};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub state: &'static str,
    pub conflicts: &'static str,
    pub paused: Option<bool>,
    pub status: Option<&'static str>,
    pub conflict_count: Option<u64>,
}

impl Observation {
    fn absent(state: &'static str) -> Self {
        Self {
            state,
            conflicts: "unknown",
            paused: None,
            status: None,
            conflict_count: None,
        }
    }
}

#[derive(Debug)]
pub struct Error {
    code: &'static str,
    changed: bool,
}
impl Error {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            changed: false,
        }
    }
    fn changed(mut self) -> Self {
        self.changed = true;
        self
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn may_have_changed(&self) -> bool {
        self.changed
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

/// Inspect the public Mutagen 0.18 JSON model without changing daemon lifecycle.
pub async fn inspect(paths: &AppPaths, sync: &SyncSessionData) -> Result<Observation> {
    if !super::binary_path(paths).is_file() {
        return Ok(Observation::absent("missing"));
    }
    if !data_directory()?.join("daemon").is_dir() {
        return Ok(Observation::absent("unavailable"));
    }
    Ok(match selected(paths, sync).await? {
        Some(session) => session.observation(),
        None => Observation::absent("session_missing"),
    })
}

async fn selected(paths: &AppPaths, sync: &SyncSessionData) -> Result<Option<model::Session>> {
    model::validate_target(sync)?;
    // Filter the official exported models in the template, rather than interpreting
    // diagnostic English or retaining the file names of unrelated sessions.
    let name = serde_json::to_string(&sync.mutagen_session_id)
        .map_err(|_| Error::new("sync_target_invalid"))?;
    let template =
        format!("{{{{range .}}}}{{{{if eq .Name {name}}}}}{{{{json .}}}}{{{{end}}}}{{{{end}}}}");
    let output = process::run(
        paths,
        &["sync", "list", "--template", &template],
        Duration::from_secs(5),
        false,
        false,
    )
    .await?;
    model::select(&output, sync)
}

/// Apply one confirmed action. Cancellation may leave accepted daemon work running;
/// callers must retain an unknown/partial receipt, never infer rollback or replay it.
pub async fn apply(
    paths: &AppPaths,
    sync: &SyncSessionData,
    action: &str,
    dry_run: bool,
) -> Result<Observation> {
    model::validate_target(sync)?;
    if !matches!(action, "ensure" | "pause" | "resume" | "resolve" | "reset") {
        return Err(Error::new("sync_action_invalid"));
    }
    if dry_run {
        return inspect(paths, sync).await;
    }
    let (_environment_guard, changed) = environment::prepare_guard(paths).await?;
    let result = apply_prepared(paths, sync, action).await;
    result.map_err(|e| if changed { e.changed() } else { e })
}

async fn apply_prepared(
    paths: &AppPaths,
    sync: &SyncSessionData,
    action: &str,
) -> Result<Observation> {
    let before = selected(paths, sync).await?;
    if action == "ensure" {
        if let Some(session) = &before {
            return Ok(session.observation());
        }
    }
    if action == "pause" && before.is_none() {
        return Ok(Observation::absent("session_missing"));
    }
    if action == "resolve" && before.as_ref().is_none_or(|s| s.paused) {
        return Err(Error::new("sync_mutagen_not_running"));
    }
    if matches!(action, "ensure" | "resume" | "reset") {
        check_git(sync).await?;
    }
    if action == "reset" {
        if let Some(session) = &before {
            process::run(
                paths,
                &["sync", "terminate", "--", &session.identifier],
                Duration::from_secs(15),
                true,
                false,
            )
            .await?;
        }
    }
    if before.is_none() || action == "reset" {
        let name = sync
            .mutagen_session_id
            .as_deref()
            .ok_or_else(|| Error::new("sync_target_invalid"))?;
        let endpoint = sync
            .remote_endpoint
            .as_deref()
            .ok_or_else(|| Error::new("sync_target_invalid"))?;
        let mut args = super::create_args(sync, endpoint, name, "two-way-safe");
        for exclude in &sync.exclude {
            if !crate::workspace::DEFAULT_EXCLUDES.contains(&exclude.as_str()) {
                let offset = args.len() - 2;
                args.splice(offset..offset, ["--ignore".into(), exclude.clone()]);
            }
        }
        // Project/global Mutagen configuration must not silently alter the reviewed
        // synchronization mode, ignores or permissions.
        args.insert(2, "--no-global-configuration".into());
        // End flags before user-controlled local paths and remote endpoints.
        args.insert(args.len() - 2, "--".into());
        let values: Vec<_> = args.iter().map(String::as_str).collect();
        process::run(paths, &values, Duration::from_secs(30), true, false)
            .await
            .map_err(Error::changed)?;
        let created = selected(paths, sync)
            .await
            .map_err(Error::changed)?
            .ok_or_else(|| Error::new("sync_mutagen_unavailable").changed())?;
        flush(paths, &created.identifier)
            .await
            .map_err(Error::changed)?;
    } else if let Some(session) = &before {
        let command = if action == "resolve" { "flush" } else { action };
        process::run(
            paths,
            &["sync", command, "--", &session.identifier],
            Duration::from_secs(30),
            true,
            false,
        )
        .await?;
    }
    let observation = inspect(paths, sync).await.map_err(Error::changed)?;
    if action == "resolve" && observation.conflicts != "none_observed" {
        return Err(Error::new(if observation.conflicts == "detected" {
            "sync_conflicts_remaining"
        } else {
            "sync_conflicts_unknown"
        })
        .changed());
    }
    if observation.state != "available"
        || (action == "pause" && observation.paused != Some(true))
        || (action == "resume" && observation.paused != Some(false))
    {
        return Err(Error::new("sync_mutagen_unverified").changed());
    }
    Ok(observation)
}

async fn flush(paths: &AppPaths, identifier: &str) -> Result<()> {
    process::run(
        paths,
        &["sync", "flush", "--", identifier],
        Duration::from_secs(30),
        true,
        false,
    )
    .await
    .map(|_| ())
}

pub(super) fn data_directory() -> Result<PathBuf> {
    let path = match std::env::var_os("MUTAGEN_DATA_DIRECTORY") {
        Some(p) => PathBuf::from(p),
        None => crate::platform::user_home_dir()
            .ok_or_else(|| Error::new("sync_mutagen_unavailable"))?
            .join(".mutagen"),
    };
    if !path.is_absolute() {
        return Err(Error::new("sync_mutagen_environment_invalid"));
    }
    Ok(path)
}

async fn check_git(sync: &SyncSessionData) -> Result<()> {
    check_git_mode(sync, false).await
}

async fn check_git_mode(sync: &SyncSessionData, reject_links: bool) -> Result<()> {
    if !sync.sync_git {
        return Ok(());
    }
    let root = Path::new(&sync.local_path).join(".git");
    let mut pending = vec![root.clone()];
    let mut visited = 0usize;
    while let Some(path) = pending.pop() {
        let metadata = match tokio::fs::symlink_metadata(&path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && path == root => return Ok(()),
            Err(_) => return Err(Error::new("sync_git_check_failed")),
        };
        if reject_links && !metadata.is_dir() {
            return Err(Error::new("sync_git_check_failed"));
        }
        if !metadata.is_dir() {
            continue;
        }
        let mut entries = tokio::fs::read_dir(&path)
            .await
            .map_err(|_| Error::new("sync_git_check_failed"))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|_| Error::new("sync_git_check_failed"))?
        {
            visited += 1;
            if visited > 100_000 {
                return Err(Error::new("sync_git_check_limit"));
            }
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "lock") {
                return Err(Error::new("sync_git_locked"));
            }
            if p == root.join("hooks") || p == root.join("worktrees") {
                continue;
            }
            let kind = entry
                .file_type()
                .await
                .map_err(|_| Error::new("sync_git_check_failed"))?;
            if reject_links && !kind.is_file() && !kind.is_dir() {
                return Err(Error::new("sync_git_check_failed"));
            }
            if kind.is_dir() {
                pending.push(p);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/src/mutagen_desktop.rs"]
mod tests;
