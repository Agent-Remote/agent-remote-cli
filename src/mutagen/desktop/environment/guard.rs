//! Project commands may initialize an empty namespace, but cannot restart others.
use super::{inventory, lifecycle, snapshot, Error, NamespaceGuard, Result};
use crate::config::AppPaths;

/// An already running, previously bound namespace. This guard cannot initialize
/// directories, lock files, daemon state or environment markers.
pub(crate) struct ExistingEnvironmentGuard {
    namespace: NamespaceGuard,
    plan: super::Plan,
}

impl ExistingEnvironmentGuard {
    pub(crate) async fn acquire(paths: &AppPaths) -> Result<Self> {
        let data = super::super::data_directory()?;
        let namespace = NamespaceGuard::acquire_existing(&data)?;
        let plan = lifecycle::preview(paths).await?;
        namespace.validate()?;
        if !plan.repairable || plan.daemon_state != "running" || !lifecycle::matching(paths)? {
            return Err(mismatch());
        }
        Ok(Self { namespace, plan })
    }

    pub(crate) async fn recheck(&self, paths: &AppPaths) -> Result<()> {
        self.namespace.validate()?;
        if lifecycle::preview(paths).await? != self.plan || !lifecycle::matching(paths)? {
            return Err(Error::new("sync_mutagen_environment_changed"));
        }
        self.namespace.validate()
    }
}

fn mismatch() -> Error {
    Error::new("sync_mutagen_environment_mismatch")
}

/// Serialize an exact recovery mutation without preparing or starting the daemon.
pub(crate) fn lock_only() -> Result<NamespaceGuard> {
    let data = super::super::data_directory()?;
    inventory::open_path(&data, false)?.ok_or_else(mismatch)?;
    NamespaceGuard::acquire(&data)
}

pub(crate) async fn prepare_guard(paths: &AppPaths) -> Result<(NamespaceGuard, bool)> {
    let before = lifecycle::preview(paths).await?;
    if !before.repairable {
        return Err(mismatch());
    }
    let data = std::path::Path::new(&before.data_directory);
    let guard = NamespaceGuard::acquire(data)?;
    let locked = lifecycle::preview(paths).await?;
    if !lifecycle::compatible_created_namespace(&before, &locked) {
        return Err(mismatch());
    }
    guard.validate()?;
    if locked.daemon_state == "running" && lifecycle::matching(paths)? {
        return Ok((guard, false));
    }
    // Even an empty stopped daemon can own external configuration. Only an
    // unused namespace is safe to initialize as part of a project operation.
    let directory = inventory::open_path(data, false)?.ok_or_else(mismatch)?;
    let unused = matches!(directory.symlink_metadata("daemon"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound);
    if !unused
        || !locked.sessions.is_empty()
        || locked.marker_fingerprint.is_some()
        || locked.daemon_state != "stopped"
        || snapshot::registration().0 != "unmanaged"
    {
        return Err(mismatch());
    }
    let mut child = lifecycle::start(paths)?;
    lifecycle::ready(paths, &mut child, &locked).await?;
    let after = lifecycle::preview(paths).await.map_err(Error::changed)?;
    if !after.repairable
        || after.daemon_state != "running"
        || !after.sessions.is_empty()
        || after.tools != locked.tools
        || after.desired != locked.desired
        || after.namespace_fingerprint != locked.namespace_fingerprint
        || after.marker_fingerprint != locked.marker_fingerprint
        || child.try_wait().ok() != Some(None)
    {
        return Err(mismatch().changed());
    }
    guard.validate().map_err(Error::changed)?;
    snapshot::publish(
        data,
        &snapshot::Marker {
            version: 2,
            binding: after.desired,
            namespace_fingerprint: after
                .namespace_fingerprint
                .ok_or_else(|| mismatch().changed())?,
            running_fingerprint: after
                .running_fingerprint
                .ok_or_else(|| mismatch().changed())?,
        },
    )?;
    if !lifecycle::matching(paths).map_err(Error::changed)? {
        return Err(mismatch().changed());
    }
    Ok((guard, true))
}

/// Legacy synchronous callers retain this guard through command completion.
pub(crate) fn legacy_guard(paths: &AppPaths) -> Result<NamespaceGuard> {
    let paths = paths.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| mismatch())?;
        runtime
            .block_on(prepare_guard(&paths))
            .map(|(guard, _)| guard)
    })
    .join()
    .map_err(|_| mismatch())?
}
