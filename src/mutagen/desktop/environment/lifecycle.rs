use super::{inventory, native_lock, snapshot, Error, Plan, Receipt, Result, Stage};
use crate::config::AppPaths;
use std::{ffi::OsStr, fs::File, path::Path, process::Stdio, time::Duration};

fn changed() -> Error {
    Error::new("sync_mutagen_environment_changed")
}

async fn local_snapshot(paths: &AppPaths) -> Result<(Plan, bool)> {
    let paths = paths.clone();
    tokio::task::spawn_blocking(move || {
        inventory::open_path(paths.home(), false)?
            .ok_or_else(|| Error::new("sync_mutagen_environment_invalid"))?;
        let data = super::super::data_directory()?;
        let probe = native_lock::probe(&data)?;
        let busy = matches!(probe, native_lock::Probe::Busy);
        let inventory = inventory::read(&data)?;
        if let native_lock::Probe::Stopped(ref guard) = probe {
            guard.validate()?;
        }
        let (tools, tool_error) = snapshot::tools(&paths);
        let desired = snapshot::desired(&paths, &tools)?;
        let (marker, marker_fingerprint) = snapshot::marker(&data)?;
        let (registration, registration_error) = snapshot::registration();
        let error_code = registration_error.or(tool_error);
        let plan = Plan {
            home: snapshot::text(paths.home())?,
            data_directory: snapshot::text(&data)?,
            namespace_fingerprint: inventory.namespace_fingerprint,
            daemon_state: if busy { "unavailable" } else { "stopped" }.into(),
            running_fingerprint: None,
            registration: registration.into(),
            previous: marker.map(|m| m.binding),
            desired,
            tools,
            sessions: inventory.sessions,
            inventory_fingerprint: inventory.fingerprint,
            marker_fingerprint,
            fingerprint: String::new(),
            repairable: error_code.is_none(),
            error_code,
        };
        Ok((plan, busy))
    })
    .await
    .map_err(|_| Error::new("sync_mutagen_environment_invalid"))?
}

fn fingerprint(plan: &Plan) -> Result<String> {
    let mut copy = plan.clone();
    copy.fingerprint.clear();
    Ok(snapshot::digest(
        &serde_json::to_vec(&copy).map_err(|_| changed())?,
    ))
}

async fn roster(paths: &AppPaths) -> Result<Vec<(String, String, bool)>> {
    let mut result = Vec::new();
    for kind in ["sync", "forward"] {
        let bytes = super::super::process::run(
            paths,
            &[
                kind,
                "list",
                "--template",
                "{{range .}}{{.Identifier}} {{.Paused}}{{\"\\n\"}}{{end}}",
            ],
            Duration::from_secs(5),
            false,
            false,
        )
        .await?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Error::new("sync_mutagen_response_invalid"))?;
        // Official template output appends its own trailing newline.
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() != 2 || !matches!(parts[1], "true" | "false") || result.len() >= 4096 {
                return Err(Error::new("sync_mutagen_response_invalid"));
            }
            result.push((kind.into(), parts[0].into(), parts[1] == "true"));
        }
    }
    result.sort();
    Ok(result)
}

fn expected_roster(plan: &Plan) -> Vec<(String, String, bool)> {
    let mut result: Vec<_> = plan
        .sessions
        .iter()
        .map(|s| (s.kind.clone(), s.identifier.clone(), s.paused))
        .collect();
    result.sort();
    result
}

/// Read the complete persisted namespace even when the daemon is stopped.
pub async fn preview(paths: &AppPaths) -> Result<Plan> {
    let (mut plan, busy) = local_snapshot(paths).await?;
    if busy {
        let before = snapshot::endpoint(Path::new(&plan.data_directory))?;
        let observed = roster(paths).await;
        let after = snapshot::endpoint(Path::new(&plan.data_directory))?;
        let (rechecked, rechecked_busy) = local_snapshot(paths).await?;
        if plan != rechecked || !rechecked_busy || before != after {
            return Err(changed());
        }
        match observed {
            Ok(roster) if before.is_some() && roster == expected_roster(&plan) => {
                plan.daemon_state = "running".into();
                plan.running_fingerprint = before;
            }
            Ok(_) => {
                plan.error_code = Some("sync_mutagen_inventory_changed".into());
                plan.repairable = false;
            }
            Err(error) => {
                plan.error_code = Some(error.code().into());
                plan.repairable = false;
            }
        }
    }
    plan.fingerprint = fingerprint(&plan)?;
    Ok(plan)
}

pub(crate) struct NamespaceGuard {
    file: File,
    data: std::path::PathBuf,
    identity: String,
}
impl NamespaceGuard {
    pub(super) fn acquire(data: &Path) -> Result<Self> {
        Self::acquire_mode(data, true)
    }
    pub(super) fn acquire_existing(data: &Path) -> Result<Self> {
        Self::acquire_mode(data, false)
    }
    fn acquire_mode(data: &Path, create: bool) -> Result<Self> {
        let directory = inventory::open_path(data, create)?.ok_or_else(changed)?;
        let name = OsStr::new("agent-remote-environment.lock");
        let missing = match directory.symlink_metadata(name) {
            Ok(_) => false,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => true,
            Err(_) => return Err(changed()),
        };
        let file = inventory::open_regular(&directory, name, true, missing)?;
        file.try_lock().map_err(|_| Error::new("operation_busy"))?;
        let identity = crate::platform::file_identity(&file).map_err(|_| changed())?;
        Ok(Self {
            file,
            data: data.to_owned(),
            identity,
        })
    }
    pub(super) fn validate(&self) -> Result<()> {
        let directory = inventory::open_path(&self.data, false)?.ok_or_else(changed)?;
        let current = inventory::open_regular(
            &directory,
            OsStr::new("agent-remote-environment.lock"),
            false,
            false,
        )?;
        if crate::platform::file_identity(&current).map_err(|_| changed())? != self.identity
            || crate::platform::file_identity(&self.file).map_err(|_| changed())? != self.identity
        {
            return Err(changed());
        }
        Ok(())
    }
}

pub(super) fn compatible_created_namespace(before: &Plan, after: &Plan) -> bool {
    if before.namespace_fingerprint.is_some() {
        return before == after;
    }
    let mut normalized = after.clone();
    normalized.namespace_fingerprint = None;
    normalized.inventory_fingerprint = before.inventory_fingerprint.clone();
    normalized.fingerprint = before.fingerprint.clone();
    normalized == *before && after.sessions.is_empty() && after.daemon_state == "stopped"
}

impl Receipt {
    fn stage(&mut self, name: &str, state: &str) {
        self.stages.push(Stage {
            name: name.into(),
            state: state.into(),
        });
    }
    fn failure(mut self, name: &str, error: Error) -> Self {
        self.outcome = if error.may_have_changed() {
            "unknown"
        } else {
            "partial"
        }
        .into();
        self.stage(
            name,
            if error.may_have_changed() {
                "unknown"
            } else {
                "failed"
            },
        );
        self.error_code = Some(error.code().into());
        self
    }
}

async fn stopped_guard(data: &Path) -> Result<native_lock::DaemonGuard> {
    for _ in 0..40 {
        match native_lock::acquire(data, true) {
            Ok(guard) => return Ok(guard),
            Err(error) if error.code() == "sync_mutagen_daemon_busy" => {
                tokio::time::sleep(Duration::from_millis(100)).await
            }
            Err(error) => return Err(error.changed()),
        }
    }
    Err(Error::new("sync_mutagen_timeout").changed())
}

/// Revalidate the entire reviewed scope before changing this daemon's lifecycle.
pub async fn apply(paths: &AppPaths, expected_fingerprint: &str) -> Result<Receipt> {
    let plan = preview(paths).await?;
    if plan.fingerprint != expected_fingerprint {
        return Err(changed());
    }
    if !plan.repairable {
        return Err(Error::new("sync_mutagen_environment_blocked"));
    }
    let data = std::path::PathBuf::from(&plan.data_directory);
    let guard = NamespaceGuard::acquire(&data)?;
    let locked = preview(paths).await?;
    if !compatible_created_namespace(&plan, &locked) {
        return Err(changed());
    }
    guard.validate()?;
    let mut receipt = Receipt {
        plan: plan.clone(),
        outcome: "completed".into(),
        stages: vec![],
        environment: None,
        error_code: None,
    };
    // Registration is rechecked immediately before invoking an official stop:
    // on macOS a registered command can otherwise target a different namespace.
    if snapshot::registration().0 != "unmanaged" {
        return Err(changed());
    }
    if plan.daemon_state == "running" {
        if let Err(error) = super::super::process::run(
            paths,
            &["daemon", "stop"],
            Duration::from_secs(10),
            true,
            false,
        )
        .await
        {
            return Ok(receipt.failure("stop", error));
        }
    }
    let daemon_guard = match stopped_guard(&data).await {
        Ok(guard) => guard,
        Err(error) => return Ok(receipt.failure("stop", error)),
    };
    receipt.stage(
        "stop",
        if plan.daemon_state == "running" {
            "completed"
        } else {
            "skipped"
        },
    );
    // Holding the official lock excludes Mutagen while checking everything that
    // could have changed during stop. Do not call preview/probe with this guard.
    let rechecked = (|| {
        daemon_guard.validate()?;
        guard.validate()?;
        let inventory = inventory::read(&data)?;
        let (tools, error) = snapshot::tools(paths);
        let desired = snapshot::desired(paths, &tools)?;
        let (_, marker) = snapshot::marker(&data)?;
        if inventory.sessions != plan.sessions
            || inventory.namespace_fingerprint != locked.namespace_fingerprint
            || tools != plan.tools
            || desired != plan.desired
            || marker != plan.marker_fingerprint
            || error.is_some()
            || snapshot::registration().0 != "unmanaged"
        {
            return Err(changed());
        }
        Ok(())
    })();
    if let Err(error) = rechecked {
        return Ok(receipt.failure("start", error));
    }
    drop(daemon_guard);
    let mut child = match start(paths) {
        Ok(child) => child,
        Err(error) => return Ok(receipt.failure("start", error)),
    };
    // This owned daemon is intentionally detached from transient-client cleanup.
    // Cancellation can leave it running and must retain an unknown operation.
    let ready = ready(paths, &mut child, &plan).await;
    if let Err(error) = ready {
        return Ok(receipt.failure("start", error));
    }
    receipt.stage("start", "completed");
    let verified = preview(paths).await;
    let verified = match verified {
        Ok(after)
            if after.repairable
                && after.registration == "unmanaged"
                && after.daemon_state == "running"
                && after.sessions == plan.sessions
                && after.tools == plan.tools
                && after.desired == plan.desired
                && after.namespace_fingerprint == locked.namespace_fingerprint
                && after.marker_fingerprint == plan.marker_fingerprint
                && child.try_wait().ok() == Some(None) =>
        {
            after
        }
        Ok(_) => {
            return Ok(receipt.failure("verify", Error::new("sync_mutagen_environment_unverified")))
        }
        Err(error) => return Ok(receipt.failure("verify", error.changed())),
    };
    receipt.stage("verify", "completed");
    if let Err(error) = guard.validate() {
        return Ok(receipt.failure("persist", error.changed()));
    }
    let (Some(namespace), Some(running)) = (
        verified.namespace_fingerprint.clone(),
        verified.running_fingerprint.clone(),
    ) else {
        return Ok(receipt.failure("persist", changed().changed()));
    };
    let marker = snapshot::Marker {
        version: 2,
        binding: plan.desired.clone(),
        namespace_fingerprint: namespace,
        running_fingerprint: running,
    };
    if let Err(error) = snapshot::publish(&data, &marker) {
        return Ok(receipt.failure("persist", error));
    }
    let after = match preview(paths).await {
        Ok(after)
            if after.previous.as_ref() == Some(&plan.desired)
                && after.daemon_state == "running"
                && after.running_fingerprint == verified.running_fingerprint
                && after.sessions == plan.sessions
                && after.repairable
                && after.tools == plan.tools
                && after.desired == plan.desired
                && after.namespace_fingerprint == verified.namespace_fingerprint
                && after.registration == "unmanaged" =>
        {
            after
        }
        Ok(_) => {
            return Ok(receipt.failure(
                "persist",
                Error::new("sync_mutagen_environment_unverified").changed(),
            ))
        }
        Err(error) => return Ok(receipt.failure("persist", error.changed())),
    };
    receipt.stage("persist", "completed");
    receipt.environment = Some(after);
    Ok(receipt)
}

pub(super) fn start(paths: &AppPaths) -> Result<tokio::process::Child> {
    let binary = crate::mutagen::binary_path(paths);
    let directory = binary.parent().ok_or_else(changed)?;
    let mut command = tokio::process::Command::from(
        crate::mutagen::configured_mutagen_command(paths, &binary, directory)
            .map_err(|_| changed())?,
    );
    command
        .args(["daemon", "run"])
        .env("MUTAGEN_DATA_DIRECTORY", super::super::data_directory()?)
        .env("MUTAGEN_DISABLE_AUTOSTART", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    #[cfg(windows)]
    command.creation_flags(
        windows_sys::Win32::System::Threading::DETACHED_PROCESS
            | windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP,
    );
    command
        .spawn()
        .map_err(|_| Error::new("sync_mutagen_unavailable"))
}

async fn ready_inner(
    paths: &AppPaths,
    child: &mut tokio::process::Child,
    plan: &Plan,
) -> Result<()> {
    for _ in 0..30 {
        if child
            .try_wait()
            .map_err(|_| Error::new("sync_mutagen_unavailable").changed())?
            .is_some()
        {
            return Err(Error::new("sync_mutagen_environment_unverified").changed());
        }
        if snapshot::endpoint(Path::new(&plan.data_directory))
            .map_err(Error::changed)?
            .is_some_and(|value| Some(value) != plan.running_fingerprint)
            && roster(paths)
                .await
                .is_ok_and(|actual| actual == expected_roster(plan))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(Error::new("sync_mutagen_timeout").changed())
}

/// A marker only applies to its namespace, exact daemon generation and tools.
pub(super) fn matching(paths: &AppPaths) -> Result<bool> {
    let data = super::super::data_directory()?;
    let Some(directory) = inventory::open_path(&data, false)? else {
        return Ok(false);
    };
    let (Some(marker), _) = snapshot::marker(&data)? else {
        return Ok(false);
    };
    let (tools, error) = snapshot::tools(paths);
    if error.is_some() {
        return Ok(false);
    }
    Ok(marker.binding == snapshot::desired(paths, &tools)?
        && Some(marker.running_fingerprint) == snapshot::endpoint(&data)?
        && marker.namespace_fingerprint == inventory::namespace(&data, &directory)?)
}

/// Bound readiness including both complete roster queries.
pub(super) async fn ready(
    paths: &AppPaths,
    child: &mut tokio::process::Child,
    plan: &Plan,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), ready_inner(paths, child, plan))
        .await
        .map_err(|_| Error::new("sync_mutagen_timeout").changed())?
}
