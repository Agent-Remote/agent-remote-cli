//! Passive desktop diagnostics never initialize state or run discovered binaries.

mod versions;

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Component, Path};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Failure, Request};
use crate::api::ApiClient;
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManifest;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    online: bool,
    #[serde(default)]
    verify_versions: bool,
    #[serde(default)]
    deep_check: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyOptions {
    #[serde(default)]
    verify_versions: bool,
}

#[derive(Serialize)]
struct Check {
    id: &'static str,
    status: &'static str,
    path: Option<String>,
    suggestion: &'static str,
}

#[derive(Serialize)]
struct Dependency {
    name: String,
    path: String,
    status: &'static str,
    required_version: String,
    license: String,
    license_notice: String,
    version_status: &'static str,
    version_output: Option<String>,
    version_exit_code: Option<i32>,
}

#[derive(Serialize)]
struct Report {
    home: String,
    platform: &'static str,
    online: bool,
    verify_versions: bool,
    deep_check: bool,
    checks: Vec<Check>,
    dependencies: Vec<Dependency>,
    manifest_source: &'static str,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    let canceled = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| Failure::new("configuration_unavailable"))?;
        let work = execute_inner(request, canceled.clone());
        tokio::pin!(work);
        tokio::select! {
            result = &mut work => result,
            _ = terminate.recv() => {
                canceled.store(true, Ordering::Release);
                // Let synchronous credential inspection kill/reap its tool before
                // the standalone entry point exits the process. Async version
                // probes are dropped and killed when this bounded wait ends.
                let _ = tokio::time::timeout(std::time::Duration::from_secs(1), &mut work).await;
                Err(Failure::new("canceled"))
            },
        }
    }
    #[cfg(not(unix))]
    execute_inner(request, canceled).await
}

async fn execute_inner(request: &Request, canceled: Arc<AtomicBool>) -> Result<Value, Failure> {
    let (online, verify_versions, deep_check) = if request.method == "diagnostics.inspect" {
        let options = serde_json::from_value::<Options>(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        (options.online, options.verify_versions, options.deep_check)
    } else {
        let options = serde_json::from_value::<DependencyOptions>(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        (false, options.verify_versions, false)
    };
    let dependencies_only = request.method == "dependencies.inspect";
    inspect_with_flags(
        online,
        verify_versions,
        deep_check,
        dependencies_only,
        canceled,
    )
    .await
}

/// Run the passive diagnostic projection for another structured desktop
/// operation.  Keeping this helper here ensures the status/doctor/deps
/// contracts use exactly the same bounded readers and redaction rules as the
/// original `diagnostics.inspect` method.
pub(super) async fn inspect_flags(
    online: bool,
    verify_versions: bool,
    deep_check: bool,
    dependencies_only: bool,
) -> Result<Value, Failure> {
    inspect_with_flags(
        online,
        verify_versions,
        deep_check,
        dependencies_only,
        Arc::new(AtomicBool::new(false)),
    )
    .await
}

async fn inspect_with_flags(
    online: bool,
    verify_versions: bool,
    deep_check: bool,
    dependencies_only: bool,
    canceled: Arc<AtomicBool>,
) -> Result<Value, Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let inspection_cancel = canceled.clone();
    let (mut report, config) = tokio::task::spawn_blocking(move || {
        inspect(&paths, dependencies_only, deep_check, &inspection_cancel)
    })
    .await
    .map_err(|_| Failure::new("configuration_unavailable"))?;
    if canceled.load(Ordering::Acquire) {
        return Err(Failure::new("canceled"));
    }
    report.online = online;
    report.verify_versions = verify_versions;
    if verify_versions {
        versions::inspect(&mut report).await;
    }
    if !dependencies_only {
        let status = match (online, config.and_then(|c| c.server_url)) {
            (false, _) => "not_checked",
            (true, None) => "missing",
            (true, Some(server)) => match ApiClient::new(server) {
                Ok(client) => match client.healthz().await {
                    Ok(_) => "reachable",
                    Err(error) if matches!(error.status_code(), Some(401 | 403)) => "inaccessible",
                    Err(_) => "unavailable",
                },
                Err(_) => "invalid",
            },
        };
        report.checks.push(Check {
            id: "server_connection",
            status,
            path: None,
            suggestion: match status {
                "not_checked" => "run_online",
                "reachable" => "none",
                _ => "check_server",
            },
        });
    }
    serde_json::to_value(report).map_err(|_| Failure::new("configuration_unavailable"))
}

fn inspect(
    paths: &AppPaths,
    dependencies_only: bool,
    deep_check: bool,
    canceled: &AtomicBool,
) -> (Report, Option<Config>) {
    let mut report = Report {
        home: paths.home().to_string_lossy().into_owned(),
        platform: std::env::consts::OS,
        online: false,
        verify_versions: false,
        deep_check,
        checks: Vec::new(),
        dependencies: Vec::new(),
        manifest_source: "default",
    };
    let config = if dependencies_only {
        None
    } else {
        for (id, path) in [
            ("home", paths.home().to_path_buf()),
            ("bin", paths.bin_dir()),
            ("dependencies", paths.dependencies_dir()),
            ("wireguard", paths.wireguard_dir()),
        ] {
            report.checks.push(path_check(id, &path, true));
        }
        // Existence is deliberately separate from SQLite integrity. Opening a
        // database (even read-only WAL mode) can create ancillary state files.
        let mut sqlite = path_check("sqlite", &paths.state_db_path(), false);
        if deep_check && sqlite.status == "present" {
            match crate::local_state::LocalState::inspect_readonly(paths) {
                Ok(()) => sqlite.suggestion = "sqlite_readable",
                Err(error) => {
                    sqlite.status = match error
                        .downcast_ref::<rusqlite::Error>()
                        .and_then(|e| e.sqlite_error_code())
                    {
                        Some(
                            rusqlite::ErrorCode::PermissionDenied | rusqlite::ErrorCode::CannotOpen,
                        ) => "inaccessible",
                        Some(
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked,
                        ) => "unavailable",
                        _ => "invalid",
                    };
                    sqlite.suggestion = "check_path";
                }
            }
        }
        report.checks.push(sqlite);
        let loaded = read_bounded(&paths.config_path(), 64 * 1024).and_then(|bytes| {
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|raw| toml::from_str::<Config>(raw).ok())
                .ok_or("invalid")
        });
        let status = loaded.as_ref().map(|_| "present").unwrap_or_else(|s| *s);
        report.checks.push(Check {
            id: "config",
            status,
            path: Some(paths.config_path().to_string_lossy().into_owned()),
            suggestion: if status == "present" {
                "none"
            } else {
                "configure"
            },
        });
        let config = loaded.ok();
        for (id, present) in [
            (
                "server",
                config
                    .as_ref()
                    .and_then(|c| c.server_url.as_ref())
                    .is_some(),
            ),
            (
                "device",
                config
                    .as_ref()
                    .and_then(|c| c.active_device_id.as_ref())
                    .is_some(),
            ),
        ] {
            report.checks.push(Check {
                id,
                status: if present { "present" } else { "missing" },
                path: None,
                suggestion: if present { "none" } else { "configure" },
            });
        }
        let (credential_status, suggestion) = if deep_check {
            use crate::auth::inspection::{inspect_credential, CredentialInspection};
            match config
                .as_ref()
                .map(|config| inspect_credential(paths, config, canceled))
            {
                Some(CredentialInspection::Present) => ("present", "credential_present"),
                Some(CredentialInspection::BindingMismatch) => ("invalid", "credential_binding"),
                Some(CredentialInspection::Unavailable) => ("inaccessible", "credential_access"),
                _ => ("missing", "configure"),
            }
        } else {
            ("not_checked", "verify_signin")
        };
        report.checks.push(Check {
            id: "credential",
            status: credential_status,
            path: None,
            suggestion,
        });
        config
    };
    inspect_dependencies(paths, &mut report);
    #[cfg(windows)]
    if !dependencies_only {
        for (id, path) in [
            ("windows_ssh", crate::platform::windows_openssh_path("ssh")),
            ("windows_scp", crate::platform::windows_openssh_path("scp")),
            (
                "windows_wireguard",
                crate::platform::windows_wireguard_path(),
            ),
        ] {
            report.checks.push(Check {
                id,
                status: if path.is_some() { "present" } else { "missing" },
                path: path.map(|p| p.to_string_lossy().into_owned()),
                suggestion: if id == "windows_wireguard" {
                    "install_wireguard"
                } else {
                    "install_openssh"
                },
            });
        }
    }
    (report, config)
}

fn inspect_dependencies(paths: &AppPaths, report: &mut Report) {
    let path = paths.dependency_manifest_path();
    let (manifest, status) = match read_bounded(&path, 256 * 1024) {
        Ok(bytes) => match serde_json::from_slice::<DependencyManifest>(&bytes) {
            Ok(manifest) if manifest.schema_version == 1 && manifest.dependencies.len() <= 128 => {
                report.manifest_source = "file";
                (Some(manifest), "present")
            }
            _ => (None, "invalid"),
        },
        Err("missing") => (Some(DependencyManifest::default_managed()), "missing"),
        Err(status) => (None, status),
    };
    if manifest.is_none() {
        report.manifest_source = "unavailable";
    }
    report.checks.push(Check {
        id: "manifest",
        status,
        path: Some(path.to_string_lossy().into_owned()),
        suggestion: if status == "present" {
            "none"
        } else {
            "repair_installation"
        },
    });
    let Some(manifest) = manifest else { return };
    for dependency in manifest.dependencies {
        let relative = Path::new(&dependency.binary);
        let safe = !dependency.binary.is_empty()
            && relative
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
            && dependency.binary.len() <= 4096;
        let path = if safe {
            paths
                .home()
                .join(crate::dependencies::platform_binary(&dependency.binary))
        } else {
            paths.home().to_path_buf()
        };
        report.dependencies.push(Dependency {
            name: dependency.name,
            path: if safe {
                path.to_string_lossy().into_owned()
            } else {
                String::new()
            },
            status: if safe {
                binary_status(&path)
            } else {
                "invalid"
            },
            required_version: dependency.required_version,
            license: dependency.license,
            license_notice: dependency.license_notice,
            version_status: "not_checked",
            version_output: None,
            version_exit_code: None,
        });
    }
}

fn path_check(id: &'static str, path: &Path, directory: bool) -> Check {
    let status = match fs::metadata(path) {
        Ok(m) if m.is_dir() == directory && (directory || m.is_file()) => "present",
        Ok(_) => "invalid",
        Err(e) => io_status(&e),
    };
    Check {
        id,
        status,
        path: Some(path.to_string_lossy().into_owned()),
        suggestion: if id == "sqlite" && status == "present" {
            "presence_only"
        } else if status == "present" {
            "none"
        } else {
            "check_path"
        },
    }
}

fn binary_status(path: &Path) -> &'static str {
    match fs::metadata(path) {
        Ok(meta) if meta.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if path.extension().is_none_or(|extension| extension != "msi")
                    && meta.permissions().mode() & 0o111 == 0
                {
                    return "inaccessible";
                }
            }
            "present"
        }
        Ok(_) => "invalid",
        Err(e) => io_status(&e),
    }
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| io_status(&e))?;
    if !file.metadata().map_err(|e| io_status(&e))?.is_file() {
        return Err("invalid");
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_status(&e))?;
    if bytes.len() > limit {
        return Err("invalid");
    }
    Ok(bytes)
}

fn io_status(error: &std::io::Error) -> &'static str {
    match error.kind() {
        ErrorKind::NotFound => "missing",
        ErrorKind::PermissionDenied => "inaccessible",
        _ => "unavailable",
    }
}
