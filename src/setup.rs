//! Local preparation shared by CLI workflows and confirmed desktop setup.
//! No configuration, credentials, network or external executables are consulted.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Result};
use serde::Serialize;

use crate::config::AppPaths;
use crate::dependencies::{DependencyManager, ManifestInitialization, ManifestInitializationError};
use crate::local_state::{LocalState, LocalStateInitializationError, StateInitialization};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Ready,
    Applied,
    Failed,
    Skipped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepCode {
    None,
    PathInvalid,
    StateUnavailable,
    UnsupportedStateVersion,
    ManifestInvalid,
    LocalIo,
    DependencyFailed,
}

#[derive(Debug, Serialize)]
pub struct SetupStep {
    pub id: &'static str,
    pub path: PathBuf,
    pub status: StepStatus,
    pub code: StepCode,
}

#[derive(Debug, Serialize)]
pub struct SetupReport {
    pub home: PathBuf,
    pub complete: bool,
    pub steps: Vec<SetupStep>,
}

/// Resolve the selected home without reading its contents or following links.
pub fn absolute_home(paths: &AppPaths) -> Result<PathBuf> {
    if paths
        .home()
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        bail!("selected home must not contain parent traversal")
    }
    // POSIX lstat follows a directory symlink when its spelling ends in `/`
    // or `/.`. Normalize components lexically before checking the home itself;
    // unlike canonicalize, this never resolves a user-selected link.
    let home: PathBuf = std::path::absolute(paths.home())?.components().collect();
    if home.as_os_str().is_empty()
        || home.to_str().is_none()
        || home
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        bail!("selected home must be a representable absolute path without parent traversal")
    }
    Ok(home)
}

/// Prepare independent local components, preserving every failed step in a
/// receipt. A successful return does not imply `complete`; no rollback is claimed.
pub fn initialize(paths: &AppPaths) -> Result<SetupReport> {
    let home = absolute_home(paths)?;
    let paths = AppPaths::new(Some(home.clone()))?;
    let mut steps = Vec::with_capacity(8);
    let home_step = directory("home", &home);
    let home_ready = successful(&home_step);
    steps.push(home_step);
    let mut dependencies_ready = false;
    for (id, path) in [
        ("bin", paths.bin_dir()),
        ("dependencies", paths.dependencies_dir()),
        ("secrets", paths.secrets_dir()),
        ("wireguard", paths.wireguard_dir()),
        ("ssh", paths.ssh_dir()),
    ] {
        let step = if home_ready {
            directory(id, &path)
        } else {
            skipped(id, path)
        };
        if id == "dependencies" {
            dependencies_ready = successful(&step);
        }
        steps.push(step);
    }
    steps.push(if home_ready {
        let (status, code) = match LocalState::initialize_local(&paths) {
            Ok(StateInitialization::Ready) => (StepStatus::Ready, StepCode::None),
            Ok(StateInitialization::Applied) => (StepStatus::Applied, StepCode::None),
            Err(error) => (
                StepStatus::Failed,
                match error.downcast_ref::<LocalStateInitializationError>() {
                    Some(LocalStateInitializationError::InvalidPath) => StepCode::PathInvalid,
                    Some(LocalStateInitializationError::UnsupportedVersion(_)) => {
                        StepCode::UnsupportedStateVersion
                    }
                    _ => StepCode::StateUnavailable,
                },
            ),
        };
        SetupStep {
            id: "database",
            path: paths.state_db_path(),
            status,
            code,
        }
    } else {
        skipped("database", paths.state_db_path())
    });
    steps.push(if dependencies_ready {
        let (status, code) = match DependencyManager::new(paths.clone()).initialize_local_manifest()
        {
            Ok(ManifestInitialization::Ready) => (StepStatus::Ready, StepCode::None),
            Ok(ManifestInitialization::Applied) => (StepStatus::Applied, StepCode::None),
            Err(error) => (
                StepStatus::Failed,
                match error.downcast_ref::<ManifestInitializationError>() {
                    Some(ManifestInitializationError::InvalidPath) => StepCode::PathInvalid,
                    Some(
                        ManifestInitializationError::InvalidManifest
                        | ManifestInitializationError::UnsupportedVersion(_),
                    ) => StepCode::ManifestInvalid,
                    _ => StepCode::LocalIo,
                },
            ),
        };
        SetupStep {
            id: "manifest",
            path: paths.dependency_manifest_path(),
            status,
            code,
        }
    } else {
        skipped("manifest", paths.dependency_manifest_path())
    });
    Ok(SetupReport {
        home,
        complete: steps.iter().all(successful),
        steps,
    })
}

/// Repair only dependency metadata for `deps status --fix`, without widening
/// that command into database, credential or network initialization.
pub fn initialize_dependencies(paths: &AppPaths) -> Result<()> {
    let home = absolute_home(paths)?;
    let paths = AppPaths::new(Some(home.clone()))?;
    for path in [&home, &paths.dependencies_dir()] {
        ensure_directory(path)
            .map_err(|_| anyhow::anyhow!("dependency metadata path is unavailable or unsafe"))?;
    }
    DependencyManager::new(paths).initialize_local_manifest()?;
    Ok(())
}

fn successful(step: &SetupStep) -> bool {
    matches!(step.status, StepStatus::Ready | StepStatus::Applied)
}

fn skipped(id: &'static str, path: PathBuf) -> SetupStep {
    SetupStep {
        id,
        path,
        status: StepStatus::Skipped,
        code: StepCode::DependencyFailed,
    }
}

fn directory(id: &'static str, path: &Path) -> SetupStep {
    let result = ensure_directory(path);
    let (status, code) = match result {
        Ok(created) => (
            if created {
                StepStatus::Applied
            } else {
                StepStatus::Ready
            },
            StepCode::None,
        ),
        Err(code) => (StepStatus::Failed, code),
    };
    SetupStep {
        id,
        path: path.to_path_buf(),
        status,
        code,
    }
}

fn ensure_directory(path: &Path) -> Result<bool, StepCode> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !directory_type(&metadata) {
                return Err(StepCode::PathInvalid);
            }
            crate::platform::set_owner_only_directory_permissions(path)
                .map_err(|_| StepCode::LocalIo)?;
            return Ok(false);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(StepCode::LocalIo),
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if builder.create(path).is_err() {
        return match fs::symlink_metadata(path) {
            Ok(metadata) if !directory_type(&metadata) => Err(StepCode::PathInvalid),
            Ok(_) => Ok(false),
            Err(_) => Err(StepCode::LocalIo),
        };
    }
    if !fs::symlink_metadata(path)
        .map(|metadata| directory_type(&metadata))
        .unwrap_or(false)
    {
        return Err(StepCode::PathInvalid);
    }
    crate::platform::set_owner_only_directory_permissions(path).map_err(|_| StepCode::LocalIo)?;
    Ok(true)
}

fn directory_type(metadata: &fs::Metadata) -> bool {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        } // FILE_ATTRIBUTE_REPARSE_POINT
    }
    true
}
