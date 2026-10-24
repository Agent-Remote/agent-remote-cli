//! Exact, read-only recovery inspection and explicitly confirmed local termination.
use super::{data_directory, model, process, Error, Result};
use crate::config::AppPaths;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

/// Content-free immutable identity of the reviewed session. Configuration values
/// stay local: only their digest is returned, never environment or conflict data.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTarget {
    pub identifier: String,
    pub name: String,
    pub local_path: String,
    pub remote_path: String,
    pub endpoint: String,
    pub configuration_fingerprint: String,
}

/// Absence is actionable only after a successful query of a running daemon.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObservation {
    pub state: String,
    pub recoverable: bool,
    pub error_code: Option<String>,
    pub namespace_fingerprint: Option<String>,
    pub target: Option<RecoveryTarget>,
}

impl RecoveryObservation {
    fn blocked(state: &str, code: &str, namespace: Option<String>) -> Self {
        Self {
            state: state.into(),
            recoverable: false,
            error_code: Some(code.into()),
            namespace_fingerprint: namespace,
            target: None,
        }
    }
}

/// Inspect saved mapping metadata without creating directories or starting a daemon.
pub async fn inspect_recovery(
    paths: &AppPaths,
    local_path: &str,
    remote_path: Option<&str>,
    name: Option<&str>,
    endpoint: Option<&str>,
) -> Result<RecoveryObservation> {
    let (Some(remote_path), Some(name), Some(endpoint)) = (remote_path, name, endpoint) else {
        return Ok(RecoveryObservation::blocked(
            "blocked",
            "sync_target_invalid",
            None,
        ));
    };
    if !Path::new(local_path).is_absolute()
        || local_path.chars().any(char::is_control)
        || !model::valid_name(name)
        || model::endpoint_parts(endpoint, remote_path).is_none()
    {
        return Ok(RecoveryObservation::blocked(
            "blocked",
            "sync_target_invalid",
            None,
        ));
    }
    if !crate::mutagen::binary_path(paths).is_file() {
        return Ok(RecoveryObservation::blocked(
            "missing",
            "sync_mutagen_missing",
            None,
        ));
    }
    let data = data_directory()?;
    if !data.join("daemon").is_dir() {
        return Ok(RecoveryObservation::blocked(
            "unavailable",
            "sync_mutagen_unavailable",
            None,
        ));
    }
    let namespace = namespace_fingerprint(&data).await?;
    let template = format!(
        "{{{{range .}}}}{{{{if eq .Name {}}}}}{{{{json .}}}}{{{{end}}}}{{{{end}}}}",
        serde_json::to_string(name).map_err(|_| Error::new("sync_target_invalid"))?
    );
    let bytes = match process::run(
        paths,
        &["sync", "list", "--template", &template],
        Duration::from_secs(5),
        false,
        false,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(RecoveryObservation::blocked(
                "unavailable",
                error.code(),
                Some(namespace),
            ))
        }
    };
    if namespace_fingerprint(&data).await? != namespace {
        return Err(Error::new("sync_mutagen_target_changed"));
    }
    let target = match select(&bytes, local_path, remote_path, name, endpoint) {
        Ok(target) => target,
        Err(error) => {
            return Ok(RecoveryObservation::blocked(
                "blocked",
                error.code(),
                Some(namespace),
            ))
        }
    };
    Ok(RecoveryObservation {
        state: if target.is_some() {
            "available"
        } else {
            "session_missing"
        }
        .into(),
        recoverable: true,
        error_code: None,
        namespace_fingerprint: Some(namespace),
        target,
    })
}

/// Revalidate the frozen target, terminate its exact identifier and verify absence.
/// This never prepares SSH, starts/stops a daemon or deletes either endpoint's files.
pub async fn terminate_recovery(
    paths: &AppPaths,
    local_path: &str,
    remote_path: Option<&str>,
    name: Option<&str>,
    endpoint: Option<&str>,
    expected: &RecoveryObservation,
) -> Result<RecoveryObservation> {
    let _environment_guard = super::environment::lock_only()?;
    let current = inspect_recovery(paths, local_path, remote_path, name, endpoint).await?;
    if !current.recoverable || &current != expected {
        return Err(Error::new("sync_mutagen_target_changed"));
    }
    let Some(target) = current.target else {
        return Ok(current);
    };
    process::run(
        paths,
        &["sync", "terminate", "--", &target.identifier],
        Duration::from_secs(15),
        true,
        false,
    )
    .await?;
    let after = inspect_recovery(paths, local_path, remote_path, name, endpoint)
        .await
        .map_err(Error::changed)?;
    if !after.recoverable
        || after.state != "session_missing"
        || after.namespace_fingerprint != expected.namespace_fingerprint
    {
        return Err(Error::new("sync_mutagen_unverified").changed());
    }
    Ok(after)
}

async fn namespace_fingerprint(data: &Path) -> Result<String> {
    let data = data.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let invalid = || Error::new("sync_mutagen_environment_invalid");
        let path = std::fs::canonicalize(&data).map_err(|_| invalid())?;
        let directory = cap_std::fs::Dir::open_ambient_dir(&path, cap_std::ambient_authority())
            .map_err(|_| invalid())?;
        let identity =
            crate::platform::file_identity(&directory.into_std_file()).map_err(|_| invalid())?;
        let path = path.to_str().ok_or_else(invalid)?;
        Ok(digest(&json!([
            "mutagen-recovery-namespace-v1",
            path,
            identity
        ])))
    })
    .await
    .map_err(|_| Error::new("sync_mutagen_environment_invalid"))?
}

fn digest(value: &Value) -> String {
    format!("sha256:{:x}", Sha256::digest(value.to_string().as_bytes()))
}

fn select(
    bytes: &[u8],
    local_path: &str,
    remote_path: &str,
    name: &str,
    endpoint: &str,
) -> Result<Option<RecoveryTarget>> {
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
    let Some(first) = stream.next() else {
        return Ok(None);
    };
    let mut session = first.map_err(|_| Error::new("sync_mutagen_response_invalid"))?;
    if stream.next().is_some() {
        return Err(Error::new("sync_mutagen_ambiguous"));
    }
    let identifier = session["identifier"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let (user, host, port) = model::endpoint_parts(endpoint, remote_path)
        .ok_or_else(|| Error::new("sync_target_invalid"))?;
    if !model::valid_identifier(&identifier)
        || session["name"] != name
        || session["alpha"]["protocol"] != "local"
        || session["alpha"]["path"] != local_path
        || session["beta"]["protocol"] != "ssh"
        || session["beta"]["path"] != remote_path
        || session["beta"]["user"] != user
        || session["beta"]["host"] != host
        || session["beta"]["port"].as_u64() != Some(u64::from(port))
    {
        return Err(Error::new("sync_mutagen_target_changed"));
    }
    // Remove only documented runtime fields. Unknown future configuration fields
    // remain in the digest so an upstream extension cannot evade revalidation.
    let object = session
        .as_object_mut()
        .ok_or_else(|| Error::new("sync_mutagen_response_invalid"))?;
    for key in [
        "paused",
        "status",
        "lastError",
        "successfulCycles",
        "conflicts",
        "excludedConflicts",
    ] {
        object.remove(key);
    }
    for side in ["alpha", "beta"] {
        let object = session[side]
            .as_object_mut()
            .ok_or_else(|| Error::new("sync_mutagen_response_invalid"))?;
        for key in [
            "connected",
            "scanned",
            "directories",
            "files",
            "symbolicLinks",
            "totalFileSize",
            "scanProblems",
            "excludedScanProblems",
            "transitionProblems",
            "excludedTransitionProblems",
            "stagingProgress",
        ] {
            object.remove(key);
        }
    }
    Ok(Some(RecoveryTarget {
        identifier,
        name: name.into(),
        local_path: local_path.into(),
        remote_path: remote_path.into(),
        endpoint: endpoint.into(),
        configuration_fingerprint: digest(&session),
    }))
}

#[cfg(test)]
#[path = "../../../tests/unit/src/mutagen_recovery.rs"]
mod tests;
