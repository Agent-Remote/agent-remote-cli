//! Read-only checks and shared private configuration snapshots.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config::AppPaths;

use super::configuration::ConfigError;
use super::{inspection_parser, publication, tools};

pub(super) const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Serialize)]
pub struct CheckResult {
    pub home: PathBuf,
    pub platform: &'static str,
    pub elevation: &'static str,
    pub config: ConfigInspection,
    pub tools: Vec<tools::ToolInfo>,
}

#[derive(Serialize)]
pub struct ConfigInspection {
    pub path: PathBuf,
    pub state: &'static str,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: Option<u16>,
    pub peer_count: Option<usize>,
    pub unsupported_directives: Vec<&'static str>,
}

impl ConfigInspection {
    fn empty(path: PathBuf, state: &'static str) -> Self {
        Self {
            path,
            state,
            addresses: vec![],
            dns: vec![],
            mtu: None,
            peer_count: None,
            unsupported_directives: vec![],
        }
    }
}

pub fn check(paths: &AppPaths, config: Option<&Path>) -> Result<CheckResult, ConfigError> {
    let home =
        crate::setup::absolute_home(paths).map_err(|_| ConfigError("configuration_unavailable"))?;
    let default = home.join("wireguard/agent-remote.conf");
    let config = inspect_config(config.unwrap_or(&default))?;
    Ok(CheckResult {
        home,
        platform: std::env::consts::OS,
        elevation: tools::elevation(),
        config,
        tools: tools::inspect(paths),
    })
}

/// Only private, regular, single-link files are read. Every read has an explicit
/// byte limit; the parsed snapshot is informational, never authority to execute.
pub fn inspect_config(path: &Path) -> Result<ConfigInspection, ConfigError> {
    inspect_snapshot(path).map(|snapshot| snapshot.0)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigBinding {
    pub file_identity: String,
    pub content_sha256: String,
    pub public_key: String,
}

/// Both the parser and digest consume exactly the bytes read from one handle.
/// A path replacement, metadata change or permission change invalidates binding.
pub(super) fn inspect_snapshot(
    path: &Path,
) -> Result<(ConfigInspection, Option<ConfigBinding>), ConfigError> {
    read_snapshot(path)
        .map(|(inspection, snapshot)| (inspection, snapshot.map(|snapshot| snapshot.binding)))
}

/// Opaque outside the WireGuard implementation; no secret serialization or debug.
pub(super) struct PrivateSnapshot {
    pub bytes: Zeroizing<Vec<u8>>,
    pub binding: ConfigBinding,
}

pub(super) fn read_snapshot(
    path: &Path,
) -> Result<(ConfigInspection, Option<PrivateSnapshot>), ConfigError> {
    let path = publication::absolute(path).map_err(|_| ConfigError("invalid_params"))?;
    let empty = |state| Ok((ConfigInspection::empty(path.clone(), state), None));
    let plan = match publication::inspect(&path) {
        Ok(plan) => plan,
        Err(error) => return empty(read_state(error)),
    };
    if plan.target_identity.is_none() {
        return empty("missing");
    }
    let parent = plan.path.parent().ok_or(ConfigError("invalid_params"))?;
    let name = plan
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ConfigError("invalid_params"))?;
    let directory = match publication::open_directory(parent) {
        Ok(directory) => directory,
        Err(error) => return empty(read_state(error)),
    };
    let file = match publication::open_regular(&directory, name) {
        Ok(Some(file)) => file,
        Ok(None) => return empty("missing"),
        Err(error) => return empty(read_state(error)),
    };
    if crate::platform::validate_private_wireguard_file(&file).is_err() {
        return empty("insecure_permissions");
    }
    let before = match publication::snapshot_identity(&file) {
        Ok(identity)
            if plan
                .target_identity
                .as_deref()
                .map(publication::snapshot_fingerprint)
                .as_ref()
                == Some(&identity) =>
        {
            identity
        }
        _ => return empty("unreadable"),
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return empty("unreadable"),
    };
    if metadata.len() > MAX_CONFIG_BYTES {
        return empty("invalid");
    }
    // Fixed-size storage avoids reallocating secret bytes, including when a
    // concurrent writer grows the file. Zeroizing covers every return path.
    let mut bytes = Zeroizing::new(vec![0; MAX_CONFIG_BYTES as usize + 1]);
    let mut filled = 0;
    loop {
        if filled == bytes.len() {
            return empty("invalid");
        }
        match (&file).read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(size) => filled += size,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return empty("unreadable"),
        }
    }
    bytes.truncate(filled);
    if publication::snapshot_identity(&file).ok().as_ref() != Some(&before)
        || publication::inspect(&path).ok().as_ref() != Some(&plan)
        || crate::platform::validate_private_wireguard_file(&file).is_err()
    {
        return empty("unreadable");
    }
    let summary = match inspection_parser::parse(&bytes) {
        Ok(summary) => summary,
        Err(()) => return empty("invalid"),
    };
    let binding = ConfigBinding {
        file_identity: before,
        content_sha256: format!("{:x}", Sha256::digest(bytes.as_slice())),
        public_key: summary.public_key,
    };
    Ok((
        ConfigInspection {
            path,
            state: if summary.unsupported_directives.is_empty() {
                "ready"
            } else {
                "unsupported"
            },
            addresses: summary.addresses,
            dns: summary.dns,
            mtu: summary.mtu,
            peer_count: Some(summary.peer_count),
            unsupported_directives: summary.unsupported_directives,
        },
        Some(PrivateSnapshot { bytes, binding }),
    ))
}

fn read_state(error: ConfigError) -> &'static str {
    if error.0 == "output_invalid" {
        "unsafe_path"
    } else {
        "unreadable"
    }
}
