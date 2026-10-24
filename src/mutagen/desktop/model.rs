//! Projection of Mutagen's versioned public JSON model; no upstream error text escapes.
use super::{Error, Observation, Result};
use crate::{api::SyncSessionData, workspace::DEFAULT_EXCLUDES};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Session {
    pub identifier: String,
    name: String,
    pub paused: bool,
    status: String,
    alpha: Value,
    beta: Value,
    mode: String,
    ignore: Value,
    permissions: Value,
    #[serde(default)]
    last_error: String,
    #[serde(default)]
    successful_cycles: u64,
    #[serde(default)]
    conflicts: Vec<Value>,
    #[serde(default)]
    excluded_conflicts: u64,
}

impl Session {
    pub fn observation(&self) -> Observation {
        let count = (self.conflicts.len() as u64).saturating_add(self.excluded_conflicts);
        let observed = !self.paused
            && self.successful_cycles > 0
            && self.last_error.is_empty()
            && self.status == "watching"
            && endpoint_ready(&self.alpha)
            && endpoint_ready(&self.beta);
        Observation {
            state: "available",
            conflicts: if self.paused {
                "unknown"
            } else if count > 0 {
                "detected"
            } else if observed {
                "none_observed"
            } else {
                "unknown"
            },
            paused: Some(self.paused),
            status: Some(match self.status.as_str() {
                "disconnected" => "disconnected",
                "watching" => "watching",
                "scanning" => "scanning",
                "reconciling" => "reconciling",
                "saving" => "saving",
                "transitioning" => "transitioning",
                "connecting-alpha" => "connecting-alpha",
                "connecting-beta" => "connecting-beta",
                "staging-alpha" => "staging-alpha",
                "staging-beta" => "staging-beta",
                "waiting-for-rescan" => "waiting-for-rescan",
                "halted-on-root-emptied" => "halted-on-root-emptied",
                "halted-on-root-deletion" => "halted-on-root-deletion",
                "halted-on-root-type-change" => "halted-on-root-type-change",
                _ => "unknown",
            }),
            conflict_count: if self.paused || (count == 0 && !observed) {
                None
            } else {
                Some(count)
            },
        }
    }

    fn matches(&self, sync: &SyncSessionData) -> bool {
        let Some(remote) = remote_parts(sync) else {
            return false;
        };
        let mut ignores: Vec<_> = DEFAULT_EXCLUDES.iter().map(|s| (*s).to_string()).collect();
        for value in &sync.exclude {
            if !ignores.contains(value) {
                ignores.push(value.clone());
            }
        }
        let actual_ignores = self.ignore.get("paths").and_then(Value::as_array);
        self.name == sync.mutagen_session_id.as_deref().unwrap_or_default()
            && valid_identifier(&self.identifier)
            && self.alpha["protocol"] == "local"
            && self.alpha["path"] == sync.local_path
            && self.beta["protocol"] == "ssh"
            && self.beta["path"] == sync.remote_path
            && self.beta["user"] == remote.0
            && self.beta["host"] == remote.1
            && self.beta.get("port").and_then(Value::as_u64).unwrap_or(0) == u64::from(remote.2)
            && endpoint_config_safe(&self.alpha)
            && endpoint_config_safe(&self.beta)
            && self.mode == "two-way-safe"
            && actual_ignores.is_some_and(|a| {
                a.len() == ignores.len() && a.iter().zip(&ignores).all(|(a, b)| a == b)
            })
            && self
                .ignore
                .get("syntax")
                .is_none_or(|v| v == "mutagen" || v == "")
            && self
                .ignore
                .get("vcs")
                .is_none_or(|v| v == "propagate" || v == "")
            && self.permissions["defaultFileMode"] == "0660"
            && self.permissions["defaultDirectoryMode"] == "0770"
            && self
                .permissions
                .get("mode")
                .is_none_or(|v| v == "portable" || v == "")
            && ["defaultOwner", "defaultGroup"]
                .iter()
                .all(|k| self.permissions.get(k).is_none_or(|v| v == ""))
    }
}

fn endpoint_ready(value: &Value) -> bool {
    value["connected"] == true
        && value["scanned"] == true
        && ["scanProblems", "transitionProblems"].iter().all(|key| {
            value
                .get(key)
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
        })
        && ["excludedScanProblems", "excludedTransitionProblems"]
            .iter()
            .all(|key| value.get(key).is_none_or(|v| v.as_u64() == Some(0)))
}

fn endpoint_config_safe(value: &Value) -> bool {
    // Endpoint-specific overrides can change ignores/ownership independently of
    // the session configuration. Managed sessions do not create any overrides.
    const KEYS: &[&str] = &[
        "environment",
        "parameters",
        "mode",
        "hash",
        "maxEntryCount",
        "maxStagingFileSize",
        "probeMode",
        "scanMode",
        "stageMode",
        "ignore",
        "symlink",
        "watch",
        "permissions",
        "compression",
    ];
    KEYS.iter()
        .all(|key| value.get(key).is_none_or(empty_configuration))
}
fn empty_configuration(value: &Value) -> bool {
    match value {
        Value::Object(v) => v.values().all(empty_configuration),
        Value::Array(v) => v.is_empty(),
        Value::String(v) => v.is_empty(),
        Value::Number(v) => v.as_u64() == Some(0),
        Value::Null => true,
        _ => false,
    }
}

pub(super) fn select(bytes: &[u8], sync: &SyncSessionData) -> Result<Option<Session>> {
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<Session>();
    let Some(first) = stream.next() else {
        return Ok(None);
    };
    let session = first.map_err(|_| Error::new("sync_mutagen_response_invalid"))?;
    if stream.next().is_some() {
        return Err(Error::new("sync_mutagen_ambiguous"));
    }
    if !session.matches(sync) {
        return Err(Error::new("sync_mutagen_target_changed"));
    }
    Ok(Some(session))
}

pub(super) fn validate_target(sync: &SyncSessionData) -> Result<()> {
    let name = sync.mutagen_session_id.as_deref().unwrap_or_default();
    if !valid_name(name)
        || !std::path::Path::new(&sync.local_path).is_absolute()
        || sync.local_path.chars().any(char::is_control)
        || sync.sync_mode != "two_way"
        || !sync.sync_git
        || remote_parts(sync).is_none()
        || sync.exclude.len() > 256
        || sync
            .exclude
            .iter()
            .any(|s| s.len() > 4096 || s.chars().any(char::is_control))
    {
        return Err(Error::new("sync_target_invalid"));
    }
    Ok(())
}

pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && name != "defaults"
        && uuid::Uuid::parse_str(name).is_err()
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

pub(super) fn valid_identifier(value: &str) -> bool {
    value.starts_with("sync_")
        && value.len() <= 128
        && value.len() > 5
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn remote_parts(sync: &SyncSessionData) -> Option<(&str, &str, u16)> {
    endpoint_parts(sync.remote_endpoint.as_deref()?, &sync.remote_path)
}

pub(super) fn endpoint_parts<'a>(
    endpoint: &'a str,
    remote_path: &str,
) -> Option<(&'a str, &'a str, u16)> {
    // Server's sync URL is an SCP-style Mutagen SSH endpoint, with an explicit port.
    let (user, rest) = endpoint.split_once('@')?;
    let (host, rest) = rest.split_once(':')?;
    let (port, path) = rest.split_once(':')?;
    let port = port.parse::<u16>().ok()?;
    if user.is_empty()
        || user.len() > 64
        || user.starts_with('-')
        || !user
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
        || host.is_empty()
        || host.starts_with('-')
        || port == 0
        || !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
        || path != remote_path
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.split('/').any(|p| p == ".." || p == ".")
    {
        return None;
    }
    Some((user, host, port))
}
