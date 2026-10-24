//! Persistent one-shot request journal for protected WireGuard brokers.
//!
//! A request is reserved before any privileged command is started.  The
//! reservation is append-only and synced before it is acknowledged, so a
//! broker restart cannot turn an uncertain operation into a fresh execution
//! opportunity.  Malformed state, unsafe paths, and a full bounded journal
//! fail closed.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::configuration::ConfigError;

pub const MAX_REPLAY_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    request_sha256: String,
}

/// A durable reservation set owned by one broker process.
pub struct ReplayJournal {
    path: PathBuf,
    used: HashSet<String>,
}

impl ReplayJournal {
    /// Open an existing journal without repairing it.  Any malformed or
    /// contradictory line leaves the broker unavailable rather than silently
    /// making a request reusable.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        validate_path(&path)?;
        let mut used = HashSet::new();
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ConfigError("wireguard_replay_journal_unsafe"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
                    return Err(ConfigError("wireguard_replay_journal_unsafe"));
                }
            }
            let file = File::open(&path)
                .map_err(|_| ConfigError("wireguard_replay_journal_unavailable"))?;
            for line in BufReader::new(file).lines() {
                let line = line.map_err(|_| ConfigError("wireguard_replay_journal_invalid"))?;
                if line.is_empty() {
                    return Err(ConfigError("wireguard_replay_journal_invalid"));
                }
                let entry: Entry = serde_json::from_str(&line)
                    .map_err(|_| ConfigError("wireguard_replay_journal_invalid"))?;
                validate_digest(&entry.request_sha256)?;
                if !used.insert(entry.request_sha256) || used.len() > MAX_REPLAY_ENTRIES {
                    return Err(ConfigError("wireguard_replay_journal_invalid"));
                }
            }
        }
        Ok(Self { path, used })
    }

    /// Reserve exactly one request.  The line is synced before the in-memory
    /// set changes; a failed write therefore leaves the request retryable only
    /// after an explicit process restart and journal repair by an operator.
    pub fn reserve(&mut self, request_sha256: &str) -> Result<(), ConfigError> {
        validate_digest(request_sha256)?;
        if self.used.contains(request_sha256) {
            return Err(ConfigError("wireguard_broker_request_replayed"));
        }
        if self.used.len() >= MAX_REPLAY_ENTRIES {
            return Err(ConfigError("wireguard_replay_journal_full"));
        }
        let parent = self
            .path
            .parent()
            .ok_or(ConfigError("wireguard_replay_journal_unavailable"))?;
        ensure_directory(parent)?;
        let encoded = serde_json::to_vec(&Entry {
            request_sha256: request_sha256.to_string(),
        })
        .map_err(|_| ConfigError("wireguard_replay_journal_invalid"))?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Do not follow a destination replacement between the metadata
            // check above and this privileged append.
            options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        }
        let mut file = options
            .open(&self.path)
            .map_err(|_| ConfigError("wireguard_replay_journal_unavailable"))?;
        if let Ok(metadata) = file.metadata() {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ConfigError("wireguard_replay_journal_unsafe"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
                    return Err(ConfigError("wireguard_replay_journal_unsafe"));
                }
            }
        } else {
            return Err(ConfigError("wireguard_replay_journal_unavailable"));
        }
        file.write_all(&encoded)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|_| ConfigError("wireguard_replay_journal_sync_failed"))?;
        self.used.insert(request_sha256.to_string());
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.used.len()
    }
}

fn validate_path(path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(ConfigError("wireguard_replay_journal_unsafe"));
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), ConfigError> {
    fs::create_dir_all(path).map_err(|_| ConfigError("wireguard_replay_journal_unavailable"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ConfigError("wireguard_replay_journal_unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ConfigError("wireguard_replay_journal_unsafe"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            return Err(ConfigError("wireguard_replay_journal_unsafe"));
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ConfigError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ConfigError("wireguard_replay_journal_invalid"))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_replay.rs"]
mod tests;
