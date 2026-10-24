use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::platform::protected_directory::{DirectorySync, ProtectedDirectory};

use super::super::execution_request::{ExecutionRequest, OperationRecord};
use super::{ConfigError, ExecutionConfig};

const MAX_RECORD_BYTES: u64 = 128 * 1024;
const JOURNAL_NAME: &str = "submission.log";
const MAX_JOURNAL_BYTES: u64 = 512 * 1024;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One immutable line in the per-request submission journal.  The event hash
/// covers the canonical body and the previous hash links the lines together.
/// This is a recovery/audit record; it is never an execution authorization.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct JournalEvent {
    version: u32,
    sequence: u64,
    previous_sha256: String,
    record: OperationRecord,
    event_sha256: String,
}

#[derive(Serialize)]
struct JournalBody<'a> {
    version: u32,
    sequence: u64,
    previous_sha256: &'a str,
    record: &'a OperationRecord,
}

pub(super) fn unavailable(_: impl std::fmt::Display) -> ConfigError {
    ConfigError("wireguard_execution_unavailable")
}

pub(super) fn check_canceled(canceled: &AtomicBool) -> Result<(), ConfigError> {
    if canceled.load(Ordering::Acquire) {
        Err(ConfigError("wireguard_execution_canceled"))
    } else {
        Ok(())
    }
}

pub(super) fn combine_sync(a: DirectorySync, b: DirectorySync) -> DirectorySync {
    if a == DirectorySync::Synced && b == DirectorySync::Synced {
        DirectorySync::Synced
    } else {
        DirectorySync::Unsupported
    }
}

pub(super) fn target_lock_name(request: &ExecutionRequest) -> String {
    let mut hash = Sha256::new();
    hash.update(b"agent-remote:wireguard:target-lock:v1\0");
    hash.update(request.target_scope_sha256.as_bytes());
    hash.update(b"\0");
    let name = if cfg!(any(windows, target_os = "macos")) {
        request.logical_name.to_ascii_lowercase()
    } else {
        request.logical_name.clone()
    };
    hash.update(name.as_bytes());
    format!("target-{:x}.lock", hash.finalize())
}

pub(super) fn lock(
    root: &ProtectedDirectory,
    name: &str,
    canceled: &AtomicBool,
) -> Result<File, ConfigError> {
    check_canceled(canceled)?;
    let file = match root.open_file(name).map_err(unavailable)? {
        Some(file) => file,
        None => match root.create_file(name) {
            Ok(file) => file,
            Err(_) => root
                .open_file(name)
                .map_err(unavailable)?
                .ok_or(ConfigError("wireguard_execution_unavailable"))?,
        },
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        check_canceled(canceled)?;
        match file.try_lock() {
            Ok(()) => {
                root.verify_file(&file).map_err(unavailable)?;
                // A replaced lock name must not create two independent locks.
                let current = root
                    .open_file(name)
                    .map_err(unavailable)?
                    .ok_or(ConfigError("wireguard_execution_changed"))?;
                if crate::platform::file_identity(&file).map_err(unavailable)?
                    != crate::platform::file_identity(&current).map_err(unavailable)?
                {
                    return Err(ConfigError("wireguard_execution_changed"));
                }
                return Ok(file);
            }
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(ConfigError("wireguard_execution_busy"));
            }
            Err(_) => return Err(ConfigError("wireguard_execution_unavailable")),
        }
    }
}

pub(super) fn load(
    directory: &ProtectedDirectory,
    request_id: &str,
) -> Result<OperationRecord, ConfigError> {
    let invalid = || ConfigError("wireguard_execution_record_invalid");
    let file = directory
        .open_file("record.json")
        .map_err(unavailable)?
        .ok_or_else(invalid)?;
    if file.metadata().map_err(unavailable)?.len() > MAX_RECORD_BYTES {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid());
    }
    let record: OperationRecord = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    record.validate()?;
    // The journal has one canonical encoding. This additionally rejects duplicate
    // keys and omitted nullable fields, including fields in nested observations.
    if record.request.request_id != request_id
        || serde_json::to_vec(&record).map_err(|_| invalid())? != bytes
    {
        return Err(invalid());
    }
    Ok(record)
}

/// Validate the append-only journal and bind its final event to the current
/// projection.  A missing, truncated, reordered or non-canonical journal is
/// treated as corruption; callers must not repair it or infer that submission
/// did not happen.
pub(super) fn verify_journal(
    directory: &ProtectedDirectory,
    record: &OperationRecord,
) -> Result<(), ConfigError> {
    let events = read_journal(directory)?;
    let last = events
        .last()
        .ok_or(ConfigError("wireguard_execution_record_invalid"))?;
    if &last.record != record {
        return Err(ConfigError("wireguard_execution_changed"));
    }
    Ok(())
}

/// Append one canonical event and durably flush its file and containing
/// directory.  On Windows, directory synchronization is explicitly
/// unsupported; the returned `Unsupported` value is retained by the caller
/// and must never be converted into an execution permit.
pub(super) fn append_journal(
    directory: &ProtectedDirectory,
    record: &OperationRecord,
) -> Result<DirectorySync, ConfigError> {
    record.validate()?;
    let events = match read_journal(directory) {
        Ok(events) => events,
        Err(error) if error.0 == "wireguard_execution_record_missing" => Vec::new(),
        Err(error) => return Err(error),
    };
    validate_next_phase(events.last().map(|event| &event.record), &record.phase)?;
    let sequence = match events.last() {
        None => 1,
        Some(event) => event
            .sequence
            .checked_add(1)
            .ok_or(ConfigError("wireguard_execution_record_invalid"))?,
    };
    let previous_sha256 = events.last().map_or_else(
        || ZERO_DIGEST.to_owned(),
        |event| event.event_sha256.clone(),
    );
    let body = JournalBody {
        version: 1,
        sequence,
        previous_sha256: &previous_sha256,
        record,
    };
    let body_bytes = serde_json::to_vec(&body).map_err(unavailable)?;
    let event = JournalEvent {
        version: 1,
        sequence,
        previous_sha256,
        record: record.clone(),
        event_sha256: format!("{:x}", Sha256::digest(&body_bytes)),
    };
    let line = serde_json::to_vec(&event).map_err(unavailable)?;
    let total = journal_size(directory)?
        .checked_add(line.len() as u64 + 1)
        .ok_or(ConfigError("wireguard_execution_record_invalid"))?;
    if total > MAX_JOURNAL_BYTES {
        return Err(ConfigError("wireguard_execution_record_invalid"));
    }
    let mut file = match directory
        .open_append_file(JOURNAL_NAME)
        .map_err(unavailable)?
    {
        Some(file) => file,
        None => match directory.create_file(JOURNAL_NAME) {
            Ok(file) => file,
            Err(_) => directory
                .open_append_file(JOURNAL_NAME)
                .map_err(unavailable)?
                .ok_or(ConfigError("wireguard_execution_unavailable"))?,
        },
    };
    let identity = crate::platform::file_identity(&file).map_err(unavailable)?;
    let result = (|| {
        file.write_all(&line).map_err(unavailable)?;
        file.write_all(b"\n").map_err(unavailable)?;
        file.sync_all().map_err(unavailable)?;
        directory.verify_file(&file).map_err(unavailable)?;
        let current = directory
            .open_file(JOURNAL_NAME)
            .map_err(unavailable)?
            .ok_or(ConfigError("wireguard_execution_changed"))?;
        if crate::platform::file_identity(&current).map_err(unavailable)? != identity {
            return Err(ConfigError("wireguard_execution_changed"));
        }
        directory.sync().map_err(unavailable)
    })();
    if result.is_ok() {
        // Re-read through the protected handle so a concurrent or malicious
        // replacement cannot turn a successful append into an unverifiable
        // projection.  The request lock normally provides serialization.
        directory.verify().map_err(unavailable)?;
    }
    result
}

fn journal_size(directory: &ProtectedDirectory) -> Result<u64, ConfigError> {
    let Some(file) = directory.open_file(JOURNAL_NAME).map_err(unavailable)? else {
        return Ok(0);
    };
    let size = file.metadata().map_err(unavailable)?.len();
    if size > MAX_JOURNAL_BYTES {
        return Err(ConfigError("wireguard_execution_record_invalid"));
    }
    Ok(size)
}

fn read_journal(directory: &ProtectedDirectory) -> Result<Vec<JournalEvent>, ConfigError> {
    let Some(file) = directory.open_file(JOURNAL_NAME).map_err(unavailable)? else {
        return Err(ConfigError("wireguard_execution_record_missing"));
    };
    if file.metadata().map_err(unavailable)?.len() > MAX_JOURNAL_BYTES {
        return Err(ConfigError("wireguard_execution_record_invalid"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES || bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err(ConfigError("wireguard_execution_record_invalid"));
    }
    let mut events = Vec::new();
    let lines = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        if index + 1 == lines.len() && line.is_empty() {
            continue;
        }
        if line.is_empty() {
            return Err(ConfigError("wireguard_execution_record_invalid"));
        }
        let event: JournalEvent = serde_json::from_slice(line)
            .map_err(|_| ConfigError("wireguard_execution_record_invalid"))?;
        validate_event(&event, events.last())?;
        if serde_json::to_vec(&event).map_err(unavailable)? != *line {
            return Err(ConfigError("wireguard_execution_record_invalid"));
        }
        events.push(event);
    }
    if events.is_empty() {
        return Err(ConfigError("wireguard_execution_record_invalid"));
    }
    Ok(events)
}

fn validate_event(
    event: &JournalEvent,
    previous: Option<&JournalEvent>,
) -> Result<(), ConfigError> {
    if event.version != 1
        || event.sequence == 0
        || !super::super::execution_request::digest(&event.previous_sha256)
        || !super::super::execution_request::digest(&event.event_sha256)
    {
        return Err(ConfigError("wireguard_execution_record_invalid"));
    }
    event.record.validate()?;
    let body = JournalBody {
        version: event.version,
        sequence: event.sequence,
        previous_sha256: &event.previous_sha256,
        record: &event.record,
    };
    let bytes = serde_json::to_vec(&body).map_err(unavailable)?;
    if format!("{:x}", Sha256::digest(bytes)) != event.event_sha256 {
        return Err(ConfigError("wireguard_execution_record_invalid"));
    }
    match previous {
        None if event.sequence == 1 && event.previous_sha256 == ZERO_DIGEST => {}
        Some(previous)
            if previous
                .sequence
                .checked_add(1)
                .is_some_and(|sequence| event.sequence == sequence)
                && event.previous_sha256 == previous.event_sha256 => {}
        _ => return Err(ConfigError("wireguard_execution_record_invalid")),
    }
    if let Some(previous) = previous {
        validate_next_phase(Some(&previous.record), &event.record.phase)?;
    } else if event.record.phase != super::super::execution_request::OperationPhase::Prepared {
        return Err(ConfigError("wireguard_execution_record_invalid"));
    }
    Ok(())
}

fn validate_next_phase(
    previous: Option<&OperationRecord>,
    next: &super::super::execution_request::OperationPhase,
) -> Result<(), ConfigError> {
    use super::super::execution_request::OperationPhase;
    let valid = match previous.map(|record| record.phase) {
        None => *next == OperationPhase::Prepared,
        Some(OperationPhase::Prepared) => *next == OperationPhase::Submitted,
        Some(OperationPhase::Submitted) => {
            matches!(*next, OperationPhase::Observed | OperationPhase::Failed)
        }
        Some(OperationPhase::Observed | OperationPhase::Failed) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ConfigError("wireguard_execution_transition_invalid"))
    }
}

/// Enumerate request directories without trusting the directory names as
/// records.  Lock files and other implementation entries are ignored, while
/// a 64-character candidate that is not a lowercase digest fails closed.
/// The caller still has to open and validate each candidate through
/// [`load`]; this function only provides a bounded, deterministic index.
pub(super) fn request_ids(directory: &ProtectedDirectory) -> Result<Vec<String>, ConfigError> {
    directory.verify().map_err(unavailable)?;
    let mut ids = Vec::new();
    let entries = directory
        .dir()
        .read_dir(Path::new("."))
        .map_err(unavailable)?;
    for entry in entries {
        let entry = entry.map_err(unavailable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.len() != 64 {
            continue;
        }
        if !super::super::execution_request::digest(name) {
            return Err(ConfigError("wireguard_execution_record_invalid"));
        }
        let file_type = entry.file_type().map_err(unavailable)?;
        if !file_type.is_dir() || file_type.is_symlink() {
            return Err(ConfigError("wireguard_execution_record_invalid"));
        }
        ids.push(name.to_string());
    }
    ids.sort_unstable();
    Ok(ids)
}

pub(super) fn verify_snapshot(
    directory: &ProtectedDirectory,
    record: &OperationRecord,
) -> Result<(), ConfigError> {
    let name = format!("{}.conf", record.request.logical_name);
    let mut file = directory
        .open_file(&name)
        .map_err(unavailable)?
        .ok_or(ConfigError("wireguard_execution_changed"))?;
    if super::super::publication::snapshot_identity(&file)? != record.snapshot_identity {
        return Err(ConfigError("wireguard_execution_changed"));
    }
    let maximum = super::super::inspection::MAX_CONFIG_BYTES as usize;
    let mut bytes = Zeroizing::new(vec![0; maximum + 1]);
    let mut length = 0;
    while length < bytes.len() {
        let read = file.read(&mut bytes[length..]).map_err(unavailable)?;
        if read == 0 {
            break;
        }
        length += read;
    }
    bytes.truncate(length);
    let config =
        ExecutionConfig::from_transfer(std::mem::take(&mut *bytes), &record.request.config)?;
    drop(config);
    directory.verify_file(&file).map_err(unavailable)?;
    let current = directory
        .open_file(&name)
        .map_err(unavailable)?
        .ok_or(ConfigError("wireguard_execution_changed"))?;
    if super::super::publication::snapshot_identity(&file)? != record.snapshot_identity
        || super::super::publication::snapshot_identity(&current)? != record.snapshot_identity
    {
        return Err(ConfigError("wireguard_execution_changed"));
    }
    Ok(())
}

pub(super) fn persist(
    directory: &ProtectedDirectory,
    record: &OperationRecord,
) -> Result<DirectorySync, ConfigError> {
    record.validate()?;
    let bytes = serde_json::to_vec(record).map_err(unavailable)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(ConfigError("wireguard_execution_record_invalid"));
    }
    let mut random = [0; 32];
    rand_core::OsRng
        .try_fill_bytes(&mut random)
        .map_err(unavailable)?;
    let name = format!("record-{:x}.tmp", Sha256::digest(random));
    let mut file = directory.create_file(&name).map_err(unavailable)?;
    let result = (|| {
        #[cfg(test)]
        faults::check(faults::Stage::Write)?;
        file.write_all(&bytes).map_err(unavailable)?;
        #[cfg(test)]
        faults::check(faults::Stage::FileSync)?;
        file.sync_all().map_err(unavailable)?;
        directory.verify_file(&file).map_err(unavailable)?;
        directory.verify().map_err(unavailable)?;
        #[cfg(test)]
        faults::check(faults::Stage::Rename)?;
        directory
            .dir()
            .rename(&name, directory.dir(), "record.json")
            .map_err(unavailable)?;
        #[cfg(test)]
        faults::check(faults::Stage::DirectorySync)?;
        directory.sync().map_err(unavailable)
    })();
    // Only this call's staging name is removable. Never delete a published record
    // or the secret snapshot, including after a failed directory synchronization.
    let _ = directory.dir().remove_file(&name);
    result
}

#[cfg(test)]
#[path = "../../../tests/unit/src/wireguard_execution_faults.rs"]
pub(super) mod faults;
