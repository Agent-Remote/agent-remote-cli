//! Read the fixed wg-quick runtime mapping without following user-controlled links.

use std::ffi::CString;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use cap_std::fs::{Dir, FileTypeExt, Metadata, MetadataExt};

use super::{fingerprint, TargetIdentity, TargetObservation, TargetReason};
use crate::wireguard::publication;

pub(super) fn observe(name: &str, cancel: &AtomicBool) -> TargetObservation {
    if super::canceled(cancel).is_err() {
        return TargetObservation::unknown(name, TargetReason::NativeQueryFailed);
    }
    match inspect_at(Path::new("/var/run/wireguard"), name, interface_index) {
        Ok(identity) => TargetObservation::present(name, identity),
        Err(reason) => TargetObservation::unknown(name, reason),
    }
}

/// Return the kernel-owned scope binding used by the privileged broker.  It
/// includes the validated utun mapping identity when one exists, while an
/// absent target remains bound to the logical tunnel name and its explicit
/// absent observation.  No user path or process environment participates.
pub(super) fn scope_digest(name: &str) -> Result<String, TargetReason> {
    let canceled = AtomicBool::new(false);
    let observation = observe(name, &canceled);
    let bytes = serde_json::to_vec(&observation).map_err(|_| TargetReason::NativeQueryFailed)?;
    Ok(fingerprint(b"agent-remote:wireguard:scope:v1\0", &bytes))
}

fn interface_index(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

fn inspect_at(
    runtime: &Path,
    name: &str,
    index: impl FnOnce(&str) -> Option<u32>,
) -> Result<TargetIdentity, TargetReason> {
    // Missing mappings do not prove the absence of a previous or orphaned utun.
    match std::fs::symlink_metadata(runtime) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(TargetReason::MappingMissing)
        }
        Err(_) => return Err(TargetReason::NativeQueryFailed),
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(TargetReason::MappingUnsafe)
        }
        Ok(_) => {}
    }
    let dir = publication::open_directory(runtime).map_err(|_| TargetReason::MappingUnsafe)?;
    let directory = dir
        .dir_metadata()
        .map_err(|_| TargetReason::NativeQueryFailed)?;
    if !trusted(&directory) {
        return Err(TargetReason::MappingUnsafe);
    }
    let leaf = format!("{name}.name");
    let before = metadata(&dir, &leaf)?;
    if !before.is_file() || before.nlink() != 1 || before.len() > 64 || !trusted(&before) {
        return Err(TargetReason::MappingUnsafe);
    }
    let file = publication::open_regular(&dir, &leaf)
        .map_err(|_| TargetReason::MappingUnsafe)?
        .ok_or(TargetReason::MappingStale)?;
    let opened = file
        .metadata()
        .map_err(|_| TargetReason::NativeQueryFailed)?;
    use std::os::unix::fs::MetadataExt as StdMetadataExt;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.len() > 64
        || opened.mode() & 0o022 != 0
    {
        return Err(TargetReason::MappingStale);
    }
    let mut bytes = Vec::new();
    file.take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| TargetReason::NativeQueryFailed)?;
    if bytes.len() > 64 {
        return Err(TargetReason::MappingUnsafe);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| TargetReason::MappingUnsafe)?;
    let actual = text.strip_suffix('\n').unwrap_or(text);
    if !utun(actual) {
        return Err(TargetReason::MappingUnsafe);
    }
    let socket_name = format!("{actual}.sock");
    let socket = metadata(&dir, &socket_name).map_err(|reason| {
        if reason == TargetReason::MappingMissing {
            TargetReason::MappingStale
        } else {
            reason
        }
    })?;
    if !socket.file_type().is_socket() || !trusted(&socket) {
        return Err(TargetReason::MappingUnsafe);
    }
    let index = index(actual).ok_or(TargetReason::MappingStale)?;
    if index == 0 {
        return Err(TargetReason::MappingStale);
    }
    // Metadata and public key are independent facts. No mtime proximity heuristic
    // is treated as ownership or as proof of a particular tunnel generation.
    let mapping_stamp = stamp(&before);
    let socket_stamp = stamp(&socket);
    if stamp(&metadata(&dir, &leaf)?) != mapping_stamp
        || stamp(&metadata(&dir, &socket_name)?) != socket_stamp
    {
        return Err(TargetReason::TargetChanged);
    }
    let reopened = publication::open_directory(runtime).map_err(|_| TargetReason::TargetChanged)?;
    if stamp(
        &reopened
            .dir_metadata()
            .map_err(|_| TargetReason::NativeQueryFailed)?,
    ) != stamp(&directory)
    {
        return Err(TargetReason::TargetChanged);
    }
    let anchor = stamp(&directory);
    let mapping = fingerprint(
        b"agent-remote:wireguard:macos-mapping:v1\0",
        format!("{anchor}\0{mapping_stamp}\0{actual}").as_bytes(),
    );
    let socket = fingerprint(
        b"agent-remote:wireguard:macos-socket:v1\0",
        format!("{anchor}\0{socket_stamp}").as_bytes(),
    );
    Ok(TargetIdentity::MacosInterface {
        name: actual.into(),
        index,
        mapping_identity: mapping,
        socket_identity: socket,
        public_key: None,
    })
}

fn metadata(dir: &Dir, name: &str) -> Result<Metadata, TargetReason> {
    dir.symlink_metadata(name).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            TargetReason::MappingMissing
        } else {
            TargetReason::NativeQueryFailed
        }
    })
}
fn trusted(metadata: &Metadata) -> bool {
    (metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() })
        && metadata.mode() & 0o022 == 0
        && !metadata.file_type().is_symlink()
}
fn stamp(metadata: &Metadata) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode()
    )
}
fn utun(name: &str) -> bool {
    let Some(number) = name.strip_prefix("utun") else {
        return false;
    };
    number
        .parse::<u32>()
        .is_ok_and(|number| format!("utun{number}") == name)
}

#[cfg(test)]
#[path = "../../../tests/unit/src/wireguard_target_macos.rs"]
mod tests;
