//! Bounded recovery staging; source paths are metadata and never local extraction paths.

use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    export::{private_directory, private_file, sync_directory, write_json, ExportBundle},
    manifest::{validate_path, ContentKind, Entry, EntryKind},
};

const MAX_ENTRY_BYTES: usize = 64 << 10;

/// Ordered counters and digest for the separate recovery format, not a manifest v1 tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySummary {
    pub entries: u64,
    pub file_bytes: u64,
    pub file_objects: u64,
    pub digest: String,
}

/// A private disk index bounds memory while checking duplicates, parents and link topology.
pub struct RecoveryBundle {
    bundle: ExportBundle,
    entries: PathBuf,
    journal: File,
    pending: Option<Entry>,
    digest: Sha256,
    count: u64,
    bytes: u64,
    files: u64,
}

impl RecoveryBundle {
    pub fn prepare(output: &Path, metadata: &impl Serialize) -> Result<Self> {
        let bundle = ExportBundle::prepare_empty(output, metadata)?;
        let entries = bundle.staging_path().join("bundle/entries");
        private_directory(&entries)?;
        let journal = private_file(&bundle.staging_path().join("bundle/recovery.jsonl"))?;
        let mut digest = Sha256::new();
        digest.update(b"agent-remote-skill-recovery-tree-v1\0");
        Ok(Self {
            bundle,
            entries,
            journal,
            pending: None,
            digest,
            count: 0,
            bytes: 0,
            files: 0,
        })
    }

    /// Validate metadata and create only a fixed private pending object for a file.
    pub fn begin(&mut self, entry: Entry) -> Result<Option<File>> {
        ensure!(self.pending.is_none(), "recovery entry is still pending");
        validate_start(&entry)?;
        ensure!(
            entry.path.split('/').count() <= 129,
            "recovery path exceeds depth bound"
        );
        let mut parent = String::new();
        let parts: Vec<_> = entry.path.split('/').collect();
        for component in &parts[..parts.len() - 1] {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            ensure!(
                self.lookup(&parent)?.kind == EntryKind::Directory,
                "recovery parent is not a directory"
            );
        }
        // create_new makes duplicate paths fail even on case-insensitive destination filesystems.
        let name = self.index_path(&entry.path);
        let mut index = private_file(&name)?;
        index.write_all(b"pending\n")?;
        let file = if entry.kind == EntryKind::File {
            Some(private_file(&self.pending_path())?)
        } else {
            None
        };
        self.pending = Some(entry);
        Ok(file)
    }

    /// Complete one verified entry. File callers must verify bytes and fsync/close the pending file.
    pub fn complete(&mut self, entry: Entry) -> Result<()> {
        entry.validate()?;
        let original = self
            .pending
            .as_ref()
            .context("recovery entry was not started")?;
        let mut start = entry.clone();
        if entry.kind == EntryKind::File {
            start.sha256.clear();
            start.content_kind = ContentKind::Empty;
        }
        ensure!(
            &start == original,
            "recovery entry changed while transferring"
        );
        self.count = self
            .count
            .checked_add(1)
            .context("recovery count overflow")?;
        self.bytes = self
            .bytes
            .checked_add(entry.size)
            .context("recovery size overflow")?;
        ensure!(
            self.count <= i64::MAX as u64 && self.bytes <= i64::MAX as u64,
            "recovery counters exceed signed bounds"
        );
        if entry.kind == EntryKind::File {
            self.files += 1;
            let object = self
                .bundle
                .staging_path()
                .join("bundle/objects")
                .join(&entry.sha256);
            if object.try_exists()? {
                let info = fs::symlink_metadata(&object)?;
                ensure!(
                    info.is_file() && info.len() == entry.size,
                    "duplicate digest has inconsistent size"
                );
                fs::remove_file(self.pending_path())?;
            } else {
                fs::rename(self.pending_path(), object)?;
            }
        }
        let encoded = serde_json::to_vec(&entry)?;
        ensure!(
            encoded.len() < MAX_ENTRY_BYTES,
            "recovery metadata is too large"
        );
        let index = self.index_path(&entry.path);
        // The private marker owns this exact path; final metadata replaces only our pending marker.
        fs::remove_file(&index)?;
        write_json(&index, &entry)?;
        self.journal.write_all(&encoded)?;
        self.journal.write_all(b"\n")?;
        update_digest(&mut self.digest, &entry);
        self.pending = None;
        Ok(())
    }

    pub fn summary(&self) -> RecoverySummary {
        RecoverySummary {
            entries: self.count,
            file_bytes: self.bytes,
            file_objects: self.files,
            digest: format!("{:x}", self.digest.clone().finalize()),
        }
    }

    /// Validate all links using the disk index and return still-private staging for SSH exit checks.
    pub fn finish(self, expected: &RecoverySummary) -> Result<ExportBundle> {
        ensure!(
            self.pending.is_none() && &self.summary() == expected,
            "recovery summary does not match complete content"
        );
        self.journal.sync_all()?;
        let mut reader = BufReader::new(File::open(
            self.bundle.staging_path().join("bundle/recovery.jsonl"),
        )?);
        let mut count = 0u64;
        let mut observed = Sha256::new();
        observed.update(b"agent-remote-skill-recovery-tree-v1\0");
        loop {
            let mut line = Vec::new();
            let length = reader
                .by_ref()
                .take((MAX_ENTRY_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)?;
            if length == 0 {
                break;
            }
            ensure!(
                length <= MAX_ENTRY_BYTES && line.last() == Some(&b'\n'),
                "invalid recovery journal frame"
            );
            let entry: Entry = serde_json::from_slice(&line)?;
            update_digest(&mut observed, &entry);
            ensure!(self.lookup(&entry.path)? == entry, "recovery index changed");
            if entry.kind == EntryKind::Symlink {
                self.validate_link(&entry)?;
            }
            count += 1;
        }
        ensure!(count == self.count, "recovery journal count changed");
        ensure!(
            format!("{:x}", observed.finalize()) == expected.digest,
            "recovery journal content changed"
        );
        sync_directory(&self.entries)?;
        Ok(self.bundle)
    }

    fn index_path(&self, path: &str) -> PathBuf {
        self.entries
            .join(format!("{:x}", Sha256::digest(path.as_bytes())))
    }
    fn pending_path(&self) -> PathBuf {
        self.bundle.staging_path().join("bundle/object.pending")
    }

    fn lookup(&self, path: &str) -> Result<Entry> {
        validate_path(path)?;
        let mut bytes = Vec::new();
        File::open(self.index_path(path))?
            .take((MAX_ENTRY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_ENTRY_BYTES,
            "recovery index entry is oversized"
        );
        let entry: Entry = serde_json::from_slice(&bytes)?;
        entry.validate()?;
        ensure!(entry.path == path, "recovery index identity changed");
        Ok(entry)
    }

    fn validate_link(&self, entry: &Entry) -> Result<()> {
        use std::collections::VecDeque;
        let mut resolved: Vec<String> = entry.path.split('/').map(str::to_owned).collect();
        resolved.pop();
        let mut pending: VecDeque<String> = entry.target.split('/').map(str::to_owned).collect();
        let mut hops = 0;
        while let Some(part) = pending.pop_front() {
            match part.as_str() {
                "" | "." => continue,
                ".." => {
                    resolved.pop().context("recovery link escapes tree")?;
                    continue;
                }
                _ => {}
            }
            let path = resolved
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(part.as_str()))
                .collect::<Vec<_>>()
                .join("/");
            let target = self.lookup(&path)?;
            if target.kind == EntryKind::Symlink {
                hops += 1;
                ensure!(hops <= 40, "recovery link exceeds cycle bound");
                pending = target
                    .target
                    .split('/')
                    .map(str::to_owned)
                    .chain(pending)
                    .collect();
                continue;
            }
            ensure!(
                pending.is_empty() || target.kind == EntryKind::Directory,
                "recovery link traverses a non-directory"
            );
            resolved.push(part);
        }
        ensure!(
            !resolved.is_empty() && !entry.path.starts_with(&(resolved.join("/") + "/")),
            "recovery link targets root or ancestor"
        );
        Ok(())
    }
}

/// Provisional files declare their extent, with content claims deferred to the verified trailer.
pub fn validate_start(entry: &Entry) -> Result<()> {
    let mut complete = entry.clone();
    if entry.kind == EntryKind::File {
        ensure!(
            entry.sha256.is_empty() && entry.content_kind == ContentKind::Empty,
            "recovery start claims verified content"
        );
        complete.sha256 = "0".repeat(64);
        complete.content_kind = ContentKind::Binary;
    }
    complete.validate()
}

fn update_digest(digest: &mut Sha256, entry: &Entry) {
    let mode = entry.mode.to_string();
    let size = entry.size.to_string();
    for field in [
        &entry.path,
        entry.kind.wire_name(),
        &mode,
        &size,
        &entry.sha256,
        &entry.target,
        entry.content_kind.wire_name(),
        &entry.dependency,
    ] {
        digest.update(field.as_bytes());
        digest.update(b"\0");
    }
}

#[cfg(test)]
#[path = "recovery_export_tests.rs"]
mod tests;
