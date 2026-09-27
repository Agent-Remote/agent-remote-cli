//! Shared bounded file copying and exact metadata capture; callers choose package or state rules.

use anyhow::{bail, Context, Result};
use cap_std::fs::{Dir, Metadata};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use tempfile::{NamedTempFile, TempDir};

use super::manifest::{validate_path, ContentKind, Entry, EntryKind};
use super::snapshot::PackageLimits;
use super::source_fs::{self, SourceEntries};
use super::state_snapshot::CaptureCancellation;

#[derive(Clone, Default)]
pub(super) enum CapturePolicy {
    #[default]
    Package,
    State(CaptureCancellation),
}

impl CapturePolicy {
    pub(super) fn entries(&self) -> SourceEntries {
        match self {
            Self::Package => SourceEntries::Package,
            Self::State(_) => SourceEntries::All,
        }
    }

    pub(super) fn check_cancelled(&self) -> Result<()> {
        if let Self::State(cancellation) = self {
            cancellation.check()?;
        }
        Ok(())
    }
}

pub(super) struct Builder<'a> {
    pub(super) policy: CapturePolicy,
    pub(super) staging: &'a TempDir,
    pub(super) limits: PackageLimits,
    pub(super) entries: Vec<Entry>,
    pub(super) baselines: BTreeMap<String, Metadata>,
    pub(super) objects: BTreeSet<String>,
    pub(super) total_bytes: u64,
}

impl Builder<'_> {
    pub(super) fn capture_directory(
        &mut self,
        dir: &Dir,
        prefix: &str,
        depth: usize,
    ) -> Result<()> {
        self.policy.check_cancelled()?;
        if depth > 128 {
            bail!("source exceeds the supported directory depth of 128");
        }
        let baseline = dir.dir_metadata()?;
        self.baselines.insert(prefix.to_owned(), baseline.clone());
        for name in source_fs::selected_names(
            dir,
            self.limits.entries - self.entries.len(),
            self.policy.entries(),
        )? {
            self.policy.check_cancelled()?;
            if self.entries.len() >= self.limits.entries {
                bail!("QUOTA_EXCEEDED: source entry limit exceeded");
            }
            let path = source_fs::join(prefix, &name);
            validate_path(&path)?;
            let before = dir.symlink_metadata(&name)?;
            let mut entry = Entry {
                path: path.clone(),
                kind: EntryKind::Directory,
                mode: source_fs::portable_mode(&before),
                size: 0,
                sha256: String::new(),
                target: String::new(),
                content_kind: ContentKind::Empty,
                dependency: String::new(),
            };
            if before.is_symlink() {
                entry.kind = EntryKind::Symlink;
                entry.mode = 0o777;
                entry.target = dir
                    .read_link_contents(&name)?
                    .to_str()
                    .context("link target must be UTF-8")?
                    .to_owned();
                if matches!(self.policy, CapturePolicy::State(_)) && entry.target.starts_with('/') {
                    bail!("RUNTIME_LINK_METADATA_REQUIRED: a local absolute link has no runtime dependency identity; choose a saved side or supply a self-contained relative tree");
                }
                entry.validate()?;
            } else if before.is_file() {
                self.capture_file(dir, &name, &before, &mut entry)?;
            } else if !before.is_dir() {
                bail!("INCOMPLETE_SOURCE: special filesystem entry at {path}");
            }
            self.entries.push(entry);
            if before.is_dir() {
                self.capture_directory(
                    &source_fs::open_directory(dir, &name, &before)?,
                    &path,
                    depth + 1,
                )?;
            }
            source_fs::require_unchanged(&before, &dir.symlink_metadata(&name)?)?;
            self.baselines.insert(path, before);
        }
        source_fs::require_unchanged(&baseline, &dir.dir_metadata()?)
    }

    pub(super) fn capture_file(
        &mut self,
        dir: &Dir,
        name: &str,
        before: &Metadata,
        entry: &mut Entry,
    ) -> Result<()> {
        if before.len() > self.limits.file_bytes
            || before.len() > self.limits.total_bytes - self.total_bytes
        {
            bail!("QUOTA_EXCEEDED: source byte limit exceeded");
        }
        let mut source = source_fs::open_file(dir, name, before)?;
        let mut output = NamedTempFile::new_in(self.staging.path())?;
        let mut hash = Sha256::new();
        let mut classifier = TextClassifier::default();
        let mut count = 0u64;
        let mut prefix = Vec::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            self.policy.check_cancelled()?;
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            count = count
                .checked_add(read as u64)
                .context("file size overflow")?;
            if count > self.limits.file_bytes || count > self.limits.total_bytes - self.total_bytes
            {
                bail!("QUOTA_EXCEEDED: source grew beyond the byte limit");
            }
            let bytes = &buffer[..read];
            prefix.extend_from_slice(&bytes[..bytes.len().min(128 - prefix.len())]);
            hash.update(bytes);
            classifier.update(bytes);
            output.write_all(bytes)?;
        }
        source_fs::require_unchanged(before, &source.metadata()?)?;
        if count != before.len() {
            bail!("SOURCE_UNSTABLE: source length changed while packing");
        }
        if matches!(self.policy, CapturePolicy::Package)
            && (prefix.starts_with(b"version https://git-lfs.github.com/spec/v1\n")
                || prefix.starts_with(b"version https://git-lfs.github.com/spec/v1\r\n"))
        {
            bail!(
                "INCOMPLETE_SOURCE: unresolved Git LFS pointer at {}",
                entry.path
            );
        }
        entry.kind = EntryKind::File;
        entry.size = count;
        entry.sha256 = format!("{:x}", hash.finalize());
        entry.content_kind = classifier.finish();
        if self.objects.insert(entry.sha256.clone()) {
            output.as_file().sync_all()?;
            output.persist_noclobber(self.staging.path().join(&entry.sha256))?;
        }
        self.total_bytes += count;
        Ok(())
    }
}

#[derive(Default)]
struct TextClassifier {
    binary: bool,
    tail: Vec<u8>,
}

impl TextClassifier {
    fn update(&mut self, chunk: &[u8]) {
        if self.binary {
            return;
        }
        if chunk.contains(&0) {
            self.binary = true;
            return;
        }
        let combined;
        let bytes = if self.tail.is_empty() {
            chunk
        } else {
            combined = [self.tail.as_slice(), chunk].concat();
            &combined
        };
        match std::str::from_utf8(bytes) {
            Ok(_) => self.tail.clear(),
            Err(error) if error.error_len().is_none() => {
                self.tail = bytes[error.valid_up_to()..].to_vec()
            }
            Err(_) => self.binary = true,
        }
    }

    fn finish(self) -> ContentKind {
        if self.binary || !self.tail.is_empty() {
            ContentKind::Binary
        } else {
            ContentKind::Text
        }
    }
}
