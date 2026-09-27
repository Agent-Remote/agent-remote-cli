//! Stable local installation packages; source bytes never remain live upload inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use cap_std::fs::Dir;
use tempfile::{NamedTempFile, TempDir};

use super::manifest::{EntryKind, Manifest};
use super::snapshot_capture::{Builder, CapturePolicy};
use super::source_fs;

/// Expanded package limits. The Server remains authoritative and may configure other values.
#[derive(Clone, Copy, Debug)]
pub struct PackageLimits {
    pub file_bytes: u64,
    pub total_bytes: u64,
    pub entries: usize,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            file_bytes: 10 * 1024 * 1024,
            total_bytes: 50 * 1024 * 1024,
            entries: 5_000,
        }
    }
}

/// Private complete package, removed on drop; only verified digest-addressed files are exposed.
#[derive(Debug)]
pub struct PackageSnapshot {
    staging: TempDir,
    manifest: Manifest,
    tree_digest: String,
    objects: BTreeSet<String>,
    total_bytes: u64,
}

impl PackageSnapshot {
    /// Copy before planning an upload. Call on a blocking worker from asynchronous commands.
    ///
    /// The source root may be a symlink; links inside it are recorded without being followed.
    /// Metadata is checked before/after each read and across a final complete tree walk.
    pub fn capture(path: &Path, limits: PackageLimits) -> Result<Self> {
        Self::capture_open(&source_fs::open_root(path)?, limits)
    }

    pub(super) fn capture_open(root: &Dir, limits: PackageLimits) -> Result<Self> {
        Self::capture_with_policy(root, limits, CapturePolicy::Package)
    }

    pub(super) fn capture_with_policy(
        root: &Dir,
        limits: PackageLimits,
        policy: CapturePolicy,
    ) -> Result<Self> {
        if limits.file_bytes == 0
            || limits.total_bytes == 0
            || !(1..=100_000).contains(&limits.entries)
        {
            bail!("invalid skill package limits");
        }
        let mut staging_builder = tempfile::Builder::new();
        staging_builder.prefix("agent-remote-skill-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            staging_builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let staging = staging_builder.tempdir()?;
        let mut builder = Builder {
            policy,
            staging: &staging,
            limits,
            entries: Vec::new(),
            baselines: BTreeMap::new(),
            objects: BTreeSet::new(),
            total_bytes: 0,
        };
        builder.capture_directory(root, "", 0)?;
        if source_fs::verify_selected_tree(
            root,
            "",
            &builder.baselines,
            builder.policy.entries(),
            &|| builder.policy.check_cancelled(),
        )? != builder.baselines.len()
        {
            bail!("SOURCE_UNSTABLE: source lost an entry while packing");
        }
        builder.entries.sort_by(|a, b| a.path.cmp(&b.path));
        let manifest = Manifest {
            version: 1,
            entries: builder.entries,
        };
        let tree_digest = manifest
            .digest()
            .context("source contains a nonportable tree or link")?;
        let total_bytes = builder.total_bytes;
        let objects = builder.objects;
        Ok(Self {
            staging,
            manifest,
            tree_digest,
            objects,
            total_bytes,
        })
    }

    pub(super) fn capture_state_file(
        path: &Path,
        limits: PackageLimits,
        policy: CapturePolicy,
    ) -> Result<Self> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("state file needs a UTF-8 filename")?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let root = source_fs::open_root(parent)?;
        let before = root.symlink_metadata(name)?;
        if !before.is_file() || before.is_symlink() {
            bail!("state --file input must be an ordinary file, not a directory or link");
        }
        let staging = tempfile::Builder::new()
            .prefix("agent-remote-state-")
            .tempdir()?;
        let mut builder = Builder {
            policy,
            staging: &staging,
            limits,
            entries: Vec::new(),
            baselines: BTreeMap::new(),
            objects: BTreeSet::new(),
            total_bytes: 0,
        };
        let mut entry = super::manifest::Entry {
            path: "content".to_owned(),
            kind: EntryKind::File,
            mode: source_fs::portable_mode(&before),
            size: 0,
            sha256: String::new(),
            target: String::new(),
            content_kind: super::manifest::ContentKind::Empty,
            dependency: String::new(),
        };
        builder.capture_file(&root, name, &before, &mut entry)?;
        source_fs::require_unchanged(&before, &root.symlink_metadata(name)?)?;
        builder.policy.check_cancelled()?;
        let manifest = Manifest {
            version: 1,
            entries: vec![entry],
        };
        let tree_digest = manifest.digest()?;
        let total_bytes = builder.total_bytes;
        let objects = builder.objects;
        Ok(Self {
            staging,
            manifest,
            tree_digest,
            objects,
            total_bytes,
        })
    }

    /// Construct a portable raw-object package without materializing host filesystem links/modes.
    pub(super) fn from_objects(
        manifest: Manifest,
        objects: BTreeMap<String, Vec<u8>>,
        limits: PackageLimits,
    ) -> Result<Self> {
        let tree_digest = manifest.digest()?;
        if manifest.entries.len() > limits.entries {
            bail!("QUOTA_EXCEEDED: installation package entry limit exceeded");
        }
        let staging = tempfile::Builder::new()
            .prefix("agent-remote-skill-")
            .tempdir()?;
        let mut retained = BTreeSet::new();
        let mut total_bytes = 0u64;
        for entry in &manifest.entries {
            if entry.kind != EntryKind::File {
                continue;
            }
            total_bytes = total_bytes
                .checked_add(entry.size)
                .context("package size overflow")?;
            if entry.size > limits.file_bytes || total_bytes > limits.total_bytes {
                bail!("QUOTA_EXCEEDED: installation package byte limit exceeded");
            }
            let bytes = objects
                .get(&entry.sha256)
                .context("INCOMPLETE_SOURCE: Git blob missing")?;
            entry.verify_content(bytes)?;
            if bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n")
                || bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\r\n")
            {
                bail!(
                    "INCOMPLETE_SOURCE: unresolved Git LFS pointer at {}",
                    entry.path
                );
            }
            if retained.insert(entry.sha256.clone()) {
                let mut output = NamedTempFile::new_in(staging.path())?;
                output.write_all(bytes)?;
                output.as_file().sync_all()?;
                output.persist_noclobber(staging.path().join(&entry.sha256))?;
            }
        }
        Ok(Self {
            staging,
            manifest,
            tree_digest,
            objects: retained,
            total_bytes,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn tree_digest(&self) -> &str {
        &self.tree_digest
    }
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Open a staged object only if it belongs to this complete snapshot.
    pub fn open_object(&self, digest: &str) -> Result<File> {
        if !self.objects.contains(digest) {
            bail!("file digest is not part of this skill snapshot");
        }
        File::open(self.staging.path().join(digest)).context("cannot read staged skill object")
    }
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod tests;
