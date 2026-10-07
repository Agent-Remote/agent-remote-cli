//! Exact private runtime-state input; no package discovery, Git exclusions or LFS interpretation.

use std::fs::File;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use anyhow::{bail, Result};

use super::manifest::Manifest;
use super::snapshot::{PackageLimits, PackageSnapshot};
use super::snapshot_capture::CapturePolicy;
use super::source_fs;

/// Cooperative cancellation for blocking disk work. A cancelled capture never returns partial data.
#[derive(Clone, Debug, Default)]
pub struct CaptureCancellation(Arc<AtomicBool>);

impl CaptureCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub(super) fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Relaxed) {
            bail!("SKILL_INTERRUPTED: local state capture cancelled");
        }
        Ok(())
    }
}

/// State defaults differ from installation packages; the Server enforces its configured quotas.
#[derive(Clone, Copy, Debug)]
pub struct StateLimits {
    pub total_bytes: u64,
    pub entries: usize,
}

impl StateLimits {
    pub const ITEM: Self = Self {
        total_bytes: 1024 * 1024 * 1024,
        entries: 100_000,
    };
    pub const DIRECTORY: Self = Self {
        total_bytes: 10 * 1024 * 1024 * 1024,
        entries: 100_000,
    };

    fn capture_limits(self) -> Result<PackageLimits> {
        if self.total_bytes == 0
            || self.total_bytes > i64::MAX as u64
            || !(1..=100_000).contains(&self.entries)
        {
            bail!("invalid state capture limits");
        }
        Ok(PackageLimits {
            file_bytes: self.total_bytes,
            total_bytes: self.total_bytes,
            entries: self.entries,
        })
    }
}

/// Staged content for one explicit resolution scope, independent of the live source afterwards.
#[derive(Debug)]
pub struct StateSnapshot(PackageSnapshot);

impl StateSnapshot {
    /// Capture all names, ordinary links, modes and empty directories. Call on a blocking worker.
    ///
    /// Absolute links cannot encode a runtime dependency's identity in a materialized directory.
    /// They fail explicitly; saved-side selection preserves existing runtime-link metadata.
    /// Export bundles are ordinary files here, never implicitly unpacked or reinterpreted.
    pub fn directory(
        path: &Path,
        limits: StateLimits,
        cancellation: &CaptureCancellation,
    ) -> Result<Self> {
        cancellation.check()?;
        let limits = limits.capture_limits()?;
        let root = source_fs::open_root(path)?;
        Ok(Self(PackageSnapshot::capture_with_policy(
            &root,
            limits,
            CapturePolicy::State(cancellation.clone()),
        )?))
    }

    /// An ordinary file becomes exactly one manifest entry named `content`; no siblings are read.
    pub fn file(
        path: &Path,
        limits: StateLimits,
        cancellation: &CaptureCancellation,
    ) -> Result<Self> {
        cancellation.check()?;
        Ok(Self(PackageSnapshot::capture_state_file(
            path,
            limits.capture_limits()?,
            CapturePolicy::State(cancellation.clone()),
        )?))
    }

    pub fn manifest(&self) -> &Manifest {
        self.0.manifest()
    }
    pub fn tree_digest(&self) -> &str {
        self.0.tree_digest()
    }
    pub fn total_bytes(&self) -> u64 {
        self.0.total_bytes()
    }

    /// Only staged immutable objects in this snapshot can be opened, never arbitrary source paths.
    pub fn open_object(&self, digest: &str) -> Result<File> {
        self.0.open_object(digest)
    }
}
#[cfg(test)]
#[path = "../../tests/unit/src/skills/state_snapshot_tests.rs"]
mod tests;
