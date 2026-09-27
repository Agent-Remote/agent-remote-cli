//! Read-only source discovery and explicit selection before atomic multi-skill installation.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use cap_std::fs::Dir;
use serde::Serialize;

use super::manifest::{validate_path, EntryKind};
pub use super::metadata::SkillMetadata;
use super::metadata::{self, DOCUMENT_PREFIX_BYTES};
use super::snapshot::{PackageLimits, PackageSnapshot};
use super::source_fs;

const DISCOVERY_ENTRIES: usize = 100_000;
pub(super) const EXCLUDED_DIRECTORIES: &[&str] = &[
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
];

/// A candidate path is relative to the opened source root, never an uploadable host path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SkillCandidate {
    pub path: String,
    pub metadata: SkillMetadata,
}

/// An invalid SKILL.md stops descent just as a valid one does; assets are not nested skills.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiscoveryIssue {
    pub path: String,
    pub message: String,
}

/// Explicit noninteractive selection. Interactive callers must resolve choices to names first.
#[derive(Clone, Debug)]
pub enum Selection {
    Automatic,
    All,
    Names(Vec<String>),
}

/// Source handle and its display-only discovery results. Capturing revalidates selected metadata.
pub struct SourceCatalog {
    root: Dir,
    root_name: String,
    candidates: Vec<SkillCandidate>,
    issues: Vec<DiscoveryIssue>,
}

impl SourceCatalog {
    /// Resolve the user's root alias once, then keep every descendant operation capability-bound.
    pub fn discover(path: &Path) -> Result<Self> {
        let canonical = path.canonicalize().context("cannot resolve skill source")?;
        let root_name = canonical
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .to_owned();
        Self::discover_open(source_fs::open_root(&canonical)?, root_name)
    }

    /// Explicit subdirectories stay inside the source capability and cannot traverse directory links.
    pub fn discover_subpath(path: &Path, subpath: &str) -> Result<Self> {
        validate_path(subpath)?;
        let canonical = path.canonicalize().context("cannot resolve skill source")?;
        let mut root = source_fs::open_root(&canonical)?;
        for part in subpath.split('/') {
            let before = root.symlink_metadata(part)?;
            root = source_fs::open_directory(&root, part, &before)?;
        }
        Self::discover_open(root, subpath.rsplit('/').next().unwrap_or("").to_owned())
    }

    fn discover_open(root: Dir, root_name: String) -> Result<Self> {
        let mut catalog = Self {
            root,
            root_name,
            candidates: Vec::new(),
            issues: Vec::new(),
        };
        let mut remaining = DISCOVERY_ENTRIES;
        catalog.walk(&catalog.root.try_clone()?, "", 0, &mut remaining)?;
        catalog.candidates.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(catalog)
    }

    pub fn candidates(&self) -> &[SkillCandidate] {
        &self.candidates
    }
    pub fn issues(&self) -> &[DiscoveryIssue] {
        &self.issues
    }

    /// Select all requested names before any packaging/upload; duplicate names need --path.
    pub fn select(&self, selection: &Selection) -> Result<Vec<SkillCandidate>> {
        select_candidates(&self.candidates, selection)
    }

    /// Package from the original opened root; reject name changes before building an API request.
    pub fn capture(
        &self,
        candidate: &SkillCandidate,
        limits: PackageLimits,
    ) -> Result<PackageSnapshot> {
        if !self.candidates.contains(candidate) {
            bail!("candidate does not belong to this source discovery");
        }
        let mut dir = self.root.try_clone()?;
        if !candidate.path.is_empty() {
            validate_path(&candidate.path)?;
            for part in candidate.path.split('/') {
                let metadata = dir.symlink_metadata(part)?;
                dir = source_fs::open_directory(&dir, part, &metadata)?;
            }
        }
        let snapshot = PackageSnapshot::capture_open(&dir, limits)?;
        // Resolve against the complete, validated manifest, never the source filesystem.
        let entry = snapshot.manifest().resolve("SKILL.md")?;
        if entry.kind != EntryKind::File || entry.content_kind != super::manifest::ContentKind::Text
        {
            bail!("INVALID_SKILL_FORMAT: SKILL.md must be text");
        }
        let mut bytes = Vec::new();
        snapshot
            .open_object(&entry.sha256)?
            .take(DOCUMENT_PREFIX_BYTES)
            .read_to_end(&mut bytes)?;
        let details = metadata::parse(&bytes, &candidate.metadata.name)?;
        if details.name != candidate.metadata.name {
            bail!("SOURCE_LAYOUT_CHANGED: selected skill changed its declared name");
        }
        Ok(snapshot)
    }

    fn walk(&mut self, dir: &Dir, prefix: &str, depth: usize, remaining: &mut usize) -> Result<()> {
        if depth > 128 {
            bail!("source discovery exceeds directory depth 128");
        }
        match dir.symlink_metadata("SKILL.md") {
            Ok(_) => {
                let fallback = prefix
                    .rsplit('/')
                    .next()
                    .filter(|v| !v.is_empty())
                    .unwrap_or(&self.root_name);
                match read_metadata(dir, fallback) {
                    Ok(metadata) => self.candidates.push(SkillCandidate {
                        path: prefix.to_owned(),
                        metadata,
                    }),
                    Err(error) => self.issues.push(DiscoveryIssue {
                        path: prefix.to_owned(),
                        message: error.to_string(),
                    }),
                }
                return Ok(());
            }
            Err(error) if source_fs::is_missing(&error) => {}
            Err(error) => return Err(error.into()),
        }
        let before = dir.dir_metadata()?;
        let names = source_fs::names(dir, *remaining)?;
        *remaining -= names.len();
        for name in names {
            if EXCLUDED_DIRECTORIES.contains(&name.as_str()) {
                continue;
            }
            let metadata = dir.symlink_metadata(&name)?;
            if metadata.is_dir() {
                let path = source_fs::join(prefix, &name);
                validate_path(&path)?;
                self.walk(
                    &source_fs::open_directory(dir, &name, &metadata)?,
                    &path,
                    depth + 1,
                    remaining,
                )?;
            }
        }
        source_fs::require_unchanged(&before, &dir.dir_metadata()?)
    }
}

fn read_metadata(dir: &Dir, fallback: &str) -> Result<SkillMetadata> {
    let path = dir
        .canonicalize("SKILL.md")
        .context("SKILL.md is missing or links outside its skill directory")?;
    let path = path
        .to_str()
        .context("SKILL.md target must be UTF-8")?
        .replace('\\', "/");
    validate_path(&path)?;
    let mut parent = dir.try_clone()?;
    let parts: Vec<_> = path.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        let before = parent.symlink_metadata(part)?;
        parent = source_fs::open_directory(&parent, part, &before)?;
    }
    let name = parts.last().context("missing SKILL.md target")?;
    let before = parent.symlink_metadata(name)?;
    if !before.is_file() {
        bail!("INVALID_SKILL_FORMAT: SKILL.md must be a regular file");
    }
    let mut input = source_fs::open_file(&parent, name, &before)?.take(DOCUMENT_PREFIX_BYTES);
    source_fs::require_unchanged(&before, &input.get_ref().metadata()?)?;
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    source_fs::require_unchanged(&before, &input.get_ref().metadata()?)?;
    source_fs::require_unchanged(&before, &parent.symlink_metadata(name)?)?;
    metadata::parse(&bytes, fallback)
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;

/// Shared selection contract for local filesystem and immutable Git object catalogs.
pub fn select_candidates(
    candidates: &[SkillCandidate],
    selection: &Selection,
) -> Result<Vec<SkillCandidate>> {
    let selected = match selection {
        Selection::Automatic if candidates.len() == 1 => candidates.to_vec(),
        Selection::Automatic if candidates.len() > 1 => {
            bail!("SELECTION_REQUIRED: choose --skill or --all; --yes does not select a source")
        }
        Selection::Automatic => bail!("INCOMPLETE_SOURCE: no valid skills discovered"),
        Selection::All => candidates.to_vec(),
        Selection::Names(names) => {
            if names.is_empty() {
                bail!("SELECTION_REQUIRED: no skill names selected");
            }
            let mut selected = Vec::new();
            let mut requested = BTreeSet::new();
            for name in names {
                if !requested.insert(name) {
                    bail!("SOURCE_AMBIGUOUS: repeated skill selection");
                }
                let matches: Vec<_> = candidates
                    .iter()
                    .filter(|c| c.metadata.name == *name)
                    .collect();
                match matches.as_slice() {
                        [candidate] => selected.push((*candidate).clone()),
                        [] => bail!("SKILL_NOT_FOUND: selected name is not a valid source candidate"),
                        _ => bail!("SOURCE_AMBIGUOUS: duplicate skill names; use --path to select a source directory"),
                    }
            }
            selected
        }
    };
    if selected.is_empty() {
        bail!("INCOMPLETE_SOURCE: no valid skills selected");
    }
    let mut names = BTreeSet::new();
    if selected.iter().any(|c| !names.insert(&c.metadata.name)) {
        bail!("SOURCE_AMBIGUOUS: selected skills repeat a name; use --path");
    }
    Ok(selected)
}
