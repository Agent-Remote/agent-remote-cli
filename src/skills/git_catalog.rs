//! Discovery and complete portable packages from immutable Git objects.

use super::discovery::{DiscoveryIssue, SkillCandidate, EXCLUDED_DIRECTORIES};
use super::git_objects::{self, GitEntry};
use super::manifest::{ContentKind, Entry, EntryKind, Manifest};
use super::metadata;
use super::snapshot::{PackageLimits, PackageSnapshot};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct GitCatalog {
    directory: PathBuf,
    tree: Vec<GitEntry>,
    links: BTreeMap<String, Vec<u8>>,
    candidates: Vec<SkillCandidate>,
    issues: Vec<DiscoveryIssue>,
}
impl GitCatalog {
    pub async fn discover(
        directory: &Path,
        commit: &str,
        subpath: Option<&str>,
        root_name: &str,
    ) -> Result<Self> {
        let tree = git_objects::tree(directory, commit, subpath).await?;
        let link_entries = tree
            .iter()
            .filter(|entry| entry.is_link())
            .collect::<Vec<_>>();
        if link_entries.iter().any(|entry| entry.size > 4096) {
            bail!("SOURCE_INVALID: Git link target exceeds 4096 bytes");
        }
        let links = git_objects::blobs(directory, &link_entries, 4 * 1024 * 1024).await?;
        let mut catalog = Self {
            directory: directory.into(),
            tree,
            links,
            candidates: Vec::new(),
            issues: Vec::new(),
        };
        let roots = catalog.discovery_roots();
        if roots.len() > 1000 {
            bail!("QUOTA_EXCEEDED: Git discovery exceeds 1000 skills; use --path");
        }
        for prefix in roots {
            let fallback = prefix
                .rsplit('/')
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or(root_name);
            match catalog.read_metadata(&prefix, fallback).await {
                Ok(metadata) => catalog.candidates.push(SkillCandidate {
                    path: prefix,
                    metadata,
                }),
                Err(error) => catalog.issues.push(DiscoveryIssue {
                    path: prefix,
                    message: error.to_string(),
                }),
            }
        }
        Ok(catalog)
    }

    pub fn candidates(&self) -> &[SkillCandidate] {
        &self.candidates
    }
    pub fn issues(&self) -> &[DiscoveryIssue] {
        &self.issues
    }

    fn discovery_roots(&self) -> Vec<String> {
        let roots = self
            .tree
            .iter()
            .filter_map(|entry| {
                if entry.path == "SKILL.md" {
                    Some("")
                } else {
                    entry.path.strip_suffix("/SKILL.md")
                }
            })
            .collect::<std::collections::BTreeSet<_>>();
        roots
            .iter()
            .filter(|prefix| {
                if prefix.is_empty() {
                    return true;
                }
                !prefix
                    .split('/')
                    .any(|part| EXCLUDED_DIRECTORIES.contains(&part))
                    && !roots.contains("")
                    && !prefix
                        .match_indices('/')
                        .any(|(index, _)| roots.contains(&prefix[..index]))
            })
            .map(|prefix| (*prefix).to_owned())
            .collect()
    }

    fn entries<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = (&'a GitEntry, &'a str)> {
        self.tree.iter().filter_map(move |entry| {
            if prefix.is_empty() {
                Some((entry, entry.path.as_str()))
            } else {
                entry
                    .path
                    .strip_prefix(prefix)
                    .and_then(|suffix| suffix.strip_prefix('/'))
                    .map(|path| (entry, path))
            }
        })
    }

    fn skeleton(&self, prefix: &str) -> Result<Manifest> {
        let mut entries = Vec::new();
        for (raw, path) in self.entries(prefix) {
            if raw.is_submodule() {
                continue;
            }
            let kind = if raw.is_tree() {
                EntryKind::Directory
            } else if raw.is_link() {
                EntryKind::Symlink
            } else {
                EntryKind::File
            };
            let file = kind == EntryKind::File;
            let entry = Entry {
                path: path.into(),
                kind,
                mode: if raw.is_tree() {
                    0o755
                } else if raw.is_link() {
                    0o777
                } else {
                    raw.mode & 0o777
                },
                size: if file { raw.size } else { 0 },
                sha256: if file { "0".repeat(64) } else { String::new() },
                target: if raw.is_link() {
                    std::str::from_utf8(
                        self.links
                            .get(&raw.oid)
                            .context("INCOMPLETE_SOURCE: missing link object")?,
                    )?
                    .to_owned()
                } else {
                    String::new()
                },
                content_kind: if file {
                    ContentKind::Text
                } else {
                    ContentKind::Empty
                },
                dependency: String::new(),
            };
            entry.validate()?;
            entries.push(entry);
        }
        Ok(Manifest {
            version: 1,
            entries,
        })
    }

    async fn read_metadata(
        &self,
        prefix: &str,
        fallback: &str,
    ) -> Result<super::discovery::SkillMetadata> {
        let manifest = self.skeleton(prefix)?;
        let entry = manifest.resolve("SKILL.md")?;
        if entry.kind != EntryKind::File {
            bail!("INVALID_SKILL_FORMAT: SKILL.md must be text");
        }
        let raw = self
            .entries(prefix)
            .find(|(_, path)| *path == entry.path)
            .context("INCOMPLETE_SOURCE: missing SKILL.md object")?
            .0;
        let mut objects =
            git_objects::blobs(&self.directory, &[raw], PackageLimits::default().file_bytes)
                .await?;
        let bytes = objects
            .remove(&raw.oid)
            .context("INCOMPLETE_SOURCE: missing SKILL.md bytes")?;
        metadata::parse(
            &bytes[..bytes.len().min(metadata::DOCUMENT_PREFIX_BYTES as usize)],
            fallback,
        )
    }

    pub async fn capture(&self, candidate: &SkillCandidate) -> Result<PackageSnapshot> {
        if !self.candidates.contains(candidate) {
            bail!("candidate does not belong to Git discovery");
        }
        let limits = PackageLimits::default();
        let selected = self.entries(&candidate.path).collect::<Vec<_>>();
        if selected.len() > limits.entries {
            bail!("QUOTA_EXCEEDED: package entry limit exceeded");
        }
        if selected.iter().any(|(entry, _)| entry.is_submodule()) {
            bail!("INCOMPLETE_SOURCE: selected skill contains an unfetched submodule");
        }
        let files = selected
            .iter()
            .filter(|(entry, _)| !entry.is_tree() && !entry.is_link())
            .map(|(entry, _)| *entry)
            .collect::<Vec<_>>();
        let mut total = 0u64;
        for entry in &files {
            total = total
                .checked_add(entry.size)
                .context("package size overflow")?;
            if entry.size > limits.file_bytes || total > limits.total_bytes {
                bail!("QUOTA_EXCEEDED: package byte limit exceeded");
            }
        }
        let raw_objects = git_objects::blobs(&self.directory, &files, limits.total_bytes).await?;
        let manifest = self.skeleton(&candidate.path)?;
        let file_ids = selected
            .iter()
            .map(|(entry, path)| ((*path).to_owned(), entry.oid.clone()))
            .collect();
        let name = candidate.metadata.name.clone();
        tokio::task::spawn_blocking(move || package(manifest, file_ids, raw_objects, limits, &name))
            .await?
    }
}

fn package(
    mut manifest: Manifest,
    file_ids: BTreeMap<String, String>,
    raw_objects: BTreeMap<String, Vec<u8>>,
    limits: PackageLimits,
    name: &str,
) -> Result<PackageSnapshot> {
    let mut objects = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    for (oid, bytes) in raw_objects {
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let kind = if std::str::from_utf8(&bytes).is_ok() && !bytes.contains(&0) {
            ContentKind::Text
        } else {
            ContentKind::Binary
        };
        hashes.insert(oid, (digest.clone(), kind));
        objects.insert(digest, bytes);
    }
    for entry in &mut manifest.entries {
        if entry.kind == EntryKind::File {
            let oid = file_ids
                .get(&entry.path)
                .context("missing Git manifest entry")?;
            let (digest, kind) = hashes.get(oid).context("missing Git content digest")?;
            entry.sha256.clone_from(digest);
            entry.content_kind = *kind;
        }
    }
    let document = manifest.resolve("SKILL.md")?;
    let metadata = metadata::parse(
        objects
            .get(&document.sha256)
            .context("INCOMPLETE_SOURCE: missing instructions")?,
        name,
    )?;
    if metadata.name != name {
        bail!("SOURCE_LAYOUT_CHANGED: skill name changed");
    }
    PackageSnapshot::from_objects(manifest, objects, limits)
}
