//! Canonical skill tree validation shared with the Server and Node wire contract.

use std::collections::{BTreeMap, VecDeque};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// The four explicitly supported manifest entry types.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    RuntimeLink,
}

impl EntryKind {
    pub(super) fn wire_name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::RuntimeLink => "runtime_link",
        }
    }
}

/// Whole-file UTF-8 classification; non-file entries use the empty value.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum ContentKind {
    #[default]
    #[serde(rename = "")]
    Empty,
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "binary")]
    Binary,
}

impl ContentKind {
    pub(super) fn wire_name(self) -> &'static str {
        match self {
            Self::Empty => "",
            Self::Text => "text",
            Self::Binary => "binary",
        }
    }
}

/// Exact portable metadata for one file, directory, or link.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    #[serde(default = "default_mode")]
    pub mode: u32,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub content_kind: ContentKind,
    #[serde(default)]
    pub dependency: String,
}

fn default_mode() -> u32 {
    0o644
}

fn manifest_version() -> u32 {
    1
}

/// A complete, UTF-8-byte-sorted tree, independent of local filesystem paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default = "manifest_version")]
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// Decode and validate without following any host filesystem links.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let manifest: Self =
            serde_json::from_slice(bytes).context("invalid skill manifest JSON")?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Enforce complete parents, unique ordering and bounded internal link resolution.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.entries.len() > 100_000 {
            bail!("unsupported skill manifest version or entry count");
        }
        let mut by_path = BTreeMap::new();
        let mut previous = "";
        let mut total = 0u64;
        for entry in &self.entries {
            entry.validate()?;
            if entry.path.as_str() <= previous {
                bail!("manifest paths must be unique and UTF-8 sorted");
            }
            previous = &entry.path;
            total = total
                .checked_add(entry.size)
                .context("skill tree byte count overflows the protocol")?;
            if total > i64::MAX as u64 {
                bail!("skill tree byte count overflows the protocol");
            }
            let parts: Vec<_> = entry.path.split('/').collect();
            for index in 1..parts.len() {
                let parent = parts[..index].join("/");
                let parent_entry: &&Entry = by_path
                    .get(parent.as_str())
                    .context("manifest requires explicit directory parents")?;
                if parent_entry.kind != EntryKind::Directory {
                    bail!("manifest parent is not a directory");
                }
            }
            by_path.insert(entry.path.as_str(), entry);
        }
        for entry in &self.entries {
            if entry.kind == EntryKind::Symlink {
                validate_link(entry, &by_path)?;
            }
        }
        Ok(())
    }

    /// Hash the documented NUL-delimited wire fields, never serde's JSON representation.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"agent-remote-skill-tree-v1\0");
        for entry in &self.entries {
            let mode = entry.mode.to_string();
            let size = entry.size.to_string();
            for value in [
                entry.path.as_str(),
                entry.kind.wire_name(),
                &mode,
                &size,
                &entry.sha256,
                &entry.target,
                entry.content_kind.wire_name(),
                &entry.dependency,
            ] {
                digest.update(value.as_bytes());
                digest.update(b"\0");
            }
        }
        Ok(format!("{:x}", digest.finalize()))
    }

    /// Resolve a portable path in this complete tree without reading the host filesystem.
    pub fn resolve(&self, path: &str) -> Result<&Entry> {
        self.validate()?;
        validate_path(path)?;
        let entries = self.entries.iter().map(|e| (e.path.as_str(), e)).collect();
        let resolved = resolve_components(path.split('/').collect(), Vec::new(), &entries)?;
        entries
            .get(resolved.join("/").as_str())
            .copied()
            .context("path resolves to the implicit tree root")
    }
}

impl Entry {
    /// Validate entry-local invariants before trusting metadata or content classification.
    pub fn validate(&self) -> Result<()> {
        validate_path(&self.path)?;
        if self.mode > 0o777 || self.size > i64::MAX as u64 {
            bail!("skill entry has invalid size or mode");
        }
        if self.kind == EntryKind::File {
            if self.sha256.len() != 64
                || !self
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || self.content_kind == ContentKind::Empty
                || !self.target.is_empty()
                || !self.dependency.is_empty()
            {
                bail!("file entry has inconsistent metadata");
            }
            return Ok(());
        }
        if self.size != 0 || !self.sha256.is_empty() || self.content_kind != ContentKind::Empty {
            bail!("non-file entry cannot contain file metadata");
        }
        if self.kind == EntryKind::Directory {
            if !self.target.is_empty() || !self.dependency.is_empty() {
                bail!("directory cannot contain a link target");
            }
            return Ok(());
        }
        if self.mode != 0o777 || self.target.is_empty() || self.target.contains('\\') {
            bail!("link entry has invalid target or mode");
        }
        validate_text(&self.target)?;
        if self.kind == EntryKind::RuntimeLink {
            let relative = self
                .target
                .strip_prefix('/')
                .context("runtime link target must be absolute")?;
            validate_path(relative)?;
            if self.dependency.is_empty()
                || self.dependency.len() > 64
                || !self.dependency.as_bytes()[0].is_ascii_lowercase()
                || !self.dependency.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
                })
            {
                bail!("runtime link requires a canonical dependency identifier");
            }
        } else if self.target.starts_with('/') || !self.dependency.is_empty() {
            bail!("ordinary link must stay relative and cannot claim a dependency");
        }
        Ok(())
    }

    /// Verify actual bytes, including the text/binary declaration used by state merges.
    pub fn verify_content(&self, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        if self.kind != EntryKind::File || self.size != bytes.len() as u64 {
            bail!("skill content size or entry kind does not match");
        }
        if self.sha256 != format!("{:x}", Sha256::digest(bytes)) {
            bail!("skill content digest does not match");
        }
        let is_text = std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0);
        if (self.content_kind == ContentKind::Text) != is_text {
            bail!("skill content classification does not match");
        }
        Ok(())
    }
}

/// Check the common NFC relative POSIX contract without accessing local paths.
pub fn validate_path(value: &str) -> Result<()> {
    if value.is_empty() || value.starts_with('/') || value.contains('\\') {
        bail!("skill path must be relative POSIX text");
    }
    validate_text(value)?;
    if value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == ".." || part.len() > 255)
    {
        bail!("skill path contains an invalid component");
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<()> {
    if value.len() > 4096 || value.chars().any(char::is_control) || !value.nfc().eq(value.chars()) {
        bail!("skill path is not canonical NFC UTF-8 text");
    }
    Ok(())
}

fn validate_link<'a>(entry: &'a Entry, entries: &BTreeMap<&'a str, &'a Entry>) -> Result<()> {
    let mut resolved: Vec<_> = entry.path.split('/').collect();
    resolved.pop();
    let resolved = resolve_components(entry.target.split('/').collect(), resolved, entries)?;
    if resolved.is_empty() || entry.path.starts_with(&(resolved.join("/") + "/")) {
        bail!("link to the manifest root or ancestor creates a cycle");
    }
    Ok(())
}

fn resolve_components<'a>(
    mut pending: VecDeque<&'a str>,
    mut resolved: Vec<&'a str>,
    entries: &BTreeMap<&'a str, &'a Entry>,
) -> Result<Vec<&'a str>> {
    let mut hops = 0;
    while let Some(component) = pending.pop_front() {
        match component {
            "" | "." => continue,
            ".." => {
                resolved.pop().context("link escapes manifest root")?;
                continue;
            }
            _ => {}
        }
        let path = resolved
            .iter()
            .copied()
            .chain(std::iter::once(component))
            .collect::<Vec<_>>()
            .join("/");
        let target = entries
            .get(path.as_str())
            .context("link target is missing from manifest")?;
        if target.kind == EntryKind::Symlink {
            hops += 1;
            if hops > 40 {
                bail!("link resolution exceeds the cycle limit");
            }
            pending = target.target.split('/').chain(pending).collect();
            continue;
        }
        if !pending.is_empty() && target.kind != EntryKind::Directory {
            bail!("link traverses a non-directory entry");
        }
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
