//! Bounded raw Git tree/blob reads. No checkout, filters, archive attributes or source execution.

use super::git_process;
use super::git_source::is_object_id;
use super::manifest::validate_path;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// The selected path is absent or is not a fetched tree, distinct from transport failure.
#[derive(Debug)]
pub struct MissingGitDirectory;
impl std::fmt::Display for MissingGitDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("INCOMPLETE_SOURCE: --path must select a fetched Git directory")
    }
}
impl std::error::Error for MissingGitDirectory {}

#[derive(Clone, Debug)]
pub struct GitEntry {
    pub path: String,
    pub mode: u32,
    pub oid: String,
    pub size: u64,
}
impl GitEntry {
    pub fn is_tree(&self) -> bool {
        self.mode == 0o040000
    }
    pub fn is_link(&self) -> bool {
        self.mode == 0o120000
    }
    pub fn is_submodule(&self) -> bool {
        self.mode == 0o160000
    }
}

pub async fn tree(directory: &Path, commit: &str, subpath: Option<&str>) -> Result<Vec<GitEntry>> {
    if !is_object_id(commit) {
        bail!("SOURCE_INVALID: Git tree needs an immutable commit");
    }
    let treeish = if let Some(path) = subpath {
        validate_path(path)?;
        // The part before ':' is a validated full OID. Git resolves the normalized path only
        // through tree objects, never through filesystem links or arbitrary revision expressions.
        let selected = format!("{commit}:{path}");
        let mut inspect = git_process::command(directory, false);
        inspect.args(["cat-file", "-t", &selected]);
        let kind = git_process::run(inspect, b"", 64, Duration::from_secs(30), None).await?;
        if kind.as_deref() != Some(b"tree\n") {
            return Err(MissingGitDirectory.into());
        }
        selected
    } else {
        commit.to_owned()
    };
    let mut command = git_process::command(directory, false);
    command.args(["ls-tree", "-r", "-t", "-z", "--long", &treeish]);
    let output = git_process::run(
        command,
        b"",
        32 * 1024 * 1024,
        Duration::from_secs(30),
        None,
    )
    .await?
    .context("SOURCE_INVALID: cannot read Git tree")?;
    tokio::task::spawn_blocking(move || parse_tree(&output)).await?
}

fn parse_tree(output: &[u8]) -> Result<Vec<GitEntry>> {
    if !output.is_empty() && output.last() != Some(&0) {
        bail!("SOURCE_INVALID: truncated Git tree");
    }
    let mut entries = BTreeMap::new();
    for line in output
        .split(|byte| *byte == 0)
        .filter(|line| !line.is_empty())
    {
        let tab = line
            .iter()
            .position(|byte| *byte == b'\t')
            .context("SOURCE_INVALID: malformed Git tree")?;
        let header = std::str::from_utf8(&line[..tab])?
            .split_whitespace()
            .collect::<Vec<_>>();
        if header.len() != 4 || !is_object_id(header[2]) {
            bail!("SOURCE_INVALID: malformed Git tree entry");
        }
        let mode = u32::from_str_radix(header[0], 8)?;
        let kind = match mode {
            0o040000 => "tree",
            0o100644 | 0o100755 | 0o120000 => "blob",
            0o160000 => "commit",
            _ => bail!("SOURCE_INVALID: unsupported Git file mode"),
        };
        if kind != header[1] {
            bail!("SOURCE_INVALID: inconsistent Git object kind");
        }
        let size = if kind == "blob" {
            header[3].parse()?
        } else {
            0
        };
        let path = std::str::from_utf8(&line[tab + 1..])
            .context("SOURCE_INVALID: Git paths must be UTF-8")?
            .to_owned();
        validate_path(&path)?;
        if path.split('/').count() > 128 {
            bail!("QUOTA_EXCEEDED: Git tree exceeds depth 128");
        }
        let entry = GitEntry {
            path: path.clone(),
            mode,
            oid: header[2].into(),
            size,
        };
        if entries.insert(path, entry).is_some() || entries.len() > 100_000 {
            bail!("QUOTA_EXCEEDED: duplicate or excessive Git entries");
        }
    }
    for entry in entries.values() {
        if let Some((parent, _)) = entry.path.rsplit_once('/') {
            if !entries.get(parent).is_some_and(GitEntry::is_tree) {
                bail!("SOURCE_INVALID: Git entry parent is not a tree");
            }
        }
    }
    Ok(entries.into_values().collect())
}

/// Batch output is parsed against exact expected OIDs/sizes; repeated blobs are requested once.
pub async fn blobs(
    directory: &Path,
    entries: &[&GitEntry],
    byte_limit: u64,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut objects = BTreeMap::new();
    for entry in entries {
        if entry.is_tree() || entry.is_submodule() {
            bail!("SOURCE_INVALID: expected blob");
        }
        if objects
            .insert(entry.oid.clone(), entry.size)
            .is_some_and(|old| old != entry.size)
        {
            bail!("SOURCE_INVALID: inconsistent Git blob size");
        }
    }
    let total = objects
        .values()
        .try_fold(0u64, |total, size| total.checked_add(*size))
        .context("QUOTA_EXCEEDED: Git blob sizes overflow")?;
    if total > byte_limit {
        bail!("QUOTA_EXCEEDED: Git content exceeds its expanded byte bound");
    }
    if objects.is_empty() {
        return Ok(BTreeMap::new());
    }
    let input = objects
        .keys()
        .map(|key| format!("{key}\n"))
        .collect::<String>();
    let mut command = git_process::command(directory, false);
    command.args(["cat-file", "--batch"]);
    let limit = usize::try_from(total)?
        .checked_add(objects.len() * 128)
        .context("Git batch size overflow")?;
    let output = git_process::run(
        command,
        input.as_bytes(),
        limit,
        Duration::from_secs(30),
        None,
    )
    .await?
    .context("SOURCE_INVALID: cannot read Git blobs")?;
    tokio::task::spawn_blocking(move || parse_blobs(&output, objects)).await?
}

fn parse_blobs(
    mut output: &[u8],
    objects: BTreeMap<String, u64>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut result = BTreeMap::new();
    for (oid, size) in objects {
        let end = output
            .iter()
            .position(|byte| *byte == b'\n')
            .context("SOURCE_INVALID: missing Git blob header")?;
        if output[..end] != *format!("{oid} blob {size}").as_bytes() {
            bail!("SOURCE_INVALID: Git blob identity changed");
        }
        output = &output[end + 1..];
        let size = usize::try_from(size)?;
        if output.get(size) != Some(&b'\n') {
            bail!("SOURCE_INVALID: truncated Git blob");
        }
        result.insert(oid, output[..size].to_vec());
        output = &output[size + 1..];
    }
    if !output.is_empty() {
        bail!("SOURCE_INVALID: trailing Git blob output");
    }
    Ok(result)
}

#[cfg(test)]
#[path = "../../tests/unit/src/skills/git_objects.rs"]
mod tests;
