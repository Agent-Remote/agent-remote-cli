//! Capability-relative source reads and change detection, shared by discovery and packing.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use anyhow::{bail, Context, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, File, Metadata, OpenOptions};

use super::manifest::validate_path;

/// An opened source root is the only filesystem authority granted to the packer.
pub(super) fn open_root(path: &Path) -> Result<Dir> {
    Dir::open_ambient_dir(path, cap_std::ambient_authority())
        .context("cannot open skill source directory")
}

pub(super) fn open_directory(parent: &Dir, name: &str, before: &Metadata) -> Result<Dir> {
    let dir = parent
        .open_dir_nofollow(name)
        .context("source directory changed or became a link")?;
    require_unchanged(before, &dir.dir_metadata()?)?;
    Ok(dir)
}

pub(super) fn open_file(parent: &Dir, name: &str, before: &Metadata) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    // A regular file replaced by a FIFO must fail validation rather than block the CLI.
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = parent.open_with(name, &options)?;
    let actual = file.metadata()?;
    if !actual.is_file() {
        bail!("source entry is no longer a regular file");
    }
    require_unchanged(before, &actual)?;
    Ok(file)
}

#[derive(Clone, Copy)]
pub(super) enum SourceEntries {
    Package,
    All,
}

pub(super) fn names(dir: &Dir, remaining: usize) -> Result<Vec<String>> {
    selected_names(dir, remaining, SourceEntries::Package)
}

pub(super) fn selected_names(
    dir: &Dir,
    remaining: usize,
    selection: SourceEntries,
) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in dir.entries()? {
        let entry = entry?;
        if matches!(selection, SourceEntries::Package) && entry.file_name() == ".git" {
            continue;
        }
        if names.len() >= remaining {
            bail!("QUOTA_EXCEEDED: source entry limit exceeded");
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("source names must be UTF-8"))?;
        validate_path(&name)?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

pub(super) fn portable_mode(metadata: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        cap_std::fs::MetadataExt::mode(metadata) & 0o777
    }
    #[cfg(not(unix))]
    {
        // Windows has no POSIX execute bits. Git acquisition supplies its index modes separately.
        if metadata.is_dir() {
            0o755
        } else {
            0o644
        }
    }
}

pub(super) fn require_unchanged(before: &Metadata, after: &Metadata) -> Result<()> {
    let mut same = before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.file_type() == after.file_type()
        && before.len() == after.len()
        && portable_mode(before) == portable_mode(after)
        && before.modified()? == after.modified()?;
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        same &= before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec();
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        same &= before.creation_time() == after.creation_time()
            && before.file_attributes() == after.file_attributes();
    }
    if !same {
        bail!("SOURCE_UNSTABLE: source changed while packing; stop writers and retry");
    }
    Ok(())
}

/// Rewalk every path after copying so late changes to already-read entries are also rejected.
#[cfg(test)]
pub(super) fn verify_tree(
    dir: &Dir,
    prefix: &str,
    expected: &BTreeMap<String, Metadata>,
) -> Result<usize> {
    verify_selected_tree(dir, prefix, expected, SourceEntries::Package, &|| Ok(()))
}

pub(super) fn verify_selected_tree(
    dir: &Dir,
    prefix: &str,
    expected: &BTreeMap<String, Metadata>,
    selection: SourceEntries,
    check_cancelled: &impl Fn() -> Result<()>,
) -> Result<usize> {
    check_cancelled()?;
    let before = expected
        .get(prefix)
        .context("missing source directory baseline")?;
    require_unchanged(before, &dir.dir_metadata()?)?;
    let mut count = 1;
    for name in selected_names(dir, expected.len(), selection)? {
        check_cancelled()?;
        let path = join(prefix, &name);
        let original = expected
            .get(&path)
            .context("SOURCE_UNSTABLE: source gained an entry")?;
        let current = dir.symlink_metadata(&name)?;
        require_unchanged(original, &current)?;
        if current.is_dir() {
            count += verify_selected_tree(
                &open_directory(dir, &name, &current)?,
                &path,
                expected,
                selection,
                check_cancelled,
            )?;
        } else {
            count += 1;
        }
    }
    require_unchanged(before, &dir.dir_metadata()?)?;
    Ok(count)
}

pub(super) fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

pub(super) fn is_missing(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
}
