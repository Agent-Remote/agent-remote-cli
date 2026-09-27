//! Private portable checkpoint bundles; no manifest path is ever extracted or followed.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use cap_std::fs::Dir;
use serde::Serialize;
use tempfile::TempDir;

use super::manifest::{Entry, EntryKind, Manifest};

/// Opened destination parent and private sibling staging survive all asynchronous downloads.
pub struct ExportBundle {
    parent: Dir,
    name: PathBuf,
    staging: TempDir,
    output: PathBuf,
    objects: Vec<Entry>,
}

impl ExportBundle {
    /// Refuse existing data before downloading and keep all staging off the final path.
    pub fn prepare(output: &Path, manifest: &Manifest, metadata: &impl Serialize) -> Result<Self> {
        manifest.validate()?;
        let mut unique: BTreeMap<String, Entry> = BTreeMap::new();
        for entry in &manifest.entries {
            if entry.kind != EntryKind::File {
                continue;
            }
            if let Some(previous) = unique.get(&entry.sha256) {
                if previous.size != entry.size || previous.content_kind != entry.content_kind {
                    bail!("one file digest has inconsistent content metadata");
                }
            } else {
                unique.insert(entry.sha256.clone(), entry.clone());
            }
        }
        let mut bundle = Self::prepare_empty(output, metadata)?;
        write_json(
            &bundle.staging.path().join("bundle/manifest.json"),
            manifest,
        )?;
        bundle.objects = unique.into_values().collect();
        Ok(bundle)
    }

    pub(super) fn prepare_empty(output: &Path, metadata: &impl Serialize) -> Result<Self> {
        let name = output
            .file_name()
            .context("export needs a destination directory name")?
            .to_owned();
        let parent_path = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()?;
        let parent = Dir::open_ambient_dir(&parent_path, cap_std::ambient_authority())?;
        require_empty(&parent, Path::new(&name))?;
        let staging = tempfile::Builder::new()
            .prefix(".skill-export-")
            .tempdir_in(&parent_path)?;
        private_directory(&staging.path().join("bundle"))?;
        private_directory(&staging.path().join("bundle/objects"))?;
        write_json(&staging.path().join("bundle/checkpoint.json"), metadata)?;
        Ok(Self {
            parent,
            name: PathBuf::from(&name),
            staging,
            output: parent_path.join(name),
            objects: Vec::new(),
        })
    }

    pub(super) fn staging_path(&self) -> &Path {
        self.staging.path()
    }

    pub fn objects(&self) -> &[Entry] {
        &self.objects
    }

    /// Only fixed validated digests form filesystem names; file contents have no path authority.
    pub fn create_object(&self, index: usize) -> Result<File> {
        let entry = self
            .objects
            .get(index)
            .context("object is not part of this export")?;
        private_file(
            &self
                .staging
                .path()
                .join("bundle/objects")
                .join(&entry.sha256),
        )
    }

    /// Called only after every download has verified and fsynced its complete object.
    pub fn publish(self) -> Result<PathBuf> {
        sync_directory(&self.staging.path().join("bundle/objects"))?;
        sync_directory(&self.staging.path().join("bundle"))?;
        require_empty(&self.parent, &self.name)?;
        let staging = Dir::open_ambient_dir(self.staging.path(), cap_std::ambient_authority())?;
        // POSIX rename replaces only an empty directory and never follows a destination symlink.
        // Windows cannot replace directories, so remove only a still-empty target immediately before.
        #[cfg(windows)]
        if self.parent.try_exists(&self.name)? {
            self.parent.remove_dir(&self.name)?;
        }
        staging.rename("bundle", &self.parent, &self.name)?;
        Ok(self.output)
    }
}

fn require_empty(parent: &Dir, name: &Path) -> Result<()> {
    use cap_fs_ext::DirExt;
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {
            if parent.open_dir_nofollow(name)?.entries()?.next().is_some() {
                bail!("export destination is not empty");
            }
            Ok(())
        }
        Ok(_) => bail!("export destination must be an absent or empty real directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

pub(super) fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

pub(super) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = private_file(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::manifest::ContentKind;

    fn file(path: &str, size: u64) -> Entry {
        Entry {
            path: path.into(),
            kind: EntryKind::File,
            mode: 0o600,
            size,
            sha256: "a".repeat(64),
            target: String::new(),
            content_kind: ContentKind::Binary,
            dependency: String::new(),
        }
    }

    #[test]
    fn export_stages_metadata_above_runtime_default_without_allocating_content() {
        let parent = tempfile::tempdir().unwrap();
        let output = parent.path().join("bundle");
        let size = (10 << 30) + 1;
        let manifest = Manifest {
            version: 1,
            entries: vec![file("large.db", size)],
        };
        let bundle = ExportBundle::prepare(&output, &manifest, &serde_json::json!({})).unwrap();
        assert_eq!(bundle.objects().len(), 1);
        assert_eq!(bundle.objects()[0].size, size);
        assert!(!output.exists());
        let objects = bundle.staging.path().join("bundle/objects");
        assert_eq!(std::fs::read_dir(objects).unwrap().count(), 0);
        drop(bundle);
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn overflowing_export_metadata_never_creates_staging() {
        let parent = tempfile::tempdir().unwrap();
        let output = parent.path().join("bundle");
        let manifest = Manifest {
            version: 1,
            entries: vec![file("a", i64::MAX as u64), file("b", 1)],
        };
        assert!(ExportBundle::prepare(&output, &manifest, &serde_json::json!({})).is_err());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}
