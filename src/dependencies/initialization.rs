use std::collections::HashSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path};

use anyhow::Result;

use super::{DependencyManager, DependencyManifest};

const MANIFEST_LIMIT: u64 = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestInitialization {
    Ready,
    Applied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestInitializationError {
    InvalidPath,
    InvalidManifest,
    UnsupportedVersion(u32),
}

impl fmt::Display for ManifestInitializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => f.write_str("dependency manifest path is not a regular file"),
            Self::InvalidManifest => f.write_str("dependency manifest is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "unsupported dependency manifest schema version {version}"
                )
            }
        }
    }
}
impl std::error::Error for ManifestInitializationError {}

impl DependencyManager {
    /// Create or validate only local dependency metadata. Never runs managed
    /// tools, downloads dependencies, or replaces an existing manifest.
    pub fn initialize_local_manifest(&self) -> Result<ManifestInitialization> {
        for directory in [
            self.paths.home().to_path_buf(),
            self.paths.dependencies_dir(),
        ] {
            check_directory(&directory, false)?;
        }
        let path = self.paths.dependency_manifest_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                read_manifest(&path)?;
                return Ok(ManifestInitialization::Ready);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // NamedTempFile is 0600 on Unix. Windows metadata inherits the prepared
        // parent ACL; initialization must not spawn icacls or any other process.
        let mut temporary = tempfile::NamedTempFile::new_in(self.paths.dependencies_dir())?;
        serde_json::to_writer_pretty(&mut temporary, &DependencyManifest::default_managed())?;
        temporary.write_all(b"\n")?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => Ok(ManifestInitialization::Applied),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A concurrent writer won. Validate its result, preserving its
                // exact bytes and permissions instead of installing our defaults.
                read_manifest(&path)?;
                Ok(ManifestInitialization::Ready)
            }
            Err(error) => Err(error.error.into()),
        }
    }
}

pub(super) fn check_directory(path: &Path, allow_missing: bool) -> Result<()> {
    // A trailing directory separator or `/.` makes POSIX lstat follow
    // the final link. Component collection removes only lexical aliases.
    let directory: std::path::PathBuf = path.components().collect();
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() && !is_link(&metadata) => Ok(()),
        Ok(_) => Err(ManifestInitializationError::InvalidPath.into()),
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn read_manifest(path: &Path) -> Result<DependencyManifest> {
    validate_metadata(&fs::symlink_metadata(path)?)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    validate_metadata(&file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(MANIFEST_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MANIFEST_LIMIT {
        return Err(ManifestInitializationError::InvalidManifest.into());
    }
    let manifest: DependencyManifest =
        serde_json::from_slice(&bytes).map_err(|_| ManifestInitializationError::InvalidManifest)?;
    if manifest.schema_version != 1 {
        return Err(
            ManifestInitializationError::UnsupportedVersion(manifest.schema_version).into(),
        );
    }
    if manifest.dependencies.len() > 128 {
        return Err(ManifestInitializationError::InvalidManifest.into());
    }
    let mut names = HashSet::new();
    for dependency in &manifest.dependencies {
        if dependency.name.trim().is_empty()
            || dependency.name.len() > 512
            || !names.insert(&dependency.name)
            || dependency.required_version.trim().is_empty()
            || dependency.binary.is_empty()
            || dependency.binary.len() > 4096
            || dependency.binary.contains(['\\', ':', '\0'])
            || !Path::new(&dependency.binary)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
        {
            return Err(ManifestInitializationError::InvalidManifest.into());
        }
    }
    Ok(manifest)
}

fn validate_metadata(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() || is_link(metadata) {
        return Err(ManifestInitializationError::InvalidPath.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(ManifestInitializationError::InvalidPath.into());
        }
    }
    if metadata.len() > MANIFEST_LIMIT {
        return Err(ManifestInitializationError::InvalidManifest.into());
    }
    Ok(())
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}
