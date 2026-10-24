//! Handle-bound storage for a future privileged broker. No installation or elevation.

use std::fs::File;
use std::path::{Component, Path, PathBuf};

use anyhow::{ensure, Context, Result};
use cap_std::fs::Dir;

#[cfg(unix)]
#[path = "protected_directory/unix.rs"]
mod native;
#[cfg(windows)]
#[path = "protected_directory/windows.rs"]
mod native;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectorySync {
    Synced,
    Unsupported,
}

#[derive(Clone)]
enum Authority {
    Privileged,
    #[cfg(test)]
    Test {
        anchor: PathBuf,
        identity: String,
    },
}
impl Authority {
    fn production(&self) -> bool {
        matches!(self, Self::Privileged)
    }
}

pub(crate) struct ProtectedDirectory {
    directory: Dir,
    path: PathBuf,
    identity: String,
    authority: Authority,
}

impl ProtectedDirectory {
    /// The root must already exist with protected ownership and ACLs/modes.
    pub(crate) fn open_existing(path: &Path) -> Result<Self> {
        native::require_privileged()?;
        let path = normalize(path)?;
        let authority = Authority::Privileged;
        let directory = walk(&path, &authority)?;
        let path = std::fs::canonicalize(&path)?;
        Self::from_directory(directory, path, authority)
    }

    fn from_directory(directory: Dir, path: PathBuf, authority: Authority) -> Result<Self> {
        validate_directory(&directory, true, &authority)?;
        let identity = identity(&directory)?;
        let result = Self {
            directory,
            path,
            identity,
            authority,
        };
        result.verify()?;
        Ok(result)
    }

    pub(crate) fn dir(&self) -> &Dir {
        &self.directory
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn verify(&self) -> Result<()> {
        if self.authority.production() {
            native::require_privileged()?;
        }
        validate_directory(&self.directory, true, &self.authority)?;
        ensure!(
            identity(&self.directory)? == self.identity,
            "protected directory handle changed"
        );
        let current = walk(&self.path, &self.authority)?;
        ensure!(
            identity(&current)? == self.identity,
            "protected directory path changed"
        );
        Ok(())
    }

    pub(crate) fn create_file(&self, name: &str) -> Result<File> {
        component(name)?;
        self.verify()?;
        let file = native::create_file(&self.directory, name, &self.authority)?;
        self.verify_file(&file)?;
        self.verify()?;
        Ok(file)
    }

    /// Returns None only for a genuinely missing leaf. Never opens a FIFO or
    /// follows a link. Callers must separately bound the amount of file data read.
    pub(crate) fn open_file(&self, name: &str) -> Result<Option<File>> {
        component(name)?;
        self.verify()?;
        let file = native::open_file(&self.directory, name)?;
        if let Some(file) = &file {
            self.verify_file(file)?;
        }
        self.verify()?;
        Ok(file)
    }

    /// Open an existing protected file for append-only writes.  The native
    /// implementations pin the descriptor without following links and apply
    /// the same ownership/ACL checks as read-only handles.  Callers must
    /// retain the returned handle while appending and verify the containing
    /// directory afterwards.
    pub(crate) fn open_append_file(&self, name: &str) -> Result<Option<File>> {
        component(name)?;
        self.verify()?;
        let file = native::open_append_file(&self.directory, name)?;
        if let Some(file) = &file {
            self.verify_file(file)?;
        }
        self.verify()?;
        Ok(file)
    }

    pub(crate) fn verify_file(&self, file: &File) -> Result<()> {
        native::validate_file(file, &self.authority)
    }

    pub(crate) fn create_child(&self, name: &str) -> Result<Self> {
        component(name)?;
        self.verify()?;
        let directory = native::create_child(&self.directory, name, &self.authority)?;
        self.verify()?;
        Self::from_directory(directory, self.path.join(name), self.authority.clone())
    }

    pub(crate) fn open_child(&self, name: &str) -> Result<Option<Self>> {
        component(name)?;
        self.verify()?;
        let Some(directory) = native::open_child(&self.directory, name)? else {
            return Ok(None);
        };
        self.verify()?;
        Self::from_directory(directory, self.path.join(name), self.authority.clone()).map(Some)
    }

    pub(crate) fn sync(&self) -> Result<DirectorySync> {
        self.verify()?;
        native::sync(&self.directory)
    }

    /// A test-only explicit authority, never selected by environment variables
    /// or compiled into release binaries. Its anchor must be an existing
    /// current-user directory supplied by the test's TempDir; only this helper
    /// narrows the temporary root's permissions before using it as authority.
    #[cfg(test)]
    pub(crate) fn open_test_root(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "test root must be a directory"
        );
        let path = std::fs::canonicalize(path)?;
        let directory = native::open_root(&path)?;
        native::prepare_test_root(&directory)?;
        let identity = identity(&directory)?;
        let authority = Authority::Test {
            anchor: path.clone(),
            identity,
        };
        Self::from_directory(directory, path, authority)
    }
}

fn normalize(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "protected root must be absolute");
    ensure!(
        !path
            .components()
            .any(|part| matches!(part, Component::ParentDir)),
        "parent traversal is forbidden"
    );
    let text = path.to_str().context("protected root is not UTF-8")?;
    ensure!(
        text.len() <= 32768 && !text.chars().any(char::is_control),
        "protected root is invalid"
    );
    native::normalize(path)
}

fn component(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && !matches!(name, "." | "..")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_=+.-".contains(&byte)),
        "invalid protected entry name"
    );
    #[cfg(windows)]
    {
        ensure!(!name.ends_with('.'), "invalid protected entry name");
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        ensure!(
            !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9')),
            "reserved protected entry name"
        );
    }
    Ok(())
}

fn identity(directory: &Dir) -> Result<String> {
    super::file_identity(&directory.try_clone()?.into_std_file())
}
fn validate_directory(directory: &Dir, private: bool, authority: &Authority) -> Result<()> {
    native::validate_directory(&directory.try_clone()?.into_std_file(), private, authority)
}

fn walk(path: &Path, authority: &Authority) -> Result<Dir> {
    #[cfg(test)]
    if let Authority::Test {
        anchor,
        identity: expected,
    } = authority
    {
        let relative = path
            .strip_prefix(anchor)
            .context("test directory escaped its anchor")?;
        let mut directory = native::open_root(anchor)?;
        ensure!(
            identity(&directory)? == *expected,
            "test anchor was replaced"
        );
        validate_directory(&directory, true, authority)?;
        for part in relative.components() {
            let Component::Normal(name) = part else {
                anyhow::bail!("invalid test child path")
            };
            directory =
                native::open_child(&directory, name.to_str().context("invalid child name")?)?
                    .context("protected child is missing")?;
            validate_directory(&directory, true, authority)?;
        }
        return Ok(directory);
    }
    let mut root = PathBuf::new();
    let mut parts = Vec::new();
    for part in path.components() {
        match part {
            Component::RootDir | Component::Prefix(_) => root.push(part.as_os_str()),
            Component::Normal(name) => parts.push(name),
            _ => anyhow::bail!("invalid protected root path"),
        }
    }
    let mut directory = native::open_root(&root)?;
    validate_directory(&directory, parts.is_empty(), authority)?;
    for (index, name) in parts.iter().enumerate() {
        directory = native::open_child(
            &directory,
            name.to_str().context("invalid protected root component")?,
        )?
        .context("protected root does not exist")?;
        validate_directory(&directory, index + 1 == parts.len(), authority)?;
    }
    Ok(directory)
}

#[cfg(test)]
#[path = "../../tests/unit/src/protected_directory.rs"]
mod tests;
