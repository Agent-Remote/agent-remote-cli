//! Descriptor-relative output preparation; secret bytes never use ambient writes.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, UNIX_EPOCH};

use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::configuration::ConfigError;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputPlan {
    pub path: PathBuf,
    pub action: OutputAction,
    pub anchor_path: PathBuf,
    pub anchor_identity: String,
    pub missing_directories: Vec<String>,
    #[serde(deserialize_with = "required_optional_identity")]
    pub target_identity: Option<String>,
}

fn required_optional_identity<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputAction {
    Create,
    Replace,
}

fn io_error(_: io::Error) -> ConfigError {
    ConfigError("output_unavailable")
}
fn invalid() -> ConfigError {
    ConfigError("output_invalid")
}

pub(super) fn absolute(path: &Path) -> Result<PathBuf, ConfigError> {
    let path: PathBuf = std::path::absolute(path)
        .map_err(io_error)?
        .components()
        .collect();
    let text = path.to_str().ok_or_else(invalid)?;
    if text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid());
    }
    Ok(path)
}

struct Location {
    dir: Dir,
    path: PathBuf,
    missing: Vec<String>,
}

fn walk(path: &Path) -> Result<Location, ConfigError> {
    let path = absolute(path)?;
    let mut root = PathBuf::new();
    let mut names = Vec::new();
    for part in path.components() {
        match part {
            Component::Prefix(_) | Component::RootDir => root.push(part.as_os_str()),
            Component::Normal(name) => names.push(name.to_str().ok_or_else(invalid)?.to_owned()),
            _ => return Err(invalid()),
        }
    }
    let mut location = Location {
        dir: Dir::open_ambient_dir(&root, cap_std::ambient_authority()).map_err(io_error)?,
        path: std::fs::canonicalize(&root).map_err(io_error)?,
        missing: Vec::new(),
    };
    for name in names {
        if !location.missing.is_empty() {
            location.missing.push(name);
            continue;
        }
        match location.dir.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => location.missing.push(name),
            Err(error) => return Err(io_error(error)),
            Ok(metadata) => {
                // Only fixed OS aliases may be resolved; user-controlled links
                // are not followed even when the selected spelling ends in '/'.
                #[cfg(target_os = "macos")]
                if location.path == Path::new("/")
                    && matches!(name.as_str(), "var" | "tmp" | "etc")
                    && metadata.file_type().is_symlink()
                {
                    let resolved =
                        std::fs::canonicalize(location.path.join(&name)).map_err(io_error)?;
                    location.dir = Dir::open_ambient_dir(&resolved, cap_std::ambient_authority())
                        .map_err(io_error)?;
                    location.path = resolved;
                    continue;
                }
                if !safe_directory(&metadata) {
                    return Err(invalid());
                }
                location.dir = location.dir.open_dir_nofollow(&name).map_err(io_error)?;
                location.path.push(name);
            }
        }
    }
    Ok(location)
}

pub(super) fn open_directory(path: &Path) -> Result<Dir, ConfigError> {
    let location = walk(path)?;
    if !location.missing.is_empty() {
        return Err(ConfigError("output_unavailable"));
    }
    Ok(location.dir)
}

fn safe_directory(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_dir() && !metadata.file_type().is_symlink() && !reparse(metadata)
}

fn reparse(metadata: &cap_std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn directory_identity(dir: &Dir) -> Result<String, ConfigError> {
    let file = dir.try_clone().map_err(io_error)?.into_std_file();
    let id =
        crate::platform::file_identity(&file).map_err(|_| ConfigError("output_unavailable"))?;
    Ok(format!("{:x}", Sha256::digest(id.as_bytes())))
}

pub(super) fn open_regular(dir: &Dir, name: &str) -> Result<Option<File>, ConfigError> {
    let before = match dir.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    if !before.is_file() || before.file_type().is_symlink() || reparse(&before) {
        return Err(invalid());
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = dir.open_with(name, &options).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || reparse(&metadata) || metadata.nlink() != 1 {
        return Err(invalid());
    }
    Ok(Some(file.into_std()))
}

fn target_identity(dir: &Dir, name: &str) -> Result<Option<String>, ConfigError> {
    let Some(file) = open_regular(dir, name)? else {
        return Ok(None);
    };
    file_fingerprint(&file).map(Some)
}

/// Stable object metadata bound to its native full-width identity.
pub(super) fn snapshot_identity(file: &File) -> Result<String, ConfigError> {
    file_fingerprint(file).map(|identity| snapshot_fingerprint(&identity))
}

pub(super) fn snapshot_fingerprint(identity: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"agent-remote:wireguard:file-snapshot:v1\0");
    hash.update(identity.as_bytes());
    format!("{:x}", hash.finalize())
}

// Preserve existing config.plan output identities across protocol versions.
fn file_fingerprint(file: &File) -> Result<String, ConfigError> {
    let id = crate::platform::file_identity(file).map_err(|_| ConfigError("output_unavailable"))?;
    let metadata = file.metadata().map_err(io_error)?;
    let modified = metadata
        .modified()
        .map_err(io_error)?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_nanos();
    let mut hash = Sha256::new();
    hash.update(format!("{id}:{}:{modified}", metadata.len()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hash.update(format!(
            ":{}:{}:{}:{}:{}",
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.mode(),
            metadata.uid(),
            metadata.gid()
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        hash.update(format!(
            ":{}:{}",
            metadata.creation_time(),
            metadata.file_attributes()
        ));
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(super) fn inspect(path: &Path) -> Result<OutputPlan, ConfigError> {
    let path = absolute(path)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid)?;
    if name.starts_with(".agent-remote-wireguard-") {
        return Err(invalid());
    }
    let parent = path.parent().ok_or_else(invalid)?;
    let location = walk(parent)?;
    let mut resolved = location.path.clone();
    for part in &location.missing {
        resolved.push(part);
    }
    resolved.push(name);
    let target = if location.missing.is_empty() {
        target_identity(&location.dir, name)?
    } else {
        None
    };
    Ok(OutputPlan {
        path: resolved,
        action: if target.is_some() {
            OutputAction::Replace
        } else {
            OutputAction::Create
        },
        anchor_identity: directory_identity(&location.dir)?,
        anchor_path: location.path,
        missing_directories: location.missing,
        target_identity: target,
    })
}

pub(super) struct PreparedOutput {
    dir: Dir,
    parent_path: PathBuf,
    parent_identity: String,
    name: String,
    expected: Option<String>,
    temporary_name: String,
    file: File,
    _lock: File,
}

#[derive(Debug)]
pub(super) struct PublishError {
    pub code: &'static str,
    pub published: bool,
}
impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for PublishError {}

impl PreparedOutput {
    pub(super) fn prepare(plan: &OutputPlan, canceled: &AtomicBool) -> Result<Self, ConfigError> {
        if inspect(&plan.path)? != *plan {
            return Err(ConfigError("output_changed"));
        }
        let mut location = walk(&plan.anchor_path)?;
        if !location.missing.is_empty()
            || directory_identity(&location.dir)? != plan.anchor_identity
        {
            return Err(ConfigError("output_changed"));
        }
        for name in &plan.missing_directories {
            canceled_check(canceled)?;
            let builder = cap_std::fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use cap_std::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            location
                .dir
                .create_dir_with(name, &builder)
                .map_err(io_error)?;
            location.dir = location.dir.open_dir_nofollow(name).map_err(io_error)?;
            location.path.push(name);
        }
        let lock = publication_lock(&location.dir, canceled)?;
        let name = plan
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(invalid)?
            .to_owned();
        if target_identity(&location.dir, &name)? != plan.target_identity {
            return Err(ConfigError("output_changed"));
        }
        let mut random = [0_u8; 32];
        rand_core::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| ConfigError("output_unavailable"))?;
        let temporary_name = format!(".agent-remote-wireguard-{:x}.tmp", Sha256::digest(random));
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt;
            // GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC.
            options.access_mode(0xC006_0000);
        }
        let file = location
            .dir
            .open_with(&temporary_name, &options)
            .map_err(io_error)?
            .into_std();
        if crate::platform::set_private_wireguard_file_permissions(&file).is_err() {
            let _ = location.dir.remove_file(&temporary_name);
            return Err(ConfigError("output_unavailable"));
        }
        Ok(Self {
            parent_identity: directory_identity(&location.dir)?,
            dir: location.dir,
            parent_path: location.path,
            name,
            expected: plan.target_identity.clone(),
            temporary_name,
            file,
            _lock: lock,
        })
    }

    pub(super) fn verify(&self) -> Result<(), ConfigError> {
        let current =
            open_directory(&self.parent_path).map_err(|_| ConfigError("output_changed"))?;
        if directory_identity(&current).ok().as_ref() != Some(&self.parent_identity)
            || target_identity(&self.dir, &self.name).ok().as_ref() != Some(&self.expected)
        {
            return Err(ConfigError("output_changed"));
        }
        Ok(())
    }

    pub(super) fn publish(
        &mut self,
        contents: &str,
        canceled: &AtomicBool,
    ) -> Result<(), PublishError> {
        let fail = |code| PublishError {
            code,
            published: false,
        };
        canceled_check(canceled).map_err(|_| fail("wireguard_outcome_unknown"))?;
        self.file
            .write_all(contents.as_bytes())
            .map_err(|_| fail("wireguard_publication_incomplete"))?;
        self.file
            .sync_all()
            .map_err(|_| fail("wireguard_publication_incomplete"))?;
        self.verify().map_err(|_| fail("output_changed"))?;
        canceled_check(canceled).map_err(|_| fail("wireguard_outcome_unknown"))?;
        if self.expected.is_none() {
            self.dir
                .hard_link(&self.temporary_name, &self.dir, &self.name)
                .map_err(|error| {
                    fail(if error.kind() == io::ErrorKind::AlreadyExists {
                        "output_changed"
                    } else {
                        "wireguard_publication_incomplete"
                    })
                })?;
            self.dir
                .remove_file(&self.temporary_name)
                .map_err(|_| PublishError {
                    code: "wireguard_publication_incomplete",
                    published: true,
                })?;
        } else {
            self.dir
                .rename(&self.temporary_name, &self.dir, &self.name)
                .map_err(|_| fail("wireguard_publication_incomplete"))?;
        }
        #[cfg(unix)]
        crate::platform::sync_directory(&self.dir).map_err(|_| PublishError {
            code: "wireguard_publication_incomplete",
            published: true,
        })?;
        Ok(())
    }
}

impl Drop for PreparedOutput {
    fn drop(&mut self) {
        let _ = self.dir.remove_file(&self.temporary_name);
    }
}

fn publication_lock(dir: &Dir, canceled: &AtomicBool) -> Result<File, ConfigError> {
    let name = ".agent-remote-wireguard-publication.lock";
    if let Ok(metadata) = dir.symlink_metadata(name) {
        if !metadata.is_file() || metadata.file_type().is_symlink() || reparse(&metadata) {
            return Err(invalid());
        }
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    let file = dir.open_with(name, &options).map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file()
        || file.metadata().map_err(io_error)?.nlink() != 1
    {
        return Err(invalid());
    }
    let file = file.into_std();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        canceled_check(canceled)?;
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(_) => return Err(ConfigError("operation_busy")),
        }
    }
}

fn canceled_check(canceled: &AtomicBool) -> Result<(), ConfigError> {
    if canceled.load(Ordering::Acquire) {
        Err(ConfigError("wireguard_outcome_unknown"))
    } else {
        Ok(())
    }
}
