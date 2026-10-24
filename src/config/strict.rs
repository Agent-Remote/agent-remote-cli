//! Bounded descriptor-relative configuration reads for confirmed operations.

use std::io::Read;
use std::path::{Component, PathBuf};

use anyhow::{bail, Context, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};

use super::{AppPaths, Config};

impl Config {
    /// Does not follow the managed home or config leaf, read special files, or
    /// allocate unbounded input. System ancestor aliases remain supported.
    pub fn load_strict(paths: &AppPaths) -> Result<Self> {
        let home: PathBuf = std::path::absolute(paths.home())?.components().collect();
        if home
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            bail!("configuration home contains parent traversal")
        }
        let parent = home
            .parent()
            .context("configuration home parent is missing")?;
        let name = home
            .file_name()
            .context("configuration home name is missing")?;
        let parent = Dir::open_ambient_dir(parent, cap_std::ambient_authority())
            .context("configuration parent is unavailable")?;
        let home = parent
            .open_dir_nofollow(name)
            .context("configuration home is unsafe or unavailable")?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = home
            .open_with("config.toml", &options)
            .context("configuration file is unavailable")?
            .into_std();
        crate::platform::validate_single_regular_file(&file)?;
        if file.metadata()?.len() > 64 * 1024 {
            bail!("configuration exceeds size limit")
        }
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 64 * 1024 {
            bail!("configuration exceeds size limit")
        }
        toml::from_str(std::str::from_utf8(&bytes).context("configuration is not UTF-8")?)
            .context("configuration is invalid")
    }
}

/// Lock an already existing home without initializing unrelated directories.
/// Descriptor-relative opens prevent a replaced home/lock symlink from redirecting writes.
pub(crate) fn write_lock_existing(paths: &AppPaths) -> Result<std::fs::File> {
    let home = crate::setup::absolute_home(paths)?;
    let parent = home
        .parent()
        .context("configuration home parent is missing")?;
    let name = home
        .file_name()
        .context("configuration home name is missing")?;
    let parent = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    let home = parent.open_dir_nofollow(name)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    let lock = home.open_with("config-write.lock", &options)?.into_std();
    crate::platform::validate_single_regular_file(&lock)?;
    lock.try_lock().context("configuration is busy")?;
    Ok(lock)
}
