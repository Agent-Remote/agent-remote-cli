use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

mod strict;
pub(crate) use strict::write_lock_existing;

#[derive(Clone, Debug)]
pub struct AppPaths {
    home: PathBuf,
}

impl AppPaths {
    pub fn new(home: Option<PathBuf>) -> Result<Self> {
        let home = match home {
            Some(path) => path,
            None => match env::var_os("AGENT_REMOTE_HOME") {
                Some(path) => PathBuf::from(path),
                None => crate::platform::default_app_home()?,
            },
        };
        Ok(Self { home })
    }

    #[cfg(test)]
    pub fn from_home(home: PathBuf) -> Self {
        Self { home }
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn config_path(&self) -> PathBuf {
        self.home.join("config.toml")
    }

    pub fn state_db_path(&self) -> PathBuf {
        self.home.join("state.sqlite3")
    }

    pub fn bin_dir(&self) -> PathBuf {
        self.home.join("bin")
    }

    pub fn wireguard_dir(&self) -> PathBuf {
        self.home.join("wireguard")
    }

    pub fn ssh_dir(&self) -> PathBuf {
        self.home.join("ssh")
    }

    pub fn wireguard_config_path(&self) -> PathBuf {
        self.wireguard_dir().join("agent-remote.conf")
    }

    pub fn dependencies_dir(&self) -> PathBuf {
        self.home.join("dependencies")
    }

    pub fn dependency_manifest_path(&self) -> PathBuf {
        self.dependencies_dir().join("manifest.json")
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.home.join("secrets")
    }

    pub fn ensure_base_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.home)
            .with_context(|| format!("failed to create {}", self.home.display()))?;
        fs::create_dir_all(self.bin_dir())?;
        fs::create_dir_all(self.dependencies_dir())?;
        fs::create_dir_all(self.secrets_dir())?;
        fs::create_dir_all(self.wireguard_dir())?;
        fs::create_dir_all(self.ssh_dir())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Config {
    pub server_url: Option<String>,
    pub active_device_id: Option<String>,
}

impl Config {
    pub fn load(paths: &AppPaths) -> Result<Self> {
        let path = paths.config_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config =
            toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
        Ok(config)
    }

    pub fn save(&self, paths: &AppPaths) -> Result<()> {
        let _guard = write_lock(paths)?;
        self.save_locked(paths)
    }

    /// Publish a login result only if another command has not switched context.
    pub fn save_if_unchanged(&self, paths: &AppPaths, expected: &Self) -> Result<()> {
        let _guard = write_lock(paths)?;
        if Self::load(paths)? != *expected {
            anyhow::bail!("configuration changed during login; inspect current status")
        }
        self.save_locked(paths)
    }

    fn save_locked(&self, paths: &AppPaths) -> Result<()> {
        use std::io::Write;
        paths.ensure_base_dirs()?;
        let raw = toml::to_string_pretty(self)?;
        let mut staged = tempfile::NamedTempFile::new_in(paths.home())?;
        crate::platform::set_owner_only_permissions(staged.path())?;
        staged.write_all(raw.as_bytes())?;
        staged.as_file().sync_all()?;
        staged
            .persist(paths.config_path())
            .map_err(|_| anyhow::anyhow!("failed to publish client configuration"))?;
        Ok(())
    }
}

pub(crate) fn write_lock(paths: &AppPaths) -> Result<fs::File> {
    paths.ensure_base_dirs()?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(paths.home().join("config-write.lock"))?;
    lock.try_lock()
        .map_err(|_| anyhow::anyhow!("configuration is busy; retry after the current operation"))?;
    Ok(lock)
}

#[cfg(test)]
#[path = "../tests/unit/src/config.rs"]
mod tests;
