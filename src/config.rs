use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
                None => default_home()?,
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
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
        paths.ensure_base_dirs()?;
        let raw = toml::to_string_pretty(self)?;
        fs::write(paths.config_path(), raw)?;
        Ok(())
    }
}

fn default_home() -> Result<PathBuf> {
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config").join("agent-remote"))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{AppPaths, Config};

    #[test]
    fn saves_and_loads_config() {
        let dir = tempdir().unwrap();
        let paths = AppPaths::from_home(dir.path().join("agent-remote"));
        let config = Config {
            server_url: Some("https://example.test".to_string()),
            active_device_id: Some("dev_1".to_string()),
        };
        config.save(&paths).unwrap();

        let loaded = Config::load(&paths).unwrap();
        assert_eq!(loaded.server_url.as_deref(), Some("https://example.test"));
        assert_eq!(loaded.active_device_id.as_deref(), Some("dev_1"));
    }
}
