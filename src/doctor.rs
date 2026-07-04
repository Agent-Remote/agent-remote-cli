use anyhow::Result;

use crate::api::ApiClient;
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManager;
use crate::local_state::LocalState;
use crate::secrets::{device_token_key, user_token_key, SecretStore};

pub struct Doctor {
    paths: AppPaths,
}

impl Doctor {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub async fn run(&self, fix: bool) -> Result<()> {
        if fix {
            self.paths.ensure_base_dirs()?;
        }

        self.check_paths();
        let config = Config::load(&self.paths)?;
        self.check_config(&config);
        self.check_state(fix)?;
        self.check_token(&config)?;
        self.check_dependencies(fix)?;
        self.check_server(&config).await?;
        Ok(())
    }

    fn check_paths(&self) {
        status_line(
            "home",
            self.paths.home().exists(),
            self.paths.home().display(),
        );
        status_line(
            "bin",
            self.paths.bin_dir().exists(),
            self.paths.bin_dir().display(),
        );
        status_line(
            "dependencies",
            self.paths.dependencies_dir().exists(),
            self.paths.dependencies_dir().display(),
        );
        status_line(
            "wireguard",
            self.paths.wireguard_dir().exists(),
            self.paths.wireguard_dir().display(),
        );
    }

    fn check_config(&self, config: &Config) {
        status_line(
            "config",
            self.paths.config_path().exists(),
            self.paths.config_path().display(),
        );
        match &config.server_url {
            Some(server_url) => println!("ok server configured: {server_url}"),
            None => println!("warn server not configured"),
        }
        match &config.active_device_id {
            Some(device_id) => println!("ok active device configured: {device_id}"),
            None => println!("warn active device not configured"),
        }
    }

    fn check_state(&self, fix: bool) -> Result<()> {
        let state = LocalState::open(&self.paths)?;
        if fix {
            state.init_schema()?;
        }
        status_line(
            "sqlite",
            self.paths.state_db_path().exists(),
            self.paths.state_db_path().display(),
        );
        Ok(())
    }

    fn check_token(&self, config: &Config) -> Result<()> {
        let store = SecretStore::new(self.paths.clone());
        let token = match (&config.server_url, &config.active_device_id) {
            (Some(server_url), Some(device_id)) => {
                store.get_secret(&device_token_key(server_url, device_id))?
            }
            (Some(server_url), None) => store.get_secret(&user_token_key(server_url))?,
            (None, _) => None,
        };
        status_line(
            "credential",
            token.is_some(),
            "platform credential or file fallback token",
        );
        Ok(())
    }

    fn check_dependencies(&self, fix: bool) -> Result<()> {
        let manager = DependencyManager::new(self.paths.clone());
        if fix {
            manager.ensure_manifest()?;
        }
        status_line(
            "dependency manifest",
            self.paths.dependency_manifest_path().exists(),
            self.paths.dependency_manifest_path().display(),
        );
        for dependency in manager.check_all()? {
            let detail = format!(
                "{} at {} license {}; notice: {}",
                dependency.name,
                dependency.binary_path.display(),
                dependency.license,
                dependency.license_notice
            );
            status_line("dependency", dependency.installed, detail);
        }
        Ok(())
    }

    async fn check_server(&self, config: &Config) -> Result<()> {
        let Some(server_url) = &config.server_url else {
            println!("warn network server check skipped");
            return Ok(());
        };
        match ApiClient::new(server_url.clone())?.healthz().await {
            Ok(health) => println!("ok network server reachable: {}", health.status),
            Err(error) => println!("fail network server unreachable: {error}"),
        }
        Ok(())
    }
}

fn status_line(label: &str, ok: bool, detail: impl std::fmt::Display) {
    let status = if ok { "ok" } else { "warn" };
    println!("{status} {label}: {detail}");
}
