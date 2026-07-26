use anyhow::Result;

use crate::api::ApiClient;
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManager;
use crate::local_state::LocalState;
use crate::secrets::{device_token_key, user_token_key, SecretStore};
use crate::terminal;

pub struct Doctor {
    paths: AppPaths,
}

impl Doctor {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub async fn run(&self, fix: bool) -> Result<()> {
        terminal::section("Agent Remote Doctor");
        if fix {
            self.paths.ensure_base_dirs()?;
        }

        self.check_paths();
        let config = Config::load(&self.paths)?;
        self.check_config(&config);
        self.check_state(fix)?;
        self.check_token(&config)?;
        self.check_dependencies(fix)?;
        #[cfg(windows)]
        self.check_windows_tools();
        self.check_server(&config).await?;
        Ok(())
    }

    #[cfg(windows)]
    fn check_windows_tools(&self) {
        status_line(
            "OpenSSH Client",
            crate::platform::windows_openssh_path("ssh").is_some(),
            "Windows OpenSSH Client optional feature",
        );
        status_line(
            "system scp",
            crate::platform::windows_openssh_path("scp").is_some(),
            "Windows OpenSSH scp.exe",
        );
        status_line(
            "WireGuard for Windows",
            crate::platform::windows_wireguard_path().is_some(),
            "official WireGuard tunnel service manager",
        );
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
            Some(server_url) => terminal::success_line(format!("Server configured: {server_url}")),
            None => terminal::warning_line("Server is not configured"),
        }
        match &config.active_device_id {
            Some(device_id) => {
                terminal::success_line(format!("Active device configured: {device_id}"))
            }
            None => terminal::warning_line("Active device is not configured"),
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
            terminal::warning_line("Network server check skipped");
            return Ok(());
        };
        match ApiClient::new(server_url.clone())?.healthz().await {
            Ok(health) => {
                terminal::success_line(format!("Network server reachable: {}", health.status))
            }
            Err(error) => terminal::failure_line(format!("Network server unreachable: {error}")),
        }
        Ok(())
    }
}

fn status_line(label: &str, ok: bool, detail: impl std::fmt::Display) {
    let message = format!("{label}: {detail}");
    if ok {
        terminal::success_line(message);
    } else {
        terminal::warning_line(message);
    }
}
