use anyhow::Result;

use crate::api::ApiClient;
use crate::broker_credentials::{
    broker_credential_storage_required, load_active_broker_credential, BrokerCredential,
};
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
        let Some(server_url) = config.server_url.as_deref() else {
            status_line(
                "credential",
                false,
                "server URL is not configured; run agent-remote init/login",
            );
            return Ok(());
        };

        let Some(device_id) = config.active_device_id.as_deref() else {
            self.check_legacy_token(
                &user_token_key(server_url),
                "user token",
                "run agent-remote login --skip-device-registration to store a user token",
            );
            return Ok(());
        };

        let broker_credential = match load_active_broker_credential(&self.paths) {
            Ok(credential) => credential,
            Err(error) => {
                status_line(
                    "credential",
                    false,
                    format!(
                        "Device Broker credential is invalid or unreadable: {error}; run agent-remote login"
                    ),
                );
                return Ok(());
            }
        };

        match classify_broker_credential(
            server_url,
            device_id,
            broker_credential.as_ref(),
            broker_credential_storage_required(),
        ) {
            BrokerCredentialState::Matching => status_line(
                "credential",
                true,
                "Device Broker credential matches the configured server/device",
            ),
            BrokerCredentialState::MissingRequired => status_line(
                "credential",
                false,
                "Device Broker credential is missing for the configured device; run agent-remote login",
            ),
            BrokerCredentialState::BindingMismatch => status_line(
                "credential",
                false,
                "Device Broker credential belongs to a different server/device; run agent-remote login",
            ),
            BrokerCredentialState::MissingOptional => self.check_legacy_token(
                &device_token_key(server_url, device_id),
                "legacy device token",
                "run agent-remote login",
            ),
        }
        Ok(())
    }

    fn check_legacy_token(&self, key: &str, label: &str, missing_action: &str) {
        let store = SecretStore::new(self.paths.clone());
        match store.get_secret(key) {
            Ok(Some(_)) => status_line(
                "credential",
                true,
                format!("{label} found in the platform credential store or file fallback"),
            ),
            Ok(None) => status_line(
                "credential",
                false,
                format!("{label} is missing; {missing_action}"),
            ),
            Err(error) => status_line(
                "credential",
                false,
                format!("{label} could not be read: {error}; {missing_action}"),
            ),
        }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerCredentialState {
    Matching,
    MissingRequired,
    MissingOptional,
    BindingMismatch,
}

fn classify_broker_credential(
    server_url: &str,
    device_id: &str,
    credential: Option<&BrokerCredential>,
    storage_required: bool,
) -> BrokerCredentialState {
    match credential {
        Some(credential)
            if credential.server_url == server_url && credential.device_id == device_id =>
        {
            BrokerCredentialState::Matching
        }
        Some(_) => BrokerCredentialState::BindingMismatch,
        None if storage_required => BrokerCredentialState::MissingRequired,
        None => BrokerCredentialState::MissingOptional,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_broker_credential, BrokerCredential, BrokerCredentialState};

    const SERVER_URL: &str = "https://control.example.test";
    const DEVICE_ID: &str = "2cb933ce-b922-4ed7-b479-6ded90f09d2d";
    const OTHER_DEVICE_ID: &str = "b79126b5-5ae7-4f8f-8515-f365bffac72d";

    fn credential(server_url: &str, device_id: &str) -> BrokerCredential {
        BrokerCredential {
            schema_version: 1,
            server_url: server_url.to_string(),
            device_id: device_id.to_string(),
            access_token: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".to_string(),
            expires_at_unix: u64::MAX,
        }
    }

    #[test]
    fn matching_broker_credential_is_healthy() {
        let credential = credential(SERVER_URL, DEVICE_ID);
        assert_eq!(
            classify_broker_credential(SERVER_URL, DEVICE_ID, Some(&credential), true),
            BrokerCredentialState::Matching
        );
    }

    #[test]
    fn mismatched_broker_credential_is_reported() {
        let credential = credential(SERVER_URL, OTHER_DEVICE_ID);
        assert_eq!(
            classify_broker_credential(SERVER_URL, DEVICE_ID, Some(&credential), true),
            BrokerCredentialState::BindingMismatch
        );
    }

    #[test]
    fn required_broker_credential_cannot_fall_back_to_legacy_storage() {
        assert_eq!(
            classify_broker_credential(SERVER_URL, DEVICE_ID, None, true),
            BrokerCredentialState::MissingRequired
        );
    }

    #[test]
    fn optional_broker_credential_uses_legacy_storage() {
        assert_eq!(
            classify_broker_credential(SERVER_URL, DEVICE_ID, None, false),
            BrokerCredentialState::MissingOptional
        );
    }
}
