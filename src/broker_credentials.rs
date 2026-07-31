#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::fs::OpenOptions;
#[cfg(target_os = "macos")]
use std::io::Write;
#[cfg(target_os = "macos")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::AppPaths;

const SCHEMA_VERSION: u64 = 1;
const MAXIMUM_SERVER_URL_BYTES: usize = 2048;
const MAXIMUM_ACCESS_TOKEN_BYTES: usize = 4096;
const MAXIMUM_CREDENTIAL_LIFETIME_SECONDS: u64 = 90 * 24 * 60 * 60;
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "dev.agentremote.device.broker-credential";
#[cfg(target_os = "macos")]
const KEYCHAIN_ACCOUNT: &str = "active-device";
#[cfg(target_os = "macos")]
const COMMUNITY_CREDENTIAL_FILENAME: &str = "device-broker-credential.json";
#[cfg(target_os = "macos")]
const CREDENTIAL_MODE: Option<&str> = option_env!("AGENT_REMOTE_DEVICE_CREDENTIAL_MODE");

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCredential {
    pub schema_version: u64,
    pub server_url: String,
    pub device_id: String,
    pub access_token: String,
    pub expires_at_unix: u64,
}

impl BrokerCredential {
    /// Creates one bounded credential for the active Network Broker device.
    pub fn new(
        server_url: &str,
        device_id: &str,
        access_token: &str,
        expires_in: u64,
    ) -> Result<Self> {
        let now = unix_time_seconds()?;
        let credential = Self {
            schema_version: SCHEMA_VERSION,
            server_url: server_url.to_string(),
            device_id: device_id.to_string(),
            access_token: access_token.to_string(),
            expires_at_unix: now
                .checked_add(expires_in)
                .context("device credential expiry overflowed")?,
        };
        credential.validate_at(now)?;
        Ok(credential)
    }

    /// Validates the fixed endpoint, canonical device identity, token, and lifetime.
    pub fn validate_at(&self, now: u64) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!("unsupported broker credential schema version")
        }
        if self.server_url.is_empty()
            || self.server_url.len() > MAXIMUM_SERVER_URL_BYTES
            || self.server_url.trim() != self.server_url
            || self.server_url.ends_with('/')
        {
            bail!("broker server URL is not normalized")
        }
        let endpoint = reqwest::Url::parse(&self.server_url)
            .context("broker server URL is not a valid absolute URL")?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            bail!("broker server URL must be an HTTPS origin")
        }
        let device_id = Uuid::parse_str(&self.device_id).context("device ID is not a UUID")?;
        if device_id.to_string() != self.device_id {
            bail!("device ID is not a canonical lowercase UUID")
        }
        if self.access_token.len() < 32
            || self.access_token.len() > MAXIMUM_ACCESS_TOKEN_BYTES
            || !self
                .access_token
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
        {
            bail!("device access token is malformed")
        }
        let remaining = self
            .expires_at_unix
            .checked_sub(now)
            .context("device credential has expired")?;
        if remaining == 0 || remaining > MAXIMUM_CREDENTIAL_LIFETIME_SECONDS {
            bail!("device credential lifetime is invalid")
        }
        Ok(())
    }
}

/// Writes the active credential only when this macOS build has a fixed access group.
pub fn store_active_broker_credential(
    paths: &AppPaths,
    credential: &BrokerCredential,
) -> Result<bool> {
    credential.validate_at(unix_time_seconds()?)?;
    store_platform_credential(paths, credential)
}

/// Reports whether this build requires the production shared Keychain path.
pub fn broker_credential_storage_required() -> bool {
    production_storage_required()
}

/// Reads and validates the active production Broker credential when configured.
pub fn load_active_broker_credential(paths: &AppPaths) -> Result<Option<BrokerCredential>> {
    let Some(data) = load_platform_credential(paths)? else {
        return Ok(None);
    };
    let credential: BrokerCredential =
        serde_json::from_slice(&data).context("broker credential JSON is invalid")?;
    credential.validate_at(unix_time_seconds()?)?;
    Ok(Some(credential))
}

/// Deletes the active production Broker credential when configured.
pub fn delete_active_broker_credential(paths: &AppPaths) -> Result<bool> {
    delete_platform_credential(paths)
}

/// Deletes the active Broker credential only when its fixed binding matches.
pub fn delete_broker_credential_if_matches(
    paths: &AppPaths,
    server_url: &str,
    device_id: &str,
) -> Result<bool> {
    let Some(data) = load_platform_credential(paths)? else {
        return Ok(false);
    };
    let credential = match serde_json::from_slice::<BrokerCredential>(&data) {
        Ok(credential) => credential,
        Err(_) => return delete_active_broker_credential(paths),
    };
    if credential.server_url != server_url || credential.device_id != device_id {
        return Ok(false);
    }
    delete_active_broker_credential(paths)
}

fn unix_time_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

#[cfg(target_os = "macos")]
fn production_access_group() -> Option<&'static str> {
    option_env!("AGENT_REMOTE_KEYCHAIN_ACCESS_GROUP").filter(|value| {
        let Some((team_identifier, suffix)) = value.split_once('.') else {
            return false;
        };
        team_identifier.len() == 10
            && team_identifier
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            && suffix == "dev.agentremote.device.credentials"
    })
}

#[cfg(target_os = "macos")]
fn production_storage_required() -> bool {
    production_access_group().is_some() || CREDENTIAL_MODE == Some("community-file")
}

#[cfg(not(target_os = "macos"))]
fn production_storage_required() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn store_platform_credential(paths: &AppPaths, credential: &BrokerCredential) -> Result<bool> {
    use security_framework::passwords::set_generic_password_options;
    use security_framework::passwords_options::PasswordOptions;

    let data = serde_json::to_vec(credential).context("failed to encode broker credential")?;
    if let Some(access_group) = production_access_group() {
        let mut options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
        options.set_access_group(access_group);
        set_generic_password_options(&data, options)
            .context("failed to write shared Network Broker credential")?;
        return Ok(true);
    }
    if CREDENTIAL_MODE != Some("community-file") {
        return Ok(false);
    }
    store_community_credential(paths, &data)?;
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
fn store_platform_credential(_: &AppPaths, _: &BrokerCredential) -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "macos")]
fn load_platform_credential(paths: &AppPaths) -> Result<Option<Vec<u8>>> {
    use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};

    let Some(access_group) = production_access_group() else {
        return if CREDENTIAL_MODE == Some("community-file") {
            load_community_credential(paths)
        } else {
            Ok(None)
        };
    };
    let result = ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(KEYCHAIN_SERVICE)
        .account(KEYCHAIN_ACCOUNT)
        .access_group(access_group)
        .load_data(true)
        .search();
    match result {
        Ok(results) => match results.as_slice() {
            [SearchResult::Data(data)] => Ok(Some(data.clone())),
            [] => Ok(None),
            _ => bail!("shared Network Broker credential query was ambiguous"),
        },
        Err(error) if error.code() == -25300 => Ok(None),
        Err(error) => Err(error).context("failed to read shared Network Broker credential"),
    }
}

#[cfg(not(target_os = "macos"))]
fn load_platform_credential(_: &AppPaths) -> Result<Option<Vec<u8>>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn delete_platform_credential(paths: &AppPaths) -> Result<bool> {
    use security_framework::item::{ItemClass, ItemSearchOptions};

    let Some(access_group) = production_access_group() else {
        return if CREDENTIAL_MODE == Some("community-file") {
            delete_community_credential(paths)
        } else {
            Ok(false)
        };
    };
    let result = ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(KEYCHAIN_SERVICE)
        .account(KEYCHAIN_ACCOUNT)
        .access_group(access_group)
        .delete();
    match result {
        Ok(()) => Ok(true),
        Err(error) if error.code() == -25300 => Ok(true),
        Err(error) => Err(error).context("failed to delete shared Network Broker credential"),
    }
}

#[cfg(not(target_os = "macos"))]
fn delete_platform_credential(_: &AppPaths) -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "macos")]
fn community_credential_path(paths: &AppPaths) -> std::path::PathBuf {
    paths.home().join(COMMUNITY_CREDENTIAL_FILENAME)
}

#[cfg(target_os = "macos")]
fn store_community_credential(paths: &AppPaths, data: &[u8]) -> Result<()> {
    paths.ensure_base_dirs()?;
    let path = community_credential_path(paths);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let temporary = paths.home().join(format!(
        ".{COMMUNITY_CREDENTIAL_FILENAME}.{}-{}.tmp",
        std::process::id(),
        nonce
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(target_os = "macos")]
fn load_community_credential(paths: &AppPaths) -> Result<Option<Vec<u8>>> {
    let path = community_credential_path(paths);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
        }
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > 16 * 1024
    {
        bail!("community Network Broker credential file is unsafe")
    }
    fs::read(&path)
        .map(Some)
        .with_context(|| format!("failed to read {}", path.display()))
}

#[cfg(target_os = "macos")]
fn delete_community_credential(paths: &AppPaths) -> Result<bool> {
    let path = community_credential_path(paths);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            Ok(true)
        }
        Ok(_) => bail!("refusing to remove an unsafe community credential path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::BrokerCredential;
    #[cfg(target_os = "macos")]
    use super::{load_community_credential, store_community_credential};
    #[cfg(target_os = "macos")]
    use crate::config::AppPaths;

    const DEVICE_ID: &str = "2cb933ce-b922-4ed7-b479-6ded90f09d2d";
    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    #[test]
    fn validates_a_bounded_https_origin_credential() {
        let credential = BrokerCredential {
            schema_version: 1,
            server_url: "https://control.example.test:8443".to_string(),
            device_id: DEVICE_ID.to_string(),
            access_token: TOKEN.to_string(),
            expires_at_unix: 1_100,
        };
        credential.validate_at(1_000).unwrap();
        let encoded = serde_json::to_vec(&credential).unwrap();
        assert_eq!(
            serde_json::from_slice::<BrokerCredential>(&encoded).unwrap(),
            credential
        );
    }

    #[test]
    fn rejects_endpoint_overrides_expired_tokens_and_unknown_fields() {
        for server_url in [
            "http://control.example.test",
            "https://user@control.example.test",
            "https://control.example.test/api",
            "https://control.example.test?next=evil",
            "https://control.example.test/",
        ] {
            let credential = BrokerCredential {
                schema_version: 1,
                server_url: server_url.to_string(),
                device_id: DEVICE_ID.to_string(),
                access_token: TOKEN.to_string(),
                expires_at_unix: 1_100,
            };
            assert!(
                credential.validate_at(1_000).is_err(),
                "accepted {server_url}"
            );
        }
        let expired = BrokerCredential {
            schema_version: 1,
            server_url: "https://control.example.test".to_string(),
            device_id: DEVICE_ID.to_string(),
            access_token: TOKEN.to_string(),
            expires_at_unix: 999,
        };
        assert!(expired.validate_at(1_000).is_err());
        let unknown = format!(
            r#"{{"schema_version":1,"server_url":"https://control.example.test","device_id":"{DEVICE_ID}","access_token":"{TOKEN}","expires_at_unix":1100,"endpoint":"https://evil.test"}}"#
        );
        assert!(serde_json::from_str::<BrokerCredential>(&unknown).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn community_credential_file_is_owner_only_and_round_trips() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_home(directory.path().join("agent-remote"));
        let data = br#"{"schema_version":1}"#;
        store_community_credential(&paths, data).unwrap();

        let path = paths.home().join("device-broker-credential.json");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_community_credential(&paths).unwrap(),
            Some(data.to_vec())
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_community_credential(&paths).is_err());
    }
}
