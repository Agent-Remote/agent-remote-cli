use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SCHEMA_VERSION: u64 = 1;
const MAXIMUM_SERVER_URL_BYTES: usize = 2048;
const MAXIMUM_ACCESS_TOKEN_BYTES: usize = 4096;
const MAXIMUM_CREDENTIAL_LIFETIME_SECONDS: u64 = 90 * 24 * 60 * 60;
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "dev.agentremote.device.broker-credential";
#[cfg(target_os = "macos")]
const KEYCHAIN_ACCOUNT: &str = "active-device";

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
pub fn store_active_broker_credential(credential: &BrokerCredential) -> Result<bool> {
    credential.validate_at(unix_time_seconds()?)?;
    store_platform_credential(credential)
}

/// Reports whether this build requires the production shared Keychain path.
pub fn broker_credential_storage_required() -> bool {
    production_storage_required()
}

/// Reads and validates the active production Broker credential when configured.
pub fn load_active_broker_credential() -> Result<Option<BrokerCredential>> {
    let Some(data) = load_platform_credential()? else {
        return Ok(None);
    };
    let credential: BrokerCredential =
        serde_json::from_slice(&data).context("broker credential JSON is invalid")?;
    credential.validate_at(unix_time_seconds()?)?;
    Ok(Some(credential))
}

/// Deletes the active production Broker credential when configured.
pub fn delete_active_broker_credential() -> Result<bool> {
    delete_platform_credential()
}

/// Deletes the active Broker credential only when its fixed binding matches.
pub fn delete_broker_credential_if_matches(server_url: &str, device_id: &str) -> Result<bool> {
    let Some(data) = load_platform_credential()? else {
        return Ok(false);
    };
    let credential = match serde_json::from_slice::<BrokerCredential>(&data) {
        Ok(credential) => credential,
        Err(_) => return delete_active_broker_credential(),
    };
    if credential.server_url != server_url || credential.device_id != device_id {
        return Ok(false);
    }
    delete_active_broker_credential()
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
    production_access_group().is_some()
}

#[cfg(not(target_os = "macos"))]
fn production_storage_required() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn store_platform_credential(credential: &BrokerCredential) -> Result<bool> {
    use security_framework::passwords::set_generic_password_options;
    use security_framework::passwords_options::PasswordOptions;

    let Some(access_group) = production_access_group() else {
        return Ok(false);
    };
    let data = serde_json::to_vec(credential).context("failed to encode broker credential")?;
    let mut options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
    options.set_access_group(access_group);
    set_generic_password_options(&data, options)
        .context("failed to write shared Network Broker credential")?;
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
fn store_platform_credential(_: &BrokerCredential) -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "macos")]
fn load_platform_credential() -> Result<Option<Vec<u8>>> {
    use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};

    let Some(access_group) = production_access_group() else {
        return Ok(None);
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
fn load_platform_credential() -> Result<Option<Vec<u8>>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn delete_platform_credential() -> Result<bool> {
    use security_framework::item::{ItemClass, ItemSearchOptions};

    let Some(access_group) = production_access_group() else {
        return Ok(false);
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
fn delete_platform_credential() -> Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::BrokerCredential;

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
}
