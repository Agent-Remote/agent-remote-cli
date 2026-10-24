//! Private bytes for a future authenticated execution bridge. This type does not
//! authorize execution and is never part of the desktop JSON protocol.

use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::configuration::ConfigError;
use super::inspection::{self, ConfigBinding, MAX_CONFIG_BYTES};
use super::{inspection_parser, validation};

/// Ownership clears the buffer on drop; intentionally not Debug/Serialize/Clone.
pub(crate) struct ExecutionConfig {
    bytes: Zeroizing<Vec<u8>>,
    binding: ConfigBinding,
}

impl ExecutionConfig {
    /// Called before elevation, under the source user's filesystem authority.
    /// Uses one content read: metadata rechecks never provide replacement bytes.
    pub(crate) fn from_source(path: &Path, expected: &ConfigBinding) -> Result<Self, ConfigError> {
        validate_binding(expected)?;
        let (inspection, snapshot) = inspection::read_snapshot(path)?;
        match inspection.state {
            "ready" => {}
            "unsupported" => return Err(ConfigError("wireguard_config_unsupported")),
            "invalid" => return Err(ConfigError("wireguard_config_invalid")),
            _ => return Err(ConfigError("wireguard_config_unavailable")),
        }
        let snapshot = snapshot.ok_or(ConfigError("wireguard_config_unavailable"))?;
        if snapshot.binding != *expected {
            return Err(ConfigError("wireguard_config_changed"));
        }
        Ok(Self {
            bytes: snapshot.bytes,
            binding: snapshot.binding,
        })
    }

    /// Revalidates a payload received through a future authenticated broker.
    /// No filesystem path is accepted or opened at elevated privilege. Source
    /// file identity is request metadata, not something transferred bytes prove.
    pub(crate) fn from_transfer(
        bytes: Vec<u8>,
        expected: &ConfigBinding,
    ) -> Result<Self, ConfigError> {
        let bytes = Zeroizing::new(bytes);
        validate_binding(expected)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError("wireguard_config_invalid"));
        }
        let summary = inspection_parser::parse(&bytes)
            .map_err(|_| ConfigError("wireguard_config_invalid"))?;
        if !summary.unsupported_directives.is_empty() {
            return Err(ConfigError("wireguard_config_unsupported"));
        }
        if format!("{:x}", Sha256::digest(bytes.as_slice())) != expected.content_sha256
            || summary.public_key != expected.public_key
        {
            return Err(ConfigError("wireguard_config_changed"));
        }
        Ok(Self {
            bytes,
            binding: expected.clone(),
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn binding(&self) -> &ConfigBinding {
        &self.binding
    }
}

fn validate_binding(binding: &ConfigBinding) -> Result<(), ConfigError> {
    let digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if !digest(&binding.file_identity)
        || !digest(&binding.content_sha256)
        || !validation::public_key(&binding.public_key)
    {
        return Err(ConfigError("wireguard_config_invalid"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_execution_config.rs"]
mod tests;
