//! Fail-closed credential access for confirmed WireGuard operations.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{SecretBackend, SecretStore};

mod file;
mod system;
#[cfg(target_os = "macos")]
pub(crate) use file::read_private_home_file;

const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Intentionally has no Debug or Serialize implementation.
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: String) -> Result<Self, StrictSecretError> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.contains('\0') {
            return Err(StrictSecretError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictSecretError {
    Denied,
    Unavailable,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    TimedOut,
    Canceled,
    Invalid,
}

impl fmt::Display for StrictSecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "credential access denied",
            Self::Unavailable => "credential store unavailable",
            Self::TimedOut => "credential operation timed out",
            Self::Canceled => "credential operation canceled",
            Self::Invalid => "credential value, file or permissions are invalid",
        })
    }
}

impl std::error::Error for StrictSecretError {}

impl From<std::io::Error> for StrictSecretError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            Self::Denied
        } else {
            Self::Unavailable
        }
    }
}

pub(super) fn check_cancel(cancel: &AtomicBool) -> Result<(), StrictSecretError> {
    if cancel.load(Ordering::Acquire) {
        Err(StrictSecretError::Canceled)
    } else {
        Ok(())
    }
}

/// Native calls and synchronous file writes cannot outlive the caller's locks.
/// Native APIs have no forcible internal deadline: process termination is the
/// outer boundary, and does not prove the operating-system operation rolled back.
pub(crate) fn blocking_credential_operation<F, R>(operation: F) -> R
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(operation),
        _ => operation(),
    }
}

impl SecretStore {
    /// System errors never authorize fallback or generation of a replacement key.
    pub async fn read_strict(
        &self,
        key: &str,
        cancel: &AtomicBool,
    ) -> Result<Option<SecretValue>, StrictSecretError> {
        check_cancel(cancel)?;
        if self.prefer_system {
            if let Some(value) = system::read(key, cancel).await? {
                return Ok(Some(value));
            }
        }
        let result = blocking_credential_operation(|| file::read(self, key));
        check_cancel(cancel)?;
        result
    }

    /// Strict writes never switch backend after an uncertain system write.
    pub async fn write_strict(
        &self,
        key: &str,
        value: &SecretValue,
        cancel: &AtomicBool,
    ) -> Result<SecretBackend, StrictSecretError> {
        check_cancel(cancel)?;
        if self.prefer_system {
            system::write(key, value, cancel).await?;
            return Ok(SecretBackend::System);
        }
        blocking_credential_operation(|| file::write(self, key, value))?;
        check_cancel(cancel)?;
        Ok(SecretBackend::File)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/secrets_strict.rs"]
mod tests;
