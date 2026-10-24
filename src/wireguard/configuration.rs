//! Shared local review and confirmed WireGuard enrollment/configuration workflow.

use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};

use crate::api::ApiClient;
use crate::auth;
use crate::config::{AppPaths, Config};
use crate::secrets::{wireguard_private_key_key, SecretStore, SecretValue};

pub use super::publication::{OutputAction, OutputPlan};
use super::{publication, validation};

#[derive(Clone, Copy, Debug)]
pub struct ConfigError(pub &'static str);
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ConfigError {}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigContext {
    pub server_url: String,
    pub active_device_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigPlan {
    pub plan_version: u32,
    pub home: PathBuf,
    pub context: ConfigContext,
    pub output: OutputPlan,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    NotChecked,
    Reused,
    Created,
    Unknown,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Enrollment {
    NotAttempted,
    Rejected,
    Confirmed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Publication {
    NotAttempted,
    Published,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct ConfigOutcome {
    pub home: PathBuf,
    pub context: ConfigContext,
    pub output_path: PathBuf,
    pub complete: bool,
    pub key_state: KeyState,
    pub enrollment: Enrollment,
    pub publication: Publication,
    pub code: &'static str,
    pub peer_count: Option<usize>,
    /// Public peer identity returned by the control plane.  Never contains a
    /// private key or the local secret-store reference.
    pub peer_id: Option<String>,
    pub peer_version: Option<u64>,
}

impl ConfigOutcome {
    fn new(plan: &ConfigPlan) -> Self {
        Self {
            home: plan.home.clone(),
            context: plan.context.clone(),
            output_path: plan.output.path.clone(),
            complete: false,
            key_state: KeyState::NotChecked,
            enrollment: Enrollment::NotAttempted,
            publication: Publication::NotAttempted,
            code: "credential_unavailable",
            peer_count: None,
            peer_id: None,
            peer_version: None,
        }
    }
    fn fail(mut self, code: &'static str) -> Self {
        self.code = code;
        self
    }
}

/// Review configuration and destination metadata without reading credentials or writing files.
pub fn plan(paths: &AppPaths, output: Option<&Path>) -> Result<ConfigPlan, ConfigError> {
    let home =
        crate::setup::absolute_home(paths).map_err(|_| ConfigError("configuration_unavailable"))?;
    let context = read_context(&home)?;
    let default = home.join("wireguard/agent-remote.conf");
    let output = publication::inspect(output.unwrap_or(&default))?;
    Ok(ConfigPlan {
        plan_version: 1,
        home,
        context,
        output,
    })
}

fn read_context(home: &Path) -> Result<ConfigContext, ConfigError> {
    let fail = || ConfigError("configuration_unavailable");
    let _home_dir = publication::open_directory(home).map_err(|_| fail())?;
    let paths = AppPaths::new(Some(home.to_path_buf())).map_err(|_| fail())?;
    let config = Config::load_strict(&paths).map_err(|error| {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            ConfigError("authentication_required")
        } else {
            fail()
        }
    })?;
    let context = ConfigContext {
        server_url: config
            .server_url
            .ok_or(ConfigError("authentication_required"))?,
        active_device_id: config
            .active_device_id
            .ok_or(ConfigError("authentication_required"))?,
    };
    let url = reqwest::Url::parse(&context.server_url).map_err(|_| fail())?;
    if context.server_url.len() > 2048
        || context.server_url.trim() != context.server_url
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || context.active_device_id.is_empty()
        || context.active_device_id.len() > 128
        || !context
            .active_device_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return Err(fail());
    }
    Ok(context)
}

struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Execute exactly the reviewed destination/context. A partial result preserves
/// known enrollment/publication facts; callers must never blindly retry it.
pub async fn apply(paths: &AppPaths, expected: &ConfigPlan) -> Result<ConfigOutcome, ConfigError> {
    apply_cancellable(paths, expected, Arc::new(AtomicBool::new(false))).await
}

pub async fn apply_cancellable(
    paths: &AppPaths,
    expected: &ConfigPlan,
    canceled: Arc<AtomicBool>,
) -> Result<ConfigOutcome, ConfigError> {
    if expected.plan_version != 1 {
        return Err(ConfigError("invalid_params"));
    }
    if (expected.output.action == OutputAction::Create) != expected.output.target_identity.is_none()
    {
        return Err(ConfigError("invalid_params"));
    }
    let actual = plan(paths, Some(&expected.output.path))?;
    if actual.home != expected.home || actual.context != expected.context {
        return Err(ConfigError("configuration_changed"));
    }
    if actual != *expected {
        return Err(ConfigError("output_changed"));
    }
    let _cancel_guard = CancelOnDrop(canceled.clone());
    let login_guard = auth::login::lock(paths)
        .await
        .map_err(|_| ConfigError("operation_busy"))?;
    let _identity_guard = auth::lock_wireguard_credentials(
        &expected.context.server_url,
        &expected.context.active_device_id,
        &canceled,
    )
    .await
    .map_err(|_| ConfigError("operation_busy"))?;
    let actual = plan(paths, Some(&expected.output.path))?;
    if actual.context != expected.context {
        return Err(ConfigError("configuration_changed"));
    }
    if actual != *expected {
        return Err(ConfigError("output_changed"));
    }
    let target_plan = expected.output.clone();
    let target_cancel = canceled.clone();
    let mut target = tokio::task::spawn_blocking(move || {
        publication::PreparedOutput::prepare(&target_plan, &target_cancel)
    })
    .await
    .map_err(|_| ConfigError("output_unavailable"))??;
    let mut outcome = ConfigOutcome::new(expected);
    let config = Config {
        server_url: Some(expected.context.server_url.clone()),
        active_device_id: Some(expected.context.active_device_id.clone()),
    };
    let credential = match auth::load_device_token_strict_locked(
        paths,
        &login_guard,
        &config,
        &canceled,
    )
    .await
    {
        Ok(credential) => credential,
        Err(_) => return Ok(outcome.fail("credential_unavailable")),
    };
    if credential.server_url != expected.context.server_url
        || credential.device_id != expected.context.active_device_id
    {
        return Err(ConfigError("configuration_changed"));
    }
    let client = ApiClient::new(credential.server_url.clone())
        .map_err(|_| ConfigError("configuration_unavailable"))?;
    let store = SecretStore::new(paths.clone());
    let key = wireguard_private_key_key(&credential.server_url, &credential.device_id);
    let private = match store.read_strict(&key, &canceled).await {
        Ok(Some(private)) => {
            outcome.key_state = KeyState::Reused;
            private
        }
        Ok(None) => {
            let private = SecretValue::new(super::generate_private_key())
                .map_err(|_| ConfigError("wireguard_outcome_unknown"))?;
            if store.write_strict(&key, &private, &canceled).await.is_err() {
                outcome.key_state = KeyState::Unknown;
                return Ok(outcome.fail("wireguard_key_store_incomplete"));
            }
            outcome.key_state = KeyState::Created;
            private
        }
        Err(_) => return Ok(outcome.fail("credential_unavailable")),
    };
    let public = match super::public_key_from_private(private.as_str()) {
        Ok(public) => public,
        Err(_) => {
            outcome.key_state = KeyState::NotChecked;
            return Ok(outcome.fail("wireguard_key_invalid"));
        }
    };
    if read_context(&expected.home).ok().as_ref() != Some(&expected.context) {
        return Ok(outcome.fail("wireguard_context_changed"));
    }
    if target.verify().is_err() {
        return Ok(outcome.fail("output_changed"));
    }
    // Freeze the server-side peer identity before the mutating enrollment. A
    // missing peer is the only case where an enrollment may omit expectations;
    // all existing peers must carry all three public concurrency tokens.
    let expected_peer = match client.get_wireguard_config(credential.token.as_str()).await {
        Ok(current) => {
            if validation::validate(&current, &expected.context.active_device_id).is_err()
                || current.peer_id.is_empty()
                || current.peer_id.len() > 128
                || !current
                    .peer_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                || !validation::public_key(&current.peer_public_key)
                || current.peer_version == 0
            {
                return Ok(outcome.fail("wireguard_config_invalid"));
            }
            Some((
                current.peer_id,
                current.peer_public_key,
                current.peer_version,
            ))
        }
        Err(error) if error.code() == Some("WIREGUARD_PEER_MISSING") => None,
        Err(_) => return Ok(outcome.fail("wireguard_config_unavailable")),
    };
    let receipt = match client
        .enroll_wireguard_peer_with_expected(
            credential.token.as_str(),
            &public,
            expected_peer.as_ref().map(|value| value.0.as_str()),
            expected_peer.as_ref().map(|value| value.1.as_str()),
            expected_peer.as_ref().map(|value| value.2),
        )
        .await
    {
        Ok(receipt)
            if receipt.device_id == expected.context.active_device_id
                && !receipt.peer_id.is_empty()
                && receipt.peer_id.len() <= 128
                && receipt
                    .peer_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                && receipt.peer_version > 0
                && validation::ip_or_network(&receipt.interface_address) =>
        {
            receipt
        }
        Ok(_) => {
            outcome.enrollment = Enrollment::Unknown;
            return Ok(outcome.fail("wireguard_enrollment_unknown"));
        }
        Err(error) => {
            let rejected = error
                .status_code()
                .is_some_and(|status| (400..500).contains(&status));
            outcome.enrollment = if rejected {
                Enrollment::Rejected
            } else {
                Enrollment::Unknown
            };
            return Ok(outcome.fail(if rejected {
                "wireguard_enrollment_rejected"
            } else {
                "wireguard_enrollment_unknown"
            }));
        }
    };
    outcome.enrollment = Enrollment::Confirmed;
    outcome.peer_id = Some(receipt.peer_id.clone());
    outcome.peer_version = Some(receipt.peer_version);
    let remote = match client.get_wireguard_config(credential.token.as_str()).await {
        Ok(config) => config,
        Err(_) => return Ok(outcome.fail("wireguard_config_unavailable")),
    };
    if validation::validate(&remote, &expected.context.active_device_id).is_err()
        || remote.interface_address != receipt.interface_address
        || remote.peer_id != receipt.peer_id
        || remote.peer_version != receipt.peer_version
        || remote.peer_public_key != public
    {
        return Ok(outcome.fail("wireguard_config_invalid"));
    }
    let rendered = match super::render_config(&remote, private.as_str()) {
        Ok(rendered) if rendered.len() <= 1024 * 1024 => rendered,
        _ => return Ok(outcome.fail("wireguard_config_invalid")),
    };
    if read_context(&expected.home).ok().as_ref() != Some(&expected.context) {
        return Ok(outcome.fail("wireguard_context_changed"));
    }
    outcome.peer_count = Some(remote.peers.len());
    // Keep all credential locks alive until the secret-bearing write actually
    // finishes. A detached blocking task could otherwise outlive cancellation.
    let published = if tokio::runtime::Handle::current().runtime_flavor()
        == tokio::runtime::RuntimeFlavor::MultiThread
    {
        tokio::task::block_in_place(|| target.publish(&rendered, &canceled))
    } else {
        target.publish(&rendered, &canceled)
    };
    match published {
        Ok(()) => {
            outcome.complete = true;
            outcome.code = "none";
            outcome.publication = Publication::Published;
        }
        Err(error) if error.code == "wireguard_outcome_unknown" => {
            return Err(ConfigError("wireguard_outcome_unknown"))
        }
        Err(error) => {
            outcome.code = error.code;
            outcome.publication = if error.published {
                Publication::Published
            } else if error.code == "output_changed" {
                Publication::NotAttempted
            } else {
                Publication::Failed
            };
        }
    }
    Ok(outcome)
}
