use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::ApiClient;
use crate::auth::login::{self, LoginStage, RegistrationOptions};
use crate::config::{AppPaths, Config};
use crate::secrets::SecretBackend;

use super::{Failure, Request};

// Deliberately not Debug: passwords and MFA input must never appear in logs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordRequest {
    server_url: String,
    username: String,
    password: String,
    totp_code: Option<String>,
    device_name: Option<String>,
    ssh_public_key: Option<PathBuf>,
    wireguard_public_key: Option<String>,
    skip_device_registration: bool,
    confirmed: bool,
    expected_context: ExpectedContext,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedContext {
    server_url: Option<String>,
    active_device_id: Option<String>,
}

pub(super) async fn password(request: &Request) -> Result<Value, Failure> {
    let input: PasswordRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    let server = input.server_url.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(server).map_err(|_| Failure::new("invalid_params"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !text_valid(&input.username, 256)
        || input.password.is_empty()
        || input.password.len() > 16384
        || input.password.contains('\0')
        || input
            .totp_code
            .as_ref()
            .is_some_and(|value| !text_valid(value, 32))
        || input
            .device_name
            .as_ref()
            .is_some_and(|value| !text_valid(value, 256))
    {
        return Err(Failure::new("invalid_params"));
    }
    if let Some(key) = &input.wireguard_public_key {
        use base64::Engine;
        if base64::engine::general_purpose::STANDARD
            .decode(key)
            .ok()
            .is_none_or(|data| data.len() != 32)
        {
            return Err(Failure::new("invalid_params"));
        }
    }
    let registration = RegistrationOptions {
        device_name: input.device_name,
        ssh_public_key: input.ssh_public_key,
        wireguard_public_key: input.wireguard_public_key,
        skip_device_registration: input.skip_device_registration,
    }
    .prepare()
    .map_err(|_| Failure::new("ssh_public_key_required"))?;
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let expected = Config {
        server_url: input.expected_context.server_url,
        active_device_id: input.expected_context.active_device_id,
    };
    if Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))? != expected {
        return Err(Failure::new("configuration_changed"));
    }
    let client = ApiClient::new(server.to_owned()).map_err(|_| Failure::new("invalid_params"))?;
    let token = client
        .login_password(&input.username, &input.password, input.totp_code.as_deref())
        .await
        .map_err(|error| {
            Failure::new(
                if error
                    .status_code()
                    .is_some_and(|status| (400..500).contains(&status))
                {
                    "login_rejected"
                } else {
                    "login_outcome_unknown"
                },
            )
        })?;
    let result = login::finalize(&paths, server, &token, registration, Some(&expected))
        .await
        .map_err(|error| {
            Failure::new(match error.downcast_ref::<LoginStage>() {
                Some(LoginStage::ContextChanged) => "configuration_changed",
                Some(LoginStage::AuthenticationUnknown) => "login_outcome_unknown",
                Some(LoginStage::RegistrationRejected) => "registration_rejected",
                Some(LoginStage::RegistrationUnknown) => "registration_outcome_unknown",
                Some(LoginStage::Persistence) => "login_persistence_incomplete",
                None => "login_persistence_incomplete",
            })
        })?;
    Ok(
        json!({"operation_id":request.request_id, "server_url":server,
        "registered_device_id":result.device_id, "credential_backend":match result.backend { SecretBackend::System => "system", SecretBackend::File => "file" },
        "expires_in":result.expires_in}),
    )
}

fn text_valid(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
