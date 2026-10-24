//! Browser approval keeps the polling credential and issued tokens inside the CLI.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time::{sleep_until, timeout_at, Instant};
use uuid::Uuid;

use crate::api::{ApiClient, ApiError, CliLoginStart};
use crate::auth::login::{self, LoginStage, RegistrationOptions};
use crate::config::{AppPaths, Config};
use crate::local_state::LocalState;
use crate::secrets::SecretBackend;

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceCodeRequest {
    server_url: String,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingCliLogin {
    server_url: String,
    completion_request_id: String,
    user_code: String,
    expires_at_unix: u64,
    interval: u64,
}

fn pending_key(server: &str) -> String {
    format!("cli_login.pending.v1:{server}")
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    let input: DeviceCodeRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    let server = input.server_url.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(server).map_err(|_| Failure::new("invalid_params"))?;
    if !http_url(&url)
        || url.query().is_some()
        || input.device_name.as_ref().is_some_and(|name| {
            name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control)
        })
    {
        return Err(Failure::new("invalid_params"));
    }
    if let Some(key) = &input.wireguard_public_key {
        use base64::Engine;
        if base64::engine::general_purpose::STANDARD
            .decode(key)
            .ok()
            .is_none_or(|value| value.len() != 32)
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
    ensure_context(&paths, &expected)?;
    let client = ApiClient::new(server.to_owned()).map_err(|_| Failure::new("invalid_params"))?;
    let state = LocalState::open(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    state
        .init_schema()
        .map_err(|_| Failure::new("configuration_unavailable"))?;
    let key = pending_key(server);
    // A second process may only recover the exact prior completion key. It has
    // no device_code and therefore cannot poll or silently start a new login.
    if let Some(raw) = state
        .get_kv(&key)
        .map_err(|_| Failure::new("configuration_unavailable"))?
    {
        let pending: PendingCliLogin =
            serde_json::from_str(&raw).map_err(|_| Failure::new("login_outcome_unknown"))?;
        if pending.server_url != server
            || Uuid::parse_str(&pending.completion_request_id)
                .ok()
                .is_none_or(|id| id.to_string() != pending.completion_request_id)
        {
            return Err(Failure::new("login_outcome_unknown"));
        }
        if unix_now() >= pending.expires_at_unix {
            state
                .delete_kv(&key)
                .map_err(|_| Failure::new("login_persistence_incomplete"))?;
            return Err(Failure::new("login_expired"));
        }
        let token = client
            .recover_cli_login(&pending.completion_request_id)
            .await
            .map_err(recovery_error)?;
        drop(state);
        return finish_login(
            &paths,
            server,
            &expected,
            registration,
            &token,
            &key,
            request,
        )
        .await;
    }
    let started = Instant::now();
    let completion_request_id = Uuid::new_v4().to_string();
    let start = client
        .start_cli_login(Some(&completion_request_id))
        .await
        .map_err(login_error)?;
    validate_start(&start)?;
    if start
        .completion_request_id
        .as_deref()
        .is_some_and(|value| value != completion_request_id)
    {
        return Err(Failure::new("login_outcome_unknown"));
    }
    // Include HTTP transit time in the server lifetime, rather than extending it locally.
    let deadline = started + Duration::from_secs(start.expires_in);
    if Instant::now() >= deadline {
        return Err(Failure::new("login_expired"));
    }
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .div_ceil(1000)
        .max(1) as u64;
    state
        .set_kv(
            &key,
            &serde_json::to_string(&PendingCliLogin {
                server_url: server.to_owned(),
                completion_request_id: completion_request_id.clone(),
                user_code: start.user_code.clone(),
                expires_at_unix: unix_now().saturating_add(start.expires_in),
                interval: start.interval,
            })
            .map_err(|_| Failure::new("configuration_unavailable"))?,
        )
        .map_err(|_| Failure::new("configuration_unavailable"))?;
    super::transport::approval(
        request,
        json!({"user_code":start.user_code,
        "verification_url":start.verification_url,"expires_in":remaining,
        "interval":start.interval}),
    )?;
    let token = loop {
        ensure_context(&paths, &expected)?;
        if Instant::now() >= deadline {
            return Err(Failure::new("login_expired"));
        }
        // A lost in-flight completion can have consumed the code and issued a token.
        // Only an explicit pending response authorizes another poll of this code.
        match timeout_at(
            deadline,
            client.complete_cli_login(&start.device_code, Some(&completion_request_id)),
        )
        .await
        {
            Ok(Ok(token)) => break token,
            Ok(Err(error)) if error.is_pending_cli_login() => {
                sleep_until((Instant::now() + Duration::from_secs(start.interval)).min(deadline))
                    .await;
            }
            Ok(Err(error))
                if error.is_transport_error()
                    || error
                        .status_code()
                        .is_none_or(|status| !(400..500).contains(&status)) =>
            {
                match client.recover_cli_login(&completion_request_id).await {
                    Ok(token) => break token,
                    Err(recovery) if recovery.is_pending_cli_login() => continue,
                    Err(_) => return Err(Failure::new("login_outcome_unknown")),
                }
            }
            Ok(Err(error)) => return Err(login_error(error)),
            Err(_) => match client.recover_cli_login(&completion_request_id).await {
                Ok(token) => break token,
                Err(error) if error.code() == Some("AUTH_TOKEN_EXPIRED") => {
                    return Err(Failure::new("login_expired"));
                }
                Err(_) => return Err(Failure::new("login_outcome_unknown")),
            },
        }
    };
    drop(state);
    finish_login(
        &paths,
        server,
        &expected,
        registration,
        &token,
        &key,
        request,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn finish_login(
    paths: &AppPaths,
    server: &str,
    expected: &Config,
    registration: crate::auth::login::PreparedRegistration,
    token: &crate::api::AuthToken,
    pending_key: &str,
    request: &Request,
) -> Result<Value, Failure> {
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        login::finalize(paths, server, token, registration, Some(expected)),
    )
    .await
    .map_err(|_| Failure::new("login_outcome_unknown"))?
    .map_err(|error| {
        Failure::new(match error.downcast_ref::<LoginStage>() {
            Some(LoginStage::ContextChanged) => "configuration_changed",
            Some(LoginStage::AuthenticationUnknown) => "login_outcome_unknown",
            Some(LoginStage::RegistrationRejected) => "registration_rejected",
            Some(LoginStage::RegistrationUnknown) => "registration_outcome_unknown",
            Some(LoginStage::Persistence) | None => "login_persistence_incomplete",
        })
    })?;
    let state = LocalState::open(paths)
        .and_then(|state| {
            state.init_schema()?;
            Ok(state)
        })
        .map_err(|_| Failure::new("login_persistence_incomplete"))?;
    state
        .delete_kv(pending_key)
        .map_err(|_| Failure::new("login_persistence_incomplete"))?;
    Ok(
        json!({"operation_id":request.request_id,"server_url":server,
        "registered_device_id":result.device_id,"credential_backend":match result.backend {
            SecretBackend::System => "system", SecretBackend::File => "file" },
        "expires_in":result.expires_in}),
    )
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn ensure_context(paths: &AppPaths, expected: &Config) -> Result<(), Failure> {
    if Config::load(paths).map_err(|_| Failure::new("configuration_unavailable"))? != *expected {
        return Err(Failure::new("configuration_changed"));
    }
    Ok(())
}

fn http_url(url: &reqwest::Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn validate_start(start: &CliLoginStart) -> Result<(), Failure> {
    let url = reqwest::Url::parse(&start.verification_url)
        .map_err(|_| Failure::new("login_outcome_unknown"))?;
    if !http_url(&url)
        || start.verification_url.len() > 2048
        || start.verification_url.chars().any(char::is_control)
        || start.user_code.is_empty()
        || start.user_code.len() > 64
        || !start
            .user_code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || start.device_code.is_empty()
        || start.device_code.len() > 4096
        || start.device_code.chars().any(char::is_control)
        || start.user_code.contains(&start.device_code)
        || contains_polling_credential(&start.verification_url, &start.device_code)
        || !(1..=1800).contains(&start.expires_in)
        || !(1..=60).contains(&start.interval)
    {
        return Err(Failure::new("login_outcome_unknown"));
    }
    // The existing server uses only ?code=<user_code>. Do not forward other
    // server-supplied query values, which could contain credentials.
    if url
        .query_pairs()
        .any(|(key, value)| key != "code" || value != start.user_code)
    {
        return Err(Failure::new("login_outcome_unknown"));
    }
    Ok(())
}

fn contains_polling_credential(url: &str, credential: &str) -> bool {
    let mut bytes = url.as_bytes().to_vec();
    loop {
        if bytes
            .windows(credential.len())
            .any(|part| part == credential.as_bytes())
        {
            return true;
        }
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                    decoded.push(high * 16 + low);
                    index += 3;
                    continue;
                }
            }
            decoded.push(bytes[index]);
            index += 1;
        }
        // Nested percent encoding can be decoded by a browser, proxy or web app.
        // Every successful round shortens the already bounded 2048-byte URL.
        if decoded.len() == bytes.len() {
            return false;
        }
        bytes = decoded;
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn login_error(error: ApiError) -> Failure {
    Failure::new(
        if error.status_code() == Some(401) && error.code() == Some("AUTH_TOKEN_EXPIRED") {
            "login_expired"
        } else if error
            .status_code()
            .is_some_and(|status| (400..500).contains(&status))
        {
            "login_rejected"
        } else {
            "login_outcome_unknown"
        },
    )
}

fn recovery_error(error: ApiError) -> Failure {
    if error.is_pending_cli_login()
        || matches!(
            error.code(),
            Some("AUTH_CLI_COMPLETION_NOT_FOUND")
                | Some("UNKNOWN_RESULT")
                | Some("AUTH_CLI_COMPLETION_KEY_MISMATCH")
        )
    {
        return Failure::new("login_outcome_unknown");
    }
    login_error(error)
}
