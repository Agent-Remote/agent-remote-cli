//! Reviewed developer-credential profile mutations.
//!
//! The desktop protocol carries profile metadata and exact identifiers only.
//! Device credentials remain inside the CLI's locked secure storage.  The
//! request types deny unknown fields so a future secret-bearing field cannot be
//! silently accepted through this boundary.

use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    account_defaults::Context,
    account_operations,
    api::{
        CreateDeveloperCredentialProfileRequest, DeveloperCredentialGitHubCli,
        DeveloperCredentialGitIdentity, DeveloperCredentialSsh,
    },
    config::AppPaths,
};

use super::{Failure, Request};

const CREATE: &str = "credentials.create";
const BIND: &str = "credentials.bind";
const UNBIND: &str = "credentials.unbind";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    confirmed: bool,
    expected_context: Context,
    display_name: String,
    #[serde(default)]
    git_user_name: Option<String>,
    #[serde(default)]
    git_user_email: Option<String>,
    gh_mode: String,
    ssh_mode: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingRequest {
    confirmed: bool,
    expected_context: Context,
    account_id: String,
    profile_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnbindRequest {
    confirmed: bool,
    expected_context: Context,
    account_id: String,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    match request.method.as_str() {
        CREATE => {
            let input: CreateRequest = serde_json::from_value(request.params.clone())
                .map_err(|_| Failure::new("invalid_params"))?;
            if !input.confirmed
                || !valid_context(&paths, &input.expected_context)
                || !valid_text(&input.display_name, 256)
                || !valid_optional_text(input.git_user_name.as_deref(), 256)
                || !valid_optional_text(input.git_user_email.as_deref(), 320)
                || !valid_gh_mode(&input.gh_mode)
                || !valid_ssh_mode(&input.ssh_mode)
            {
                return Err(Failure::new("invalid_params"));
            }
            let authority = account_operations::authorize(&paths, &input.expected_context)
                .await
                .map_err(operation_failure)?;
            let expected_display_name = input.display_name.clone();
            let expected_gh_mode = input.gh_mode.clone();
            let expected_ssh_mode = input.ssh_mode.clone();
            let profile = authority
                .client
                .create_developer_credential_profile(
                    authority.token.token.as_str(),
                    &CreateDeveloperCredentialProfileRequest {
                        display_name: input.display_name,
                        git_identity: DeveloperCredentialGitIdentity {
                            user_name: input.git_user_name,
                            user_email: input.git_user_email,
                        },
                        github_cli: DeveloperCredentialGitHubCli {
                            mode: input.gh_mode,
                        },
                        ssh: DeveloperCredentialSsh {
                            mode: input.ssh_mode,
                        },
                    },
                )
                .await
                .map_err(api_failure)?;
            if profile.display_name != expected_display_name
                || profile.github_cli_mode != expected_gh_mode
                || profile.ssh_mode != expected_ssh_mode
            {
                return Err(Failure::new("credential_outcome_unknown"));
            }
            let profile = projection(profile)?;
            Ok(receipt(
                request,
                input.expected_context,
                "create",
                None,
                Some(profile),
            ))
        }
        BIND => {
            let input: BindingRequest = serde_json::from_value(request.params.clone())
                .map_err(|_| Failure::new("invalid_params"))?;
            if !input.confirmed
                || !valid_context(&paths, &input.expected_context)
                || !account_operations::valid_id(&input.account_id)
                || !account_operations::valid_id(&input.profile_id)
            {
                return Err(Failure::new("invalid_params"));
            }
            let authority = account_operations::authorize(&paths, &input.expected_context)
                .await
                .map_err(operation_failure)?;
            let profile = authority
                .client
                .bind_developer_credential_profile(
                    authority.token.token.as_str(),
                    &input.account_id,
                    &input.profile_id,
                )
                .await
                .map_err(api_failure)?;
            let profile = projection(profile)?;
            if profile["id"] != input.profile_id {
                return Err(Failure::new("credential_outcome_unknown"));
            }
            Ok(receipt(
                request,
                input.expected_context,
                "bind",
                Some((input.account_id, input.profile_id)),
                Some(profile),
            ))
        }
        UNBIND => {
            let input: UnbindRequest = serde_json::from_value(request.params.clone())
                .map_err(|_| Failure::new("invalid_params"))?;
            if !input.confirmed
                || !valid_context(&paths, &input.expected_context)
                || !account_operations::valid_id(&input.account_id)
            {
                return Err(Failure::new("invalid_params"));
            }
            let authority = account_operations::authorize(&paths, &input.expected_context)
                .await
                .map_err(operation_failure)?;
            authority
                .client
                .unbind_developer_credential_profile(
                    authority.token.token.as_str(),
                    &input.account_id,
                )
                .await
                .map_err(api_failure)?;
            let mut result = receipt(
                request,
                input.expected_context,
                "unbind",
                Some((input.account_id, String::new())),
                None,
            );
            result["profile_id"] = Value::Null;
            Ok(result)
        }
        _ => Err(Failure::new("unsupported_method")),
    }
}

fn valid_context(paths: &AppPaths, context: &Context) -> bool {
    paths.home() == Path::new(&context.home)
        && context
            .server_url
            .as_deref()
            .is_some_and(|v| valid_text(v, 8192))
        && context
            .active_device_id
            .as_deref()
            .is_some_and(account_operations::valid_id)
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_optional_text(value: Option<&str>, max: usize) -> bool {
    value.is_none_or(|value| valid_text(value, max))
}

fn valid_gh_mode(value: &str) -> bool {
    matches!(value, "remote_login" | "import_token" | "disabled")
}

fn valid_ssh_mode(value: &str) -> bool {
    matches!(value, "agent_forwarding" | "deploy_key" | "disabled")
}

fn projection(profile: crate::api::DeveloperCredentialProfileData) -> Result<Value, Failure> {
    if !account_operations::valid_id(&profile.id)
        || !valid_text(&profile.display_name, 256)
        || !matches!(profile.status.as_str(), "active" | "disabled")
        || !valid_gh_mode(&profile.github_cli_mode)
        || !valid_ssh_mode(&profile.ssh_mode)
        || !valid_text(&profile.created_at, 128)
        || !valid_text(&profile.updated_at, 128)
    {
        return Err(Failure::new("credential_response_invalid"));
    }
    // Deliberate projection: user_id, git_identity and secret_ref never cross
    // the desktop boundary.  The profile itself contains no secret material.
    Ok(json!({
        "id": profile.id,
        "display_name": profile.display_name,
        "status": profile.status,
        "github_cli_mode": profile.github_cli_mode,
        "ssh_mode": profile.ssh_mode,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
    }))
}

fn receipt(
    request: &Request,
    context: Context,
    action: &str,
    target: Option<(String, String)>,
    profile: Option<Value>,
) -> Value {
    let (account_id, profile_id) = target
        .map(|(account, profile)| (Value::String(account), Value::String(profile)))
        .unwrap_or((Value::Null, Value::Null));
    json!({
        "operation_id": request.request_id,
        "context": context,
        "accepted": true,
        "action": action,
        "account_id": account_id,
        "profile_id": profile_id,
        "profile": profile,
    })
}

fn operation_failure(error: account_operations::Error) -> Failure {
    Failure {
        code: error.code,
        retryable: false,
        http_status: error.http_status,
    }
}

fn api_failure(error: crate::api::ApiError) -> Failure {
    let status = error.status_code();
    let code = match status {
        Some(401) => "authentication_required",
        Some(403) => "permission_denied",
        Some(404) => "credential_not_found",
        Some(422) => "credential_rejected",
        Some(429) => "rate_limited",
        _ => "server_unavailable",
    };
    Failure {
        code,
        retryable: status.is_none_or(|value| value == 429 || value >= 500),
        http_status: status,
    }
}
