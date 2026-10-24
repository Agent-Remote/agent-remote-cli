//! Confirmed remote account workflows with bounded public projections.
//! A POST receipt confirms acceptance, never completion of a queued binding task.

mod projection;
pub(crate) use projection::{id as valid_id, text as valid_text};
pub use projection::{Account, Binding};

use crate::{
    account_defaults::Context,
    api::{ApiClient, ApiError, CreateToolAccountRequest},
    auth,
    config::{AppPaths, Config},
};
use serde::Serialize;
use std::sync::atomic::AtomicBool;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    pub http_status: Option<u16>,
}
impl Error {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            http_status: None,
        }
    }
    fn read(error: ApiError) -> Self {
        let status = error.status_code();
        Self {
            code: match status {
                Some(401) => "authentication_required",
                Some(403) => "permission_denied",
                Some(404) => "account_not_found",
                Some(429) => "rate_limited",
                Some(200..=299) => "account_response_invalid",
                _ => "server_unavailable",
            },
            http_status: status,
        }
    }
    fn submission(error: ApiError) -> Self {
        let status = error.status_code();
        Self {
            code: if status.is_some_and(|v| (400..500).contains(&v)) {
                "account_rejected"
            } else {
                "account_outcome_unknown"
            },
            http_status: status,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Error {}

pub struct Create {
    pub tool: String,
    pub name: String,
    pub region: String,
    pub timezone: String,
    pub locale: String,
    pub tags: Vec<String>,
}
impl Create {
    pub fn valid(&self) -> bool {
        valid_id(&self.tool)
            && valid_text(&self.name, 256)
            && valid_text(&self.region, 64)
            && valid_text(&self.timezone, 128)
            && valid_text(&self.locale, 128)
            && projection::tags(&self.tags)
    }
    fn matches(&self, account: &Account) -> bool {
        account.tool_type == self.tool
            && account.display_name == self.name
            && account.region_code == self.region
            && account.timezone == self.timezone
            && account.locale == self.locale
            && account.preferred_node_tags == self.tags
    }
}
pub enum Mutation {
    Create(Create),
    Bind(String),
    Verify(String),
    Disable(String),
}
#[derive(Serialize)]
pub struct Status {
    pub context: Context,
    pub account: Account,
    pub binding: Binding,
}
#[derive(Serialize)]
pub struct Receipt {
    pub context: Context,
    pub accepted: bool,
    pub account: Option<Account>,
    pub binding: Option<Binding>,
}

pub(crate) struct Authority {
    // Release the configuration lock before the outer login guard.
    _config: std::fs::File,
    _login: auth::login::LoginLock,
    pub(crate) client: ApiClient,
    pub(crate) token: auth::StrictDeviceToken,
}

pub(crate) fn check_context(paths: &AppPaths, expected: &Context) -> Result<Config> {
    if paths.home() != expected.home {
        return Err(Error::new("configuration_changed"));
    }
    let actual = Config::load_strict(paths).map_err(|_| Error::new("configuration_unavailable"))?;
    if actual.server_url != expected.server_url
        || actual.active_device_id != expected.active_device_id
    {
        return Err(Error::new("configuration_changed"));
    }
    if actual.server_url.is_none() || actual.active_device_id.is_none() {
        return Err(Error::new("authentication_required"));
    }
    Ok(actual)
}

pub(crate) async fn authorize(paths: &AppPaths, expected: &Context) -> Result<Authority> {
    check_context(paths, expected)?;
    let login = auth::login::lock(paths)
        .await
        .map_err(|_| Error::new("credential_unavailable"))?;
    let config = check_context(paths, expected)?;
    let cancel = AtomicBool::new(false);
    let token = auth::load_device_token_strict_locked(paths, &login, &config, &cancel)
        .await
        .map_err(|_| Error::new("credential_unavailable"))?;
    // Credential refresh precedes this lock. Config::save writers cannot switch
    // the selected context between the final check and a remote POST.
    let guard =
        crate::config::write_lock(paths).map_err(|_| Error::new("configuration_unavailable"))?;
    check_context(paths, expected)?;
    let client = ApiClient::new(token.server_url.clone())
        .map_err(|_| Error::new("configuration_unavailable"))?;
    Ok(Authority {
        _config: guard,
        _login: login,
        client,
        token,
    })
}

/// Two distinct observations, not an atomic account/binding snapshot.
pub async fn status(paths: &AppPaths, expected: Context, account_id: &str) -> Result<Status> {
    if !valid_id(account_id) {
        return Err(Error::new("invalid_params"));
    }
    let authority = authorize(paths, &expected).await?;
    let account = projection::account(
        authority
            .client
            .get_tool_account(authority.token.token.as_str(), account_id)
            .await
            .map_err(Error::read)?,
    )?;
    if account.id != account_id {
        return Err(Error::new("account_response_invalid"));
    }
    let binding = projection::binding(
        authority
            .client
            .get_tool_account_binding_status(authority.token.token.as_str(), account_id)
            .await
            .map_err(Error::read)?,
        account_id,
    )?;
    Ok(Status {
        context: expected,
        account,
        binding,
    })
}

/// Exactly one remote POST. No automatic replay, even after an ambiguous result.
pub async fn mutate(paths: &AppPaths, expected: Context, action: Mutation) -> Result<Receipt> {
    let valid = match &action {
        Mutation::Create(input) => input.valid(),
        Mutation::Bind(id) | Mutation::Verify(id) | Mutation::Disable(id) => valid_id(id),
    };
    if !valid {
        return Err(Error::new("invalid_params"));
    }
    let authority = authorize(paths, &expected).await?;
    let client = &authority.client;
    let token = authority.token.token.as_str();
    let mut result = Receipt {
        context: expected,
        accepted: true,
        account: None,
        binding: None,
    };
    let is_bind = matches!(&action, Mutation::Bind(_));
    match action {
        Mutation::Create(input) => {
            let account = client
                .create_tool_account(
                    token,
                    &CreateToolAccountRequest {
                        tool_type: input.tool.clone(),
                        display_name: input.name.clone(),
                        region_code: input.region.clone(),
                        timezone: input.timezone.clone(),
                        locale: input.locale.clone(),
                        preferred_node_tags: input.tags.clone(),
                    },
                )
                .await
                .map_err(Error::submission)?;
            let account =
                projection::account(account).map_err(|_| Error::new("account_outcome_unknown"))?;
            if !input.matches(&account) {
                return Err(Error::new("account_outcome_unknown"));
            }
            result.account = Some(account);
        }
        Mutation::Disable(id) => {
            let account = client
                .disable_tool_account(token, &id)
                .await
                .map_err(Error::submission)?;
            let account =
                projection::account(account).map_err(|_| Error::new("account_outcome_unknown"))?;
            if account.id != id || account.status != "disabled" {
                return Err(Error::new("account_outcome_unknown"));
            }
            result.account = Some(account);
        }
        Mutation::Bind(id) | Mutation::Verify(id) => {
            let value = if is_bind {
                client.start_tool_account_binding(token, &id).await
            } else {
                client.verify_tool_account_binding(token, &id).await
            }
            .map_err(Error::submission)?;
            let binding = projection::binding(value, &id)
                .map_err(|_| Error::new("account_outcome_unknown"))?;
            if binding.task_id.is_none() {
                return Err(Error::new("account_outcome_unknown"));
            }
            result.binding = Some(binding);
        }
    }
    Ok(result)
}
