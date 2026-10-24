//! Shared per-home tool defaults. Login identity and confirmed previous values
//! are checked before publication; credentials never enter default metadata.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    api::ApiClient,
    auth,
    config::{AppPaths, Config},
    local_state::LocalState,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub home: PathBuf,
    #[serde(deserialize_with = "required_nullable")]
    pub server_url: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub active_device_id: Option<String>,
}

/// A nullable confirmation field must still be explicitly present.
pub fn required_nullable<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub context: Context,
    pub tool: String,
    pub account_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Outcome {
    pub context: Context,
    pub tool: String,
    pub previous_account_id: Option<String>,
    pub account_id: Option<String>,
    pub changed: bool,
}

#[derive(Debug)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            "configuration_unavailable" => "client configuration is unavailable; inspect local setup",
            "configuration_changed" => "client context changed; inspect the selected home, server and device before retrying",
            "state_unavailable" => "default account metadata is unavailable; inspect local setup",
            "default_changed" => "the default account changed; inspect the current default before retrying",
            "authentication_required" => "a registered device login is required to select an account",
            "credential_unavailable" => "device credentials are unavailable; inspect login status",
            "account_mismatch" => "the server account identity or tool does not match the selection",
            "default_outcome_unknown" => "the default account update could not be confirmed; inspect the current default before retrying",
            _ => "default account operation failed",
        })
    }
}
impl std::error::Error for Error {}

fn config(paths: &AppPaths) -> Result<Config> {
    match std::fs::symlink_metadata(paths.config_path()) {
        Ok(_) => Config::load_strict(paths).map_err(|_| Error("configuration_unavailable").into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(_) => Err(Error("configuration_unavailable").into()),
    }
}

fn context(paths: &AppPaths) -> Result<Context> {
    let config = config(paths)?;
    Ok(Context {
        home: paths.home().to_path_buf(),
        server_url: config.server_url,
        active_device_id: config.active_device_id,
    })
}

fn key(tool: &str) -> String {
    format!("default_tool_account:{tool}")
}

/// Local-only inspection. Missing metadata means no default, never initialization.
pub fn get(paths: &AppPaths, tool: &str) -> Result<Snapshot> {
    let initial = context(paths)?;
    let account_id =
        LocalState::read_default(paths, &key(tool)).map_err(|_| Error("state_unavailable"))?;
    if account_id.as_deref().is_some_and(|id| !valid_id(id)) {
        return Err(Error("state_unavailable").into());
    }
    if context(paths)? != initial {
        return Err(Error("configuration_changed").into());
    }
    Ok(Snapshot {
        context: initial,
        tool: tool.to_owned(),
        account_id,
    })
}

/// Human callers may resolve a prefix; desktop callers must supply an exact ID.
/// No database transaction is retained across credential or HTTP work.
pub async fn set(
    paths: &AppPaths,
    tool: &str,
    reference: &str,
    expected: Option<&Snapshot>,
    resolve_prefix: bool,
) -> Result<Outcome> {
    let initial = get(paths, tool)?;
    verify(&initial, expected)?;
    let guard = auth::login::lock(paths)
        .await
        .map_err(|_| Error("state_unavailable"))?;
    let current = get(paths, tool)?;
    verify(&current, Some(expected.unwrap_or(&initial)))?;
    if current.context.server_url.is_none() || current.context.active_device_id.is_none() {
        return Err(Error("authentication_required").into());
    }
    let expected_config = Config {
        server_url: current.context.server_url.clone(),
        active_device_id: current.context.active_device_id.clone(),
    };
    let cancel = AtomicBool::new(false);
    let token = auth::load_device_token_strict_locked(paths, &guard, &expected_config, &cancel)
        .await
        .map_err(|_| Error("credential_unavailable"))?;
    let client =
        ApiClient::new(token.server_url).map_err(|_| Error("configuration_unavailable"))?;
    let account_id = if resolve_prefix {
        let accounts = client.list_tool_accounts(token.token.as_str()).await?;
        crate::identifiers::resolve_id(
            reference,
            "tool account",
            accounts.iter().map(|a| a.id.as_str()),
        )?
    } else {
        reference.to_owned()
    };
    if !valid_id(&account_id) {
        return Err(Error("account_mismatch").into());
    }
    let account = client
        .get_tool_account(token.token.as_str(), &account_id)
        .await?;
    if account.id != account_id || account.tool_type != tool {
        return Err(Error("account_mismatch").into());
    }
    publish(paths, &current, Some(account_id))
}

/// Clear is local and requires no user/device credential or network request.
pub async fn clear(paths: &AppPaths, tool: &str, expected: Option<&Snapshot>) -> Result<Outcome> {
    let initial = get(paths, tool)?;
    verify(&initial, expected)?;
    let _guard = auth::login::lock(paths)
        .await
        .map_err(|_| Error("state_unavailable"))?;
    let current = get(paths, tool)?;
    verify(&current, Some(expected.unwrap_or(&initial)))?;
    publish(paths, &current, None)
}

fn verify(current: &Snapshot, expected: Option<&Snapshot>) -> Result<()> {
    if let Some(expected) = expected {
        if current.context != expected.context {
            return Err(Error("configuration_changed").into());
        }
        if current.account_id != expected.account_id || current.tool != expected.tool {
            return Err(Error("default_changed").into());
        }
    }
    Ok(())
}

fn publish(paths: &AppPaths, current: &Snapshot, next: Option<String>) -> Result<Outcome> {
    // The login guard is held by the caller. This second lock also excludes
    // Config::save writers which do not participate in login publication.
    let _config_guard =
        crate::config::write_lock(paths).map_err(|_| Error("configuration_unavailable"))?;
    if context(paths)? != current.context {
        return Err(Error("configuration_changed").into());
    }
    let changed = current.account_id != next;
    if changed {
        let state = LocalState::open(paths).map_err(|_| Error("state_unavailable"))?;
        state
            .init_schema()
            .map_err(|_| Error("state_unavailable"))?;
        if !state
            .compare_default(
                &key(&current.tool),
                current.account_id.as_deref(),
                next.as_deref(),
            )
            .map_err(|_| Error("default_outcome_unknown"))?
        {
            return Err(Error("default_changed").into());
        }
    } else if LocalState::read_default(paths, &key(&current.tool))
        .map_err(|_| Error("state_unavailable"))?
        != current.account_id
    {
        return Err(Error("default_changed").into());
    }
    Ok(Outcome {
        context: current.context.clone(),
        tool: current.tool.clone(),
        previous_account_id: current.account_id.clone(),
        account_id: next,
        changed,
    })
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
