use super::{Authority, Error, Result, UserContext};
use crate::{
    api::{ApiClient, ApiError},
    auth,
    config::{AppPaths, Config},
    secrets::SecretValue,
};
use std::{path::Path, sync::atomic::AtomicBool};

pub(super) struct Access {
    pub context: UserContext,
    pub admin: bool,
    pub client: ApiClient,
    pub token: SecretValue,
    raw_server: String,
}
pub(super) struct WriteAccess {
    // Writers use login -> user credential -> config ordering; release in reverse.
    _config: std::fs::File,
    _credential: std::fs::File,
    _login: auth::login::LoginLock,
    pub access: Access,
}
pub fn valid_context(context: &UserContext) -> bool {
    context.home.is_absolute()
        && crate::api::runtime_recovery::canonical_uuid(&context.actor_user_id)
        && canonical_server(&context.server_url).is_ok_and(|v| v == context.server_url)
}
fn canonical_server(server: &str) -> Result<String> {
    if server.len() > 8192
        || server.chars().any(char::is_control)
        || !(server.starts_with("https://") || server.starts_with("http://"))
    {
        return Err(Error::new("configuration_unavailable"));
    }
    let url = reqwest::Url::parse(server).map_err(|_| Error::new("configuration_unavailable"))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::new("configuration_unavailable"));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}
fn config(paths: &AppPaths, home: &Path, server: &str) -> Result<Config> {
    if paths.home() != home {
        return Err(Error::new("configuration_changed"));
    }
    let value = Config::load_strict(paths).map_err(|_| Error::new("configuration_unavailable"))?;
    let configured = value
        .server_url
        .as_deref()
        .ok_or_else(|| Error::new("authentication_required"))?;
    if canonical_server(configured)? != canonical_server(server)? {
        return Err(Error::new("configuration_changed"));
    }
    Ok(value)
}
pub(super) fn read_error(error: ApiError) -> Error {
    Error {
        code: match error.status_code() {
            Some(401) => "authentication_required",
            Some(403) => "permission_denied",
            _ => "runtime_recovery_status_unknown",
        },
        http_status: error.status_code(),
        submitted: false,
    }
}
pub(super) async fn read(paths: &AppPaths, home: &Path, server: &str) -> Result<Access> {
    let before = config(paths, home, server)?;
    let raw = before
        .server_url
        .as_deref()
        .ok_or_else(|| Error::new("authentication_required"))?;
    let token = auth::strict_user::read(paths, raw, &AtomicBool::new(false))
        .await
        .map_err(|_| Error::new("credential_unavailable"))?;
    let client = ApiClient::new(raw.into()).map_err(|_| Error::new("configuration_unavailable"))?;
    let identity = client
        .recovery_authority(token.as_str())
        .await
        .map_err(read_error)?;
    if identity.schema_version != 1
        || !crate::api::runtime_recovery::canonical_uuid(&identity.actor_user_id)
    {
        return Err(Error::new("runtime_recovery_response_invalid"));
    }
    let after = config(paths, home, server)?;
    if after.server_url != before.server_url {
        return Err(Error::new("configuration_changed"));
    }
    let current = auth::strict_user::read(paths, raw, &AtomicBool::new(false))
        .await
        .map_err(|_| Error::new("credential_unavailable"))?;
    if current.as_str() != token.as_str() {
        return Err(Error::new("runtime_recovery_context_changed"));
    }
    Ok(Access {
        context: UserContext {
            home: paths.home().into(),
            server_url: canonical_server(raw)?,
            actor_user_id: identity.actor_user_id,
        },
        admin: identity.admin,
        client,
        token,
        raw_server: raw.into(),
    })
}

pub(super) async fn recheck(paths: &AppPaths, access: &Access) -> Result<()> {
    let current = config(paths, &access.context.home, &access.context.server_url)?;
    if current.server_url.as_deref() != Some(access.raw_server.as_str()) {
        return Err(Error::new("configuration_changed"));
    }
    let token = auth::strict_user::read(paths, &access.raw_server, &AtomicBool::new(false))
        .await
        .map_err(|_| Error::new("credential_unavailable"))?;
    if token.as_str() != access.token.as_str() {
        return Err(Error::new("runtime_recovery_context_changed"));
    }
    Ok(())
}
pub(super) async fn authorize(paths: &AppPaths, expected: &UserContext) -> Result<Access> {
    if !valid_context(expected) {
        return Err(Error::new("invalid_params"));
    }
    let access = read(paths, &expected.home, &expected.server_url).await?;
    if access.context != *expected {
        return Err(Error::new("runtime_recovery_context_changed"));
    }
    if !access.admin {
        return Err(Error::new("permission_denied"));
    }
    Ok(access)
}
pub(super) async fn write(paths: &AppPaths, expected: &UserContext) -> Result<WriteAccess> {
    let before = config(paths, &expected.home, &expected.server_url)?;
    let login = auth::login::lock(paths)
        .await
        .map_err(|_| Error::new("credential_unavailable"))?;
    let raw = before
        .server_url
        .as_deref()
        .ok_or_else(|| Error::new("authentication_required"))?;
    let credential = auth::strict_user::lock(paths, raw)
        .await
        .map_err(|_| Error::new("credential_unavailable"))?;
    let guard =
        crate::config::write_lock(paths).map_err(|_| Error::new("configuration_unavailable"))?;
    let access = authorize(paths, expected).await?;
    Ok(WriteAccess {
        _config: guard,
        _credential: credential,
        _login: login,
        access,
    })
}
/// User identity projection without refresh, local initialization or device authentication.
pub async fn authority(paths: &AppPaths, home: &Path, server: &str) -> Result<Authority> {
    let access = read(paths, home, server).await?;
    Ok(Authority {
        context: access.context,
        admin: access.admin,
    })
}
