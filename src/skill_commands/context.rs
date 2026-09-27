//! Authenticated user/origin context shared by journaled skill commands.

use crate::api::ApiClient;
use crate::auth::{load_user_token, user_login_error};
use crate::config::{AppPaths, Config};
use anyhow::{Context, Result};

pub(super) struct ContextData {
    pub paths: AppPaths,
    pub client: ApiClient,
    pub token: String,
    pub server: String,
    pub user: String,
}
impl ContextData {
    pub(super) async fn load(paths: AppPaths) -> Result<Self> {
        let server = Config::load(&paths)?
            .server_url
            .context("server profile missing")?;
        let token = load_user_token(&paths, &server)
            .await?
            .ok_or_else(user_login_error)?;
        let client = ApiClient::new(server)?;
        let server = client.skill_server_identity()?;
        let user = client.skill_user_id(&token).await?;
        Ok(Self {
            paths,
            client,
            token,
            server,
            user,
        })
    }
}
