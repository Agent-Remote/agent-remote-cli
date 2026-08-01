use std::fmt;
use std::time::Duration;

use anyhow::{bail, Result};
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::time::{sleep, Instant};

const MAX_API_RESPONSE_BYTES: usize = 1 << 20;

#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl ApiClient {
    pub fn new(base_url: String) -> Result<Self> {
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            bail!("server URL must start with http:// or https://");
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        })
    }

    pub async fn healthz(&self) -> Result<HealthResponse, ApiError> {
        self.get("/healthz", None).await
    }

    pub async fn login_password(
        &self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<AuthToken, ApiError> {
        let response: Envelope<AuthToken> = self
            .post(
                "/api/v1/auth/login",
                None,
                &LoginRequest {
                    username,
                    password,
                    totp_code,
                },
            )
            .await?;
        Ok(response.data)
    }

    pub async fn start_cli_login(&self) -> Result<CliLoginStart, ApiError> {
        let response: Envelope<CliLoginStart> =
            self.post_empty("/api/v1/auth/cli/start", None).await?;
        Ok(response.data)
    }

    pub async fn complete_cli_login(&self, device_code: &str) -> Result<AuthToken, ApiError> {
        let response: Envelope<AuthToken> = self
            .post(
                "/api/v1/auth/cli/complete",
                None,
                &CliLoginCompleteRequest { device_code },
            )
            .await?;
        Ok(response.data)
    }

    pub async fn logout(&self, token: &str) -> Result<(), ApiError> {
        let _: serde_json::Value = self.post_empty("/api/v1/auth/logout", Some(token)).await?;
        Ok(())
    }

    pub async fn refresh_token(&self, token: &str) -> Result<AuthToken, ApiError> {
        let response: Envelope<AuthToken> =
            self.post_empty("/api/v1/auth/refresh", Some(token)).await?;
        Ok(response.data)
    }

    pub async fn register_device(
        &self,
        token: &str,
        request: &RegisterDeviceRequest,
    ) -> Result<DeviceRegistrationResponse, ApiError> {
        let response: Envelope<DeviceRegistrationData> = self
            .post("/api/v1/devices/register", Some(token), request)
            .await?;
        Ok(DeviceRegistrationResponse {
            data: response.data,
        })
    }

    pub async fn get_device(&self, token: &str, device_id: &str) -> Result<DeviceData, ApiError> {
        let response: Envelope<DeviceData> = self
            .get(&format!("/api/v1/devices/{device_id}"), Some(token))
            .await?;
        Ok(response.data)
    }

    /// Revokes one device through the authenticated control-plane endpoint.
    pub async fn revoke_device(&self, token: &str, device_id: &str) -> Result<(), ApiError> {
        let path = format!("/api/v1/devices/{}/revoke", url_encode(device_id));
        let _: serde_json::Value = self.post_empty(&path, Some(token)).await?;
        Ok(())
    }

    /// Rotates one device token through the authenticated control-plane endpoint.
    pub async fn rotate_device_token(
        &self,
        token: &str,
        device_id: &str,
    ) -> Result<AuthToken, ApiError> {
        let path = format!("/api/v1/devices/{}/rotate-token", url_encode(device_id));
        let response: Envelope<AuthToken> = self.post_empty(&path, Some(token)).await?;
        Ok(response.data)
    }

    pub async fn get_wireguard_config(&self, token: &str) -> Result<WireGuardConfigData, ApiError> {
        let response: Envelope<WireGuardConfigData> = self
            .get("/api/v1/network/wireguard/config", Some(token))
            .await?;
        Ok(response.data)
    }

    pub async fn enroll_wireguard_peer(
        &self,
        token: &str,
        public_key: &str,
    ) -> Result<(), ApiError> {
        let _: Envelope<serde_json::Value> = self
            .post(
                "/api/v1/network/wireguard/peer",
                Some(token),
                &EnrollWireGuardPeerRequest { public_key },
            )
            .await?;
        Ok(())
    }

    pub async fn attach_session(
        &self,
        token: &str,
        session_id: &str,
    ) -> Result<AttachSessionData, ApiError> {
        let response: Envelope<AttachSessionData> = self
            .post_empty(
                &format!("/api/v1/sessions/{session_id}/attach"),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn wait_for_attach_authorization(
        &self,
        token: &str,
        mut attach: AttachSessionData,
    ) -> Result<AttachSessionData, ApiError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match attach.authorization_task_status.as_str() {
                "succeeded" => return Ok(attach),
                "failed" | "cancelled" | "expired" => {
                    return Err(ApiError {
                        status: None,
                        code: Some("SSH_KEY_SYNC_FAILED".to_string()),
                        message: format!(
                            "SSH key synchronization task {} became {}",
                            attach.authorization_task_id, attach.authorization_task_status
                        ),
                    });
                }
                _ if Instant::now() >= deadline => {
                    return Err(ApiError {
                        status: None,
                        code: Some("SSH_KEY_SYNC_TIMEOUT".to_string()),
                        message: format!(
                            "SSH key synchronization task {} did not complete within 30 seconds",
                            attach.authorization_task_id
                        ),
                    });
                }
                _ => {
                    sleep(Duration::from_secs(1)).await;
                    attach = self.attach_session(token, &attach.session_id).await?;
                }
            }
        }
    }

    #[allow(dead_code)]
    pub async fn list_sessions(
        &self,
        token: &str,
        tool_type: Option<&str>,
        statuses: &[String],
    ) -> Result<Vec<SessionData>, ApiError> {
        let mut query = Vec::new();
        if let Some(tool_type) = tool_type {
            query.push(format!("tool_type={}", url_encode(tool_type)));
        }
        query.extend(
            statuses
                .iter()
                .map(|status| format!("status={}", url_encode(status))),
        );
        let path = if query.is_empty() {
            "/api/v1/sessions".to_string()
        } else {
            format!("/api/v1/sessions?{}", query.join("&"))
        };
        let response: Envelope<SessionListData> = self.get(&path, Some(token)).await?;
        Ok(response.data.items)
    }

    #[allow(dead_code)]
    pub async fn create_tool_session(
        &self,
        token: &str,
        request: &CreateSessionRequest,
    ) -> Result<SessionData, ApiError> {
        let response: Envelope<SessionData> =
            self.post("/api/v1/sessions", Some(token), request).await?;
        Ok(response.data)
    }

    #[allow(dead_code)]
    pub async fn get_tool_session(
        &self,
        token: &str,
        session_id: &str,
    ) -> Result<SessionData, ApiError> {
        let response: Envelope<SessionData> = self
            .get(&format!("/api/v1/sessions/{session_id}"), Some(token))
            .await?;
        Ok(response.data)
    }

    #[allow(dead_code)]
    pub async fn get_current_project_session(
        &self,
        token: &str,
        tool_type: &str,
        project_key: &str,
    ) -> Result<SessionData, ApiError> {
        let path = format!(
            "/api/v1/sessions/current-project?tool_type={}&project_key={}",
            url_encode(tool_type),
            url_encode(project_key)
        );
        let response: Envelope<SessionData> = self.get(&path, Some(token)).await?;
        Ok(response.data)
    }

    #[allow(dead_code)]
    pub async fn stop_tool_session(
        &self,
        token: &str,
        session_id: &str,
    ) -> Result<SessionData, ApiError> {
        let response: Envelope<SessionData> = self
            .post_empty(&format!("/api/v1/sessions/{session_id}/stop"), Some(token))
            .await?;
        Ok(response.data)
    }

    #[allow(dead_code)]
    pub async fn delete_tool_session(&self, token: &str, session_id: &str) -> Result<(), ApiError> {
        self.delete_empty(&format!("/api/v1/sessions/{session_id}"), Some(token))
            .await
    }

    #[allow(dead_code)]
    pub async fn delete_inactive_tool_sessions(&self, token: &str) -> Result<(), ApiError> {
        self.delete_empty("/api/v1/sessions", Some(token)).await
    }

    pub async fn create_port_forward(
        &self,
        token: &str,
        session_id: &str,
        request: &CreatePortForwardRequest,
    ) -> Result<CreatedPortForwardData, ApiError> {
        let response: Envelope<CreatedPortForwardData> = self
            .post(
                &format!("/api/v1/sessions/{}/port-forwards", url_encode(session_id)),
                Some(token),
                request,
            )
            .await?;
        Ok(response.data)
    }

    pub async fn create_port_forward_connection(
        &self,
        token: &str,
        forward_id: &str,
    ) -> Result<PortForwardConnectionData, ApiError> {
        let response: Envelope<PortForwardConnectionData> = self
            .post_empty(
                &format!(
                    "/api/v1/port-forwards/{}/connections",
                    url_encode(forward_id)
                ),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn list_port_forwards(&self, token: &str) -> Result<Vec<PortForwardData>, ApiError> {
        let response: Envelope<PortForwardListData> =
            self.get("/api/v1/port-forwards", Some(token)).await?;
        Ok(response.data.items)
    }

    pub async fn stop_port_forward(
        &self,
        token: &str,
        forward_id: &str,
    ) -> Result<PortForwardData, ApiError> {
        let response: Envelope<PortForwardData> = self
            .delete(
                &format!("/api/v1/port-forwards/{}", url_encode(forward_id)),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn create_workspace(
        &self,
        token: &str,
        request: &CreateWorkspaceRequest,
    ) -> Result<WorkspaceData, ApiError> {
        let response: Envelope<WorkspaceData> = self
            .post("/api/v1/workspaces", Some(token), request)
            .await?;
        Ok(response.data)
    }

    pub async fn create_sync_session(
        &self,
        token: &str,
        request: &CreateSyncSessionRequest,
    ) -> Result<SyncSessionData, ApiError> {
        let response: Envelope<SyncSessionData> = self
            .post("/api/v1/sync-sessions", Some(token), request)
            .await?;
        Ok(response.data)
    }

    pub async fn get_sync_session(
        &self,
        token: &str,
        sync_session_id: &str,
    ) -> Result<SyncSessionData, ApiError> {
        let response: Envelope<SyncSessionData> = self
            .get(
                &format!("/api/v1/sync-sessions/{sync_session_id}"),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn pause_sync_session(
        &self,
        token: &str,
        sync_session_id: &str,
    ) -> Result<SyncSessionData, ApiError> {
        self.sync_session_action(token, sync_session_id, "pause")
            .await
    }

    pub async fn resume_sync_session(
        &self,
        token: &str,
        sync_session_id: &str,
    ) -> Result<SyncSessionData, ApiError> {
        self.sync_session_action(token, sync_session_id, "resume")
            .await
    }

    pub async fn resolve_sync_session(
        &self,
        token: &str,
        sync_session_id: &str,
    ) -> Result<SyncSessionData, ApiError> {
        self.sync_session_action(token, sync_session_id, "resolve")
            .await
    }

    pub async fn reset_sync_session(
        &self,
        token: &str,
        sync_session_id: &str,
    ) -> Result<SyncSessionData, ApiError> {
        self.sync_session_action(token, sync_session_id, "reset")
            .await
    }

    pub async fn list_tool_accounts(&self, token: &str) -> Result<Vec<ToolAccountData>, ApiError> {
        let response: Envelope<ToolAccountListData> =
            self.get("/api/v1/tool-accounts", Some(token)).await?;
        Ok(response.data.items)
    }

    pub async fn create_tool_account(
        &self,
        token: &str,
        request: &CreateToolAccountRequest,
    ) -> Result<ToolAccountData, ApiError> {
        let response: Envelope<ToolAccountData> = self
            .post("/api/v1/tool-accounts", Some(token), request)
            .await?;
        Ok(response.data)
    }

    pub async fn get_tool_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> Result<ToolAccountData, ApiError> {
        let response: Envelope<ToolAccountData> = self
            .get(&format!("/api/v1/tool-accounts/{account_id}"), Some(token))
            .await?;
        Ok(response.data)
    }

    pub async fn start_tool_account_binding(
        &self,
        token: &str,
        account_id: &str,
    ) -> Result<BindingStatusData, ApiError> {
        let response: Envelope<BindingStatusData> = self
            .post_empty(
                &format!("/api/v1/tool-accounts/{account_id}/bind/start"),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn get_tool_account_binding_status(
        &self,
        token: &str,
        account_id: &str,
    ) -> Result<BindingStatusData, ApiError> {
        let response: Envelope<BindingStatusData> = self
            .get(
                &format!("/api/v1/tool-accounts/{account_id}/bind/status"),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn verify_tool_account_binding(
        &self,
        token: &str,
        account_id: &str,
    ) -> Result<BindingStatusData, ApiError> {
        let response: Envelope<BindingStatusData> = self
            .post_empty(
                &format!("/api/v1/tool-accounts/{account_id}/bind/verify"),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn disable_tool_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> Result<ToolAccountData, ApiError> {
        let response: Envelope<ToolAccountData> = self
            .post_empty(
                &format!("/api/v1/tool-accounts/{account_id}/disable"),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn create_tool_account_config_import(
        &self,
        token: &str,
        account_id: &str,
        request: &ToolAccountConfigImportRequest,
    ) -> Result<ToolAccountConfigImportData, ApiError> {
        let response: Envelope<ToolAccountConfigImportData> = self
            .post(
                &format!("/api/v1/tool-accounts/{account_id}/config-imports"),
                Some(token),
                request,
            )
            .await?;
        Ok(response.data)
    }

    pub async fn get_tool_account_config_import_status(
        &self,
        token: &str,
        account_id: &str,
        task_id: &str,
    ) -> Result<ToolAccountConfigImportStatusData, ApiError> {
        let response: Envelope<ToolAccountConfigImportStatusData> = self
            .get(
                &format!("/api/v1/tool-accounts/{account_id}/config-imports/{task_id}"),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn list_developer_credential_profiles(
        &self,
        token: &str,
    ) -> Result<Vec<DeveloperCredentialProfileData>, ApiError> {
        let response: Envelope<DeveloperCredentialProfileListData> = self
            .get("/api/v1/developer-credential-profiles", Some(token))
            .await?;
        Ok(response.data.items)
    }

    pub async fn create_developer_credential_profile(
        &self,
        token: &str,
        request: &CreateDeveloperCredentialProfileRequest,
    ) -> Result<DeveloperCredentialProfileData, ApiError> {
        let response: Envelope<DeveloperCredentialProfileData> = self
            .post(
                "/api/v1/developer-credential-profiles",
                Some(token),
                request,
            )
            .await?;
        Ok(response.data)
    }

    pub async fn bind_developer_credential_profile(
        &self,
        token: &str,
        account_id: &str,
        profile_id: &str,
    ) -> Result<DeveloperCredentialProfileData, ApiError> {
        let response: Envelope<DeveloperCredentialProfileData> = self
            .post(
                &format!("/api/v1/tool-accounts/{account_id}/developer-credential-profile"),
                Some(token),
                &BindDeveloperCredentialProfileRequest {
                    profile_id: profile_id.to_string(),
                },
            )
            .await?;
        Ok(response.data)
    }

    pub async fn unbind_developer_credential_profile(
        &self,
        token: &str,
        account_id: &str,
    ) -> Result<(), ApiError> {
        self.delete_empty(
            &format!("/api/v1/tool-accounts/{account_id}/developer-credential-profile"),
            Some(token),
        )
        .await
    }

    async fn sync_session_action(
        &self,
        token: &str,
        sync_session_id: &str,
        action: &str,
    ) -> Result<SyncSessionData, ApiError> {
        let response: Envelope<SyncSessionData> = self
            .post(
                &format!("/api/v1/sync-sessions/{sync_session_id}/{action}"),
                Some(token),
                &SyncSessionActionRequest { note: None },
            )
            .await?;
        Ok(response.data)
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> Result<T, ApiError> {
        let request = self.client.get(self.endpoint(path));
        self.send(request, token).await
    }

    async fn post_empty<T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> Result<T, ApiError> {
        let request = self.client.post(self.endpoint(path));
        self.send(request, token).await
    }

    async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &B,
    ) -> Result<T, ApiError> {
        let request = self.client.post(self.endpoint(path)).json(body);
        self.send(request, token).await
    }

    async fn delete_empty(&self, path: &str, token: Option<&str>) -> Result<(), ApiError> {
        let request = self.client.delete(self.endpoint(path));
        let request = match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        let response = request.send().await.map_err(ApiError::transport)?;
        let status = response.status();
        let body = read_response_body(response).await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(ApiError::from_error_response(status, body))
        }
    }

    async fn delete<T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> Result<T, ApiError> {
        let request = self.client.delete(self.endpoint(path));
        self.send(request, token).await
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        token: Option<&str>,
    ) -> Result<T, ApiError> {
        let request = match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        let response = request.send().await.map_err(ApiError::transport)?;
        let status = response.status();
        let body = read_response_body(response).await?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(|error| ApiError::decode(status, body, error))
        } else {
            Err(ApiError::from_error_response(status, body))
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

async fn read_response_body(mut response: reqwest::Response) -> Result<String, ApiError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_API_RESPONSE_BYTES as u64)
    {
        return Err(ApiError::response_too_large(status));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(ApiError::transport)? {
        if body.len().saturating_add(chunk.len()) > MAX_API_RESPONSE_BYTES {
            return Err(ApiError::response_too_large(status));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| ApiError {
        status: Some(status),
        code: None,
        message: "API response is not valid UTF-8".to_string(),
    })
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Debug, Serialize)]
struct LoginRequest<'a> {
    username: &'a str,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp_code: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct CliLoginCompleteRequest<'a> {
    device_code: &'a str,
}

#[derive(Clone, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub expires_in: u64,
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthToken")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct CliLoginStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
    pub platform: String,
    pub cli_version: String,
    pub ssh_public_key: String,
    pub wireguard_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub existing_device_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeviceRegistrationResponse {
    pub data: DeviceRegistrationData,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeviceRegistrationData {
    pub device: DeviceData,
    pub device_token: AuthToken,
    pub ssh_key_id: String,
    pub wireguard_peer_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeviceData {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub status: String,
    pub last_seen_at: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WireGuardConfigData {
    pub device_id: String,
    pub interface_address: String,
    #[serde(rename = "private_key_ref")]
    pub _private_key_ref: String,
    pub dns: Vec<String>,
    pub peers: Vec<WireGuardNodePeerData>,
}

#[derive(Debug, Serialize)]
struct EnrollWireGuardPeerRequest<'a> {
    public_key: &'a str,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WireGuardNodePeerData {
    pub node_id: String,
    pub name: String,
    pub region_code: String,
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_seconds: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AttachSessionData {
    pub session_id: String,
    pub node_id: String,
    pub node_wireguard_ip: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub tmux_session_name: String,
    pub command_args: Vec<String>,
    pub ssh_command: String,
    #[serde(default)]
    pub forward_ssh_agent: bool,
    pub authorization_task_id: String,
    #[serde(default = "default_authorization_task_status")]
    pub authorization_task_status: String,
    pub expires_in: u64,
}

fn default_authorization_task_status() -> String {
    "succeeded".to_string()
}

#[derive(Clone, Debug, Serialize)]
#[allow(dead_code)]
pub struct CreateSessionRequest {
    pub tool_type: String,
    pub tool_account_id: String,
    pub workspace_id: String,
    pub project_key: String,
    pub argv: Vec<String>,
    pub replaces_session_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
struct SessionListData {
    items: Vec<SessionData>,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct SessionData {
    pub id: String,
    pub tool_type: String,
    pub user_id: String,
    pub tool_account_id: String,
    pub workspace_id: String,
    pub workspace_local_path: Option<String>,
    pub workspace_remote_path: Option<String>,
    pub node_id: String,
    pub project_key: String,
    pub status: String,
    pub tmux_session_name: Option<String>,
    pub container_id: Option<String>,
    pub runtime_backend: String,
    pub runtime_resource_id: Option<String>,
    pub replaces_session_id: Option<String>,
    pub create_task_id: Option<String>,
    pub stop_task_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreatePortForwardRequest {
    pub remote_port: u16,
    pub local_port: u16,
    pub client_instance_id: String,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Deserialize)]
#[allow(dead_code)]
pub struct PortForwardConnectionData {
    pub token: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct PortForwardData {
    pub id: String,
    pub user_id: String,
    pub device_id: String,
    pub session_id: String,
    pub node_id: String,
    pub remote_port: u16,
    pub requested_local_port: u16,
    pub client_instance_id: String,
    pub status: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub connection_count: u64,
    pub last_connected_at: Option<String>,
    pub lease_expires_at: Option<String>,
    pub expires_at: String,
    pub stopped_at: Option<String>,
    pub stop_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Deserialize)]
pub struct CreatedPortForwardData {
    #[serde(flatten)]
    pub forward: PortForwardData,
    pub node_wireguard_ip: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub connection: PortForwardConnectionData,
}

#[derive(Clone, Debug, Deserialize)]
struct PortForwardListData {
    items: Vec<PortForwardData>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreateWorkspaceRequest {
    pub device_id: String,
    pub project_key: String,
    pub local_start_path: String,
    pub display_name: String,
    pub sync_git: bool,
    pub git_sync_policy: GitSyncPolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct WorkspaceData {
    pub id: String,
    pub user_id: String,
    pub device_id: String,
    pub project_key: String,
    pub local_start_path: String,
    pub display_name: String,
    pub remote_path: Option<String>,
    #[serde(default = "default_sync_git")]
    pub sync_git: bool,
    #[serde(default)]
    pub git_sync_policy: GitSyncPolicy,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreateSyncSessionRequest {
    pub workspace_id: String,
    pub node_id: Option<String>,
    pub local_path: Option<String>,
    pub sync_mode: String,
    pub sync_git: bool,
    pub exclude: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitSyncPolicy {
    pub exclude_hooks: bool,
    pub exclude_locks: bool,
    pub require_clean_git_lock: bool,
    pub warn_concurrent_git: bool,
}

impl Default for GitSyncPolicy {
    fn default() -> Self {
        Self {
            exclude_hooks: true,
            exclude_locks: true,
            require_clean_git_lock: true,
            warn_concurrent_git: true,
        }
    }
}

fn default_sync_git() -> bool {
    true
}

#[derive(Clone, Debug, Serialize)]
struct SyncSessionActionRequest {
    note: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct SyncSessionData {
    pub id: String,
    pub user_id: String,
    pub workspace_id: String,
    pub node_id: Option<String>,
    pub local_path: String,
    pub remote_path: String,
    pub status: String,
    pub conflict_status: String,
    pub sync_mode: String,
    #[serde(default = "default_sync_git")]
    pub sync_git: bool,
    #[serde(default)]
    pub exclude: Vec<String>,
    pub mutagen_session_id: Option<String>,
    pub remote_endpoint: Option<String>,
    pub prepare_task_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreateToolAccountRequest {
    pub tool_type: String,
    pub display_name: String,
    pub region_code: String,
    pub timezone: String,
    pub locale: String,
    pub preferred_node_tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolAccountConfigImportRequest {
    pub tool_type: String,
    pub source: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    #[serde(default)]
    pub files: Vec<ToolAccountConfigImportFile>,
    pub include_resume_history: bool,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolAccountConfigImportFile {
    pub path: String,
    pub content_base64: String,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ToolAccountConfigImportData {
    pub tool_account_id: String,
    pub accepted: Vec<String>,
    pub rejected: Vec<String>,
    pub warnings: Vec<String>,
    pub task_id: Option<String>,
    pub account_remote_path: Option<String>,
    pub imported_file_count: Option<u32>,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ToolAccountConfigImportStatusData {
    pub task_id: String,
    pub status: String,
    pub files_written: Vec<String>,
    pub file_count: u32,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreateDeveloperCredentialProfileRequest {
    pub display_name: String,
    pub git_identity: DeveloperCredentialGitIdentity,
    pub github_cli: DeveloperCredentialGitHubCli,
    pub ssh: DeveloperCredentialSsh,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeveloperCredentialGitIdentity {
    pub user_name: Option<String>,
    pub user_email: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeveloperCredentialGitHubCli {
    pub mode: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeveloperCredentialSsh {
    pub mode: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BindDeveloperCredentialProfileRequest {
    pub profile_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DeveloperCredentialProfileListData {
    items: Vec<DeveloperCredentialProfileData>,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct DeveloperCredentialProfileData {
    pub id: String,
    pub user_id: String,
    pub display_name: String,
    pub status: String,
    pub git_identity: serde_json::Value,
    pub github_cli_mode: String,
    pub ssh_mode: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ToolAccountListData {
    items: Vec<ToolAccountData>,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct ToolAccountData {
    pub id: String,
    pub user_id: String,
    pub tool_type: String,
    pub display_name: String,
    pub status: String,
    pub region_code: String,
    pub timezone: String,
    pub locale: String,
    pub preferred_node_tags: Vec<String>,
    pub affinity_node_id: Option<String>,
    pub runtime_backend: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct BindingStatusData {
    pub tool_account_id: String,
    pub status: String,
    pub node_id: Option<String>,
    pub binding_session_id: Option<String>,
    pub tmux_session_name: Option<String>,
    pub account_remote_path: Option<String>,
    pub connect_command: Option<String>,
    pub task_id: Option<String>,
    pub verifier: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Debug)]
pub struct ApiError {
    status: Option<StatusCode>,
    code: Option<String>,
    message: String,
}

impl ApiError {
    #[allow(dead_code)]
    pub fn is_not_found(&self) -> bool {
        self.status == Some(StatusCode::NOT_FOUND)
    }

    pub fn is_pending_cli_login(&self) -> bool {
        self.status == Some(StatusCode::BAD_REQUEST)
            && self.code.as_deref() == Some("COMMON_BAD_REQUEST")
            && self.message.contains("not approved")
    }

    pub fn is_port_forward_terminal(&self) -> bool {
        self.status.is_some_and(|status| {
            status.is_client_error() && status != StatusCode::TOO_MANY_REQUESTS
        })
    }

    fn transport(error: reqwest::Error) -> Self {
        Self {
            status: error.status(),
            code: None,
            message: error.to_string(),
        }
    }

    fn decode(status: StatusCode, body: String, error: serde_json::Error) -> Self {
        let _ = body;
        Self {
            status: Some(status),
            code: None,
            message: format!("failed to decode API response: {error}"),
        }
    }

    fn response_too_large(status: StatusCode) -> Self {
        Self {
            status: Some(status),
            code: None,
            message: "API response exceeds the 1 MiB safety limit".to_string(),
        }
    }

    fn from_error_response(status: StatusCode, body: String) -> Self {
        match serde_json::from_str::<ErrorEnvelope>(&body) {
            Ok(error) => Self {
                status: Some(status),
                code: Some(error.error.code),
                message: error.error.message,
            },
            Err(_) => Self {
                status: Some(status),
                code: None,
                message: "server returned an invalid error response".to_string(),
            },
        }
    }
}

#[allow(dead_code)]
fn url_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.status, &self.code) {
            (Some(status), Some(code)) => write!(formatter, "{status} {code}: {}", self.message),
            (Some(status), None) => write!(formatter, "{status}: {}", self.message),
            (None, Some(code)) => write!(formatter, "{code}: {}", self.message),
            (None, None) => write!(formatter, "{}", self.message),
        }
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: ErrorPayload,
}

#[derive(Debug, Deserialize)]
struct ErrorPayload {
    code: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{ApiClient, AttachSessionData, RegisterDeviceRequest};

    #[test]
    fn attach_authorization_defaults_to_ready_for_older_servers() {
        let attach: AttachSessionData = serde_json::from_str(
            r#"{
                "session_id":"session_1",
                "node_id":"node_1",
                "node_wireguard_ip":"10.77.0.1",
                "ssh_host":"10.77.0.1",
                "ssh_port":22,
                "ssh_user":"agent-remote",
                "tmux_session_name":"claude-test",
                "command_args":[],
                "ssh_command":"ssh agent-remote@10.77.0.1",
                "authorization_task_id":"task_1",
                "expires_in":300
            }"#,
        )
        .unwrap();
        assert_eq!(attach.authorization_task_status, "succeeded");
    }

    #[test]
    fn device_registration_reports_version_and_optional_existing_device() {
        let request = RegisterDeviceRequest {
            name: "laptop".to_string(),
            platform: "linux".to_string(),
            cli_version: "0.0.5-fix.7".to_string(),
            ssh_public_key: "ssh-ed25519 AAAA".to_string(),
            wireguard_public_key: None,
            existing_device_id: None,
        };

        let payload = serde_json::to_value(request).unwrap();
        assert_eq!(payload["cli_version"], "0.0.5-fix.7");
        assert!(payload.get("existing_device_id").is_none());

        let existing_request = RegisterDeviceRequest {
            name: "laptop".to_string(),
            platform: "linux".to_string(),
            cli_version: "0.1.5".to_string(),
            ssh_public_key: "ssh-ed25519 AAAA".to_string(),
            wireguard_public_key: None,
            existing_device_id: Some("device-1".to_string()),
        };
        let existing_payload = serde_json::to_value(existing_request).unwrap();
        assert_eq!(existing_payload["existing_device_id"], "device-1");
    }

    #[tokio::test]
    async fn device_revoke_uses_the_authenticated_versioned_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "request ended before its headers were complete");
                request.extend_from_slice(&chunk[..read]);
                assert!(request.len() <= 8192, "request headers exceeded 8 KiB");
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("POST /api/v1/devices/device-123/revoke HTTP/1.1\r\n"));
            assert!(request
                .to_ascii_lowercase()
                .contains("\r\nauthorization: bearer test-user-token\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
                )
                .await
                .unwrap();
        });

        ApiClient::new(format!("http://{address}"))
            .unwrap()
            .revoke_device("test-user-token", "device-123")
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn device_token_rotation_uses_user_auth_and_redacts_the_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "request ended before its headers were complete");
                request.extend_from_slice(&chunk[..read]);
                assert!(request.len() <= 8192, "request headers exceeded 8 KiB");
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("POST /api/v1/devices/device-123/rotate-token HTTP/1.1\r\n")
            );
            assert!(request
                .to_ascii_lowercase()
                .contains("\r\nauthorization: bearer test-user-token\r\n"));
            let body = r#"{"data":{"access_token":"new-device-token-that-must-remain-redacted","expires_in":3600}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let token = ApiClient::new(format!("http://{address}"))
            .unwrap()
            .rotate_device_token("test-user-token", "device-123")
            .await
            .unwrap();
        assert_eq!(token.expires_in, 3600);
        assert!(!format!("{token:?}").contains("new-device-token"));
        server.await.unwrap();
    }
}
