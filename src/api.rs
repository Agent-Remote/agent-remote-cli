use std::fmt;

use anyhow::{bail, Result};
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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
        let body = response.text().await.map_err(ApiError::transport)?;
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

#[derive(Clone, Debug, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub expires_in: u64,
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
    pub ssh_public_key: String,
    pub wireguard_public_key: Option<String>,
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
    pub fn is_pending_cli_login(&self) -> bool {
        self.status == Some(StatusCode::BAD_REQUEST)
            && self.code.as_deref() == Some("COMMON_BAD_REQUEST")
            && self.message.contains("not approved")
    }

    fn transport(error: reqwest::Error) -> Self {
        Self {
            status: error.status(),
            code: None,
            message: error.to_string(),
        }
    }

    fn decode(status: StatusCode, body: String, error: serde_json::Error) -> Self {
        Self {
            status: Some(status),
            code: None,
            message: format!("failed to decode API response: {error}; body: {body}"),
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
                message: body,
            },
        }
    }
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
