//! Exact session authorization and GET-only observation of its original task row.

use serde::{Deserialize, Serialize};

use super::{ApiClient, ApiError, Envelope};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionAttachData {
    pub version: u32,
    pub session_id: String,
    pub tool_type: String,
    pub device_id: String,
    pub node_id: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub tmux_session_name: String,
    pub forward_ssh_agent: bool,
    pub authorization_task_id: String,
    pub authorization_task_record_id: String,
    pub authorization_task_status: AuthorizationStatus,
    pub expires_in: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Pending,
    Leased,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
}

#[derive(Serialize)]
struct Request<'a> {
    expected_device_id: &'a str,
}

impl ApiClient {
    pub async fn authorize_session_attach(
        &self,
        token: &str,
        session: &str,
        device: &str,
    ) -> Result<SessionAttachData, ApiError> {
        let response: Envelope<SessionAttachData> = self
            .post(
                &format!("/api/v1/sessions/{session}/attach/exact"),
                Some(token),
                &Request {
                    expected_device_id: device,
                },
            )
            .await?;
        Ok(response.data)
    }

    pub async fn session_attach_status(
        &self,
        token: &str,
        session: &str,
        device: &str,
        task: &str,
        task_record: &str,
    ) -> Result<SessionAttachData, ApiError> {
        let response: Envelope<SessionAttachData> = self
            .get(
                &format!(
                    "/api/v1/sessions/{session}/attach/exact/{}?expected_device_id={}&expected_task_record_id={}",
                    super::url_encode(task), super::url_encode(device), super::url_encode(task_record)
                ),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }
}
