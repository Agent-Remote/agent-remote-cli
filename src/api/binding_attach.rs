//! Typed exact-generation binding authorization. Polling never resubmits a POST.

use serde::{Deserialize, Serialize};

use super::{ApiClient, ApiError, Envelope};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingAttachData {
    pub version: u32,
    pub tool_account_id: String,
    pub binding_session_id: String,
    pub node_id: String,
    pub device_id: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub tmux_session_name: String,
    pub authorization_task_id: String,
    pub authorization_task_status: String,
    pub expires_in: u64,
}

#[derive(Serialize)]
struct Request<'a> {
    expected_binding_session_id: &'a str,
}

impl ApiClient {
    pub async fn authorize_binding_attach(
        &self,
        token: &str,
        account: &str,
        binding: &str,
    ) -> Result<BindingAttachData, ApiError> {
        let response: Envelope<BindingAttachData> = self
            .post(
                &format!("/api/v1/tool-accounts/{account}/bind/attach"),
                Some(token),
                &Request {
                    expected_binding_session_id: binding,
                },
            )
            .await?;
        Ok(response.data)
    }

    pub async fn binding_attach_status(
        &self,
        token: &str,
        account: &str,
        binding: &str,
        task: &str,
    ) -> Result<BindingAttachData, ApiError> {
        let response: Envelope<BindingAttachData> = self
            .get(
                &format!(
                    "/api/v1/tool-accounts/{account}/bind/attach/{}?expected_binding_session_id={}",
                    super::url_encode(task),
                    super::url_encode(binding)
                ),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }
}
