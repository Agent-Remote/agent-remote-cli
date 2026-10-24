//! Additive conditional sync actions; legacy requests retain their existing shape.
use super::{ApiClient, ApiError, Envelope, SyncSessionData};
use serde::{Deserialize, Serialize};
#[derive(Serialize)]
struct ExpectedSyncTarget<'a> {
    id: &'a str,
    workspace_id: &'a str,
    node_id: Option<&'a str>,
    local_path: &'a str,
    remote_path: &'a str,
    mutagen_session_id: Option<&'a str>,
    remote_endpoint: Option<&'a str>,
    sync_mode: &'a str,
    sync_git: bool,
    exclude: &'a [String],
}
#[derive(Serialize)]
struct ConfirmedSyncAction<'a> {
    note: Option<&'a str>,
    expected_target: ExpectedSyncTarget<'a>,
}
#[derive(Deserialize)]
struct CheckedSyncSession {
    #[serde(flatten)]
    sync: SyncSessionData,
    target_precondition_version: u32,
    #[serde(default)]
    target_precondition_checked: bool,
}
impl CheckedSyncSession {
    fn validate(self, submitted: bool) -> Result<SyncSessionData, ApiError> {
        if self.target_precondition_version != 1 || (submitted && !self.target_precondition_checked)
        {
            return Err(ApiError {
                status: Some(reqwest::StatusCode::OK),
                code: None,
                message: "sync target precondition unsupported".into(),
            });
        }
        Ok(self.sync)
    }
}
impl ApiClient {
    /// Read the exact workspace without recreating or changing its mapping.
    pub async fn get_workspace(
        &self,
        token: &str,
        id: &str,
    ) -> Result<super::WorkspaceData, ApiError> {
        let response: Envelope<super::WorkspaceData> = self
            .get(&format!("/api/v1/workspaces/{id}"), Some(token))
            .await?;
        Ok(response.data)
    }

    /// Read and require Server support for the exact-target action contract.
    pub async fn get_sync_session_checked(
        &self,
        token: &str,
        id: &str,
    ) -> Result<SyncSessionData, ApiError> {
        let response: Envelope<CheckedSyncSession> = self
            .get(&format!("/api/v1/sync-sessions/{id}"), Some(token))
            .await?;
        response.data.validate(false)
    }

    /// Mutate only the exact synchronization destination reviewed by the caller.
    pub async fn confirmed_sync_session_action(
        &self,
        token: &str,
        action: &str,
        expected: &SyncSessionData,
    ) -> Result<SyncSessionData, ApiError> {
        let target = ExpectedSyncTarget {
            id: &expected.id,
            workspace_id: &expected.workspace_id,
            node_id: expected.node_id.as_deref(),
            local_path: &expected.local_path,
            remote_path: &expected.remote_path,
            mutagen_session_id: expected.mutagen_session_id.as_deref(),
            remote_endpoint: expected.remote_endpoint.as_deref(),
            sync_mode: &expected.sync_mode,
            sync_git: expected.sync_git,
            exclude: &expected.exclude,
        };
        let response: Envelope<CheckedSyncSession> = self
            .post(
                &format!("/api/v1/sync-sessions/{}/{action}", expected.id),
                Some(token),
                &ConfirmedSyncAction {
                    note: None,
                    expected_target: target,
                },
            )
            .await?;
        response.data.validate(true)
    }
}
