//! Exact no-session admission receipts and read-only initial account takeover progress.

use super::{read_response_body, ApiClient, ApiError, CreateSessionRequest, Envelope, SessionData};
use reqwest::StatusCode;
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TakeoverPhase {
    Reserved,
    Uploading,
    Committed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingTakeover {
    pub account_id: String,
    pub takeover_id: String,
    pub takeover_status: TakeoverPhase,
    reservation_committed: bool,
    session_created: bool,
}

pub enum SessionAdmission {
    Created(Box<SessionData>),
    Takeover(PendingTakeover),
}

#[derive(Debug, Deserialize)]
pub struct TakeoverStatus {
    pub operation_id: String,
    pub account_id: String,
    pub status: TakeoverPhase,
    pub task_status: String,
    pub checkpoint_id: Option<String>,
    pub recovery_required: bool,
}

#[derive(Deserialize)]
struct PendingEnvelope {
    error: PendingError,
}

#[derive(Deserialize)]
struct PendingError {
    code: String,
    details: PendingTakeover,
}

impl ApiClient {
    /// Submit once; only an exact no-session receipt permits takeover waiting and later creation.
    pub async fn create_session_admission(
        &self,
        token: &str,
        request: &CreateSessionRequest,
    ) -> Result<SessionAdmission, ApiError> {
        let response = self
            .client
            .post(self.endpoint("/api/v1/sessions"))
            .bearer_auth(token)
            .json(request)
            .send()
            .await
            .map_err(ApiError::transport)?;
        let status = response.status();
        let body = read_response_body(response).await?;
        if status.is_success() {
            let response: Envelope<SessionData> = serde_json::from_str(&body)
                .map_err(|error| ApiError::decode(status, body, error))?;
            let session = response.data;
            if session.tool_account_id != request.tool_account_id
                || session.workspace_id != request.workspace_id
                || session.project_key != request.project_key
                || session.tool_type != request.tool_type
            {
                return Err(invalid_takeover_response());
            }
            return Ok(SessionAdmission::Created(Box::new(session)));
        }
        if status == StatusCode::CONFLICT {
            if let Ok(pending) = serde_json::from_str::<PendingEnvelope>(&body) {
                let view = pending.error.details;
                if pending.error.code == "MIGRATION_PENDING"
                    && view.account_id == request.tool_account_id
                    && canonical_id(&view.account_id)
                    && canonical_id(&view.takeover_id)
                    && view.reservation_committed
                    && !view.session_created
                    && view.takeover_status != TakeoverPhase::Committed
                {
                    return Ok(SessionAdmission::Takeover(view));
                }
            }
        }
        Err(ApiError::from_error_response(status, body))
    }

    /// Observe only the original owner-scoped takeover; this never renews or resubmits a task.
    pub async fn session_takeover_status(
        &self,
        token: &str,
        operation: &str,
        account: &str,
    ) -> Result<TakeoverStatus, ApiError> {
        if !canonical_id(operation) || !canonical_id(account) {
            return Err(invalid_takeover_response());
        }
        let response: Envelope<TakeoverStatus> = self
            .get(
                &format!("/api/v1/sessions/skill-takeovers/{operation}"),
                Some(token),
            )
            .await?;
        let view = response.data;
        let active = matches!(view.task_status.as_str(), "pending" | "leased" | "running");
        let terminal = matches!(
            view.task_status.as_str(),
            "succeeded" | "failed" | "cancelled" | "expired" | "missing"
        );
        if view.operation_id != operation
            || view.account_id != account
            || !(active || terminal)
            || (view.status == TakeoverPhase::Committed) != view.checkpoint_id.is_some()
            || view
                .checkpoint_id
                .as_deref()
                .is_some_and(|value| !canonical_id(value))
            || view.status != TakeoverPhase::Committed && terminal && !view.recovery_required
        {
            return Err(invalid_takeover_response());
        }
        Ok(view)
    }
}

fn canonical_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

fn invalid_takeover_response() -> ApiError {
    ApiError {
        status: None,
        code: Some("INVALID_TAKEOVER_RESPONSE".to_owned()),
        message: "Takeover response does not match the original account operation.".to_owned(),
    }
}
