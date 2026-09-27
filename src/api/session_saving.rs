//! Metadata for independently retained managed-session finalization operations.

use super::{ApiClient, ApiError, Envelope};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SaveStatus {
    AwaitingNode,
    CapturePending,
    LocalDurable,
    UploadPending,
    Persisted,
    PersistedUnclean,
    Published,
    Conflicted,
    Detached,
    Superseded,
}

impl SaveStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::AwaitingNode => "awaiting_node",
            Self::CapturePending => "capture_pending",
            Self::LocalDurable => "local_durable",
            Self::UploadPending => "upload_pending",
            Self::Persisted => "persisted",
            Self::PersistedUnclean => "persisted_unclean",
            Self::Published => "published",
            Self::Conflicted => "conflicted",
            Self::Detached => "detached",
            Self::Superseded => "superseded",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::CapturePending
                | Self::Published
                | Self::Conflicted
                | Self::Detached
                | Self::Superseded
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureError {
    QuotaExceeded,
    InsufficientStorage,
    PortabilityError,
    CaptureFailed,
}

impl CaptureError {
    pub fn label(self) -> &'static str {
        match self {
            Self::QuotaExceeded => "quota_exceeded",
            Self::InsufficientStorage => "insufficient_storage",
            Self::PortabilityError => "portability_error",
            Self::CaptureFailed => "capture_failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionSavingStatus {
    pub operation_id: String,
    pub session_id: String,
    pub account_id: String,
    pub process_status: String,
    pub process_stopped: bool,
    pub status: SaveStatus,
    #[serde(default)]
    pub capture_error: Option<CaptureError>,
    pub unclean: Option<bool>,
    pub finalization_id: Option<String>,
    pub checkpoint_id: Option<String>,
    pub publication_id: Option<String>,
    pub content_retained: bool,
}

impl SessionSavingStatus {
    fn valid_progress(&self) -> bool {
        if self.capture_error.is_some() != (self.status == SaveStatus::CapturePending) {
            return false;
        }
        let incoming = self.finalization_id.is_some() && self.checkpoint_id.is_some();
        let published = self.publication_id.is_some();
        let has_input = self.unclean.is_some();
        match self.status {
            SaveStatus::AwaitingNode => {
                !self.process_stopped
                    && !has_input
                    && self.finalization_id.is_none()
                    && self.checkpoint_id.is_none()
                    && !published
                    && !self.content_retained
            }
            SaveStatus::CapturePending | SaveStatus::LocalDurable => {
                self.process_stopped
                    && has_input
                    && self.finalization_id.is_none()
                    && self.checkpoint_id.is_none()
                    && !published
                    && !self.content_retained
            }
            SaveStatus::UploadPending => {
                self.finalization_id.is_some()
                    && has_input
                    && self.checkpoint_id.is_none()
                    && !published
                    && !self.content_retained
            }
            SaveStatus::Persisted => incoming && !published && self.unclean == Some(false),
            SaveStatus::PersistedUnclean => incoming && !published && self.unclean == Some(true),
            SaveStatus::Published => incoming && published && self.unclean == Some(false),
            SaveStatus::Conflicted | SaveStatus::Detached | SaveStatus::Superseded => {
                incoming && published && has_input
            }
        }
    }
}

impl ApiClient {
    /// Read the original owner-scoped operation without submitting stop or saving work.
    pub async fn session_saving_status(
        &self,
        token: &str,
        operation_id: &str,
    ) -> Result<SessionSavingStatus, ApiError> {
        let operation_id = uuid::Uuid::parse_str(operation_id)
            .map_err(|_| super::skills::invalid_skill_response())?
            .to_string();
        let response: Envelope<SessionSavingStatus> = self
            .get(
                &format!(
                    "/api/v1/sessions/skill-finalizations/{}",
                    super::url_encode(&operation_id)
                ),
                Some(token),
            )
            .await
            .map_err(|error| {
                if error
                    .status_code()
                    .is_some_and(|status| (200..300).contains(&status))
                {
                    super::skills::invalid_skill_response()
                } else {
                    error
                }
            })?;
        let view = response.data;
        let identifiers = [
            Some(view.session_id.as_str()),
            Some(view.account_id.as_str()),
            view.finalization_id.as_deref(),
            view.checkpoint_id.as_deref(),
            view.publication_id.as_deref(),
        ];
        if view.operation_id != operation_id
            || identifiers
                .into_iter()
                .flatten()
                .any(|id| uuid::Uuid::parse_str(id).is_err())
            || !view.valid_progress()
        {
            return Err(super::skills::invalid_skill_response());
        }
        Ok(view)
    }
}
