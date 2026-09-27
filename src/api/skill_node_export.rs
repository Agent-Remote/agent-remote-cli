//! Original user authorization and direct read-only transfer of frozen Node snapshots.

mod recovery;
mod stream;
mod transport;
mod types;

pub use transport::download;
pub use types::{Authorization, Binding, Exported, Request};

use super::skills::SkillResult;
use super::{ApiClient, ApiError};

impl ApiClient {
    /// This grant can authorize a frozen read, but does not establish local data availability.
    pub async fn authorize_skill_node_export(
        &self,
        token: &str,
        snapshot: &str,
        request: &Request,
    ) -> Result<Authorization, ApiError> {
        types::id(snapshot)?;
        types::id(&request.device_id)?;
        types::id(&request.ssh_key_id)?;
        let http = self
            .client
            .post(self.endpoint(&format!(
                "/api/v1/skills/state/node-exports/{snapshot}/authorize"
            )))
            .json(request);
        let response: SkillResult<Authorization> =
            self.send_skill_request_bounded(http, token, 16384).await?;
        if let Some(value) = &response.data {
            types::require(
                response.status == "authorized"
                    && !response.committed
                    && !response.retryable
                    && response.operation_id.is_none()
                    && response.errors.is_empty(),
            )?;
            value.validate(snapshot, request)?;
        }
        response.data.ok_or_else(|| {
            let mut error = stream::unavailable();
            if let Some(code) = response
                .errors
                .first()
                .map(|item| item.code.as_str())
                .filter(|code| {
                    matches!(
                        *code,
                        "STATE_EXPORT_DENIED"
                            | "STATE_EXPORT_UNAVAILABLE"
                            | "STATE_EXPIRED"
                            | "SKILL_MANAGER_DISABLED"
                    )
                })
            {
                error.code = Some(code.to_owned());
            }
            error
        })
    }
}
