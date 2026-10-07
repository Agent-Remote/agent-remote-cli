use std::time::Duration;

use tokio::time::{sleep, timeout_at, Instant};

use super::{ApiClient, ApiError};

impl ApiClient {
    // Startup and SSH-key authorization are independent. Never request an attach
    // command while the original session is still preparing its runtime spec.
    pub(super) async fn wait_for_session_readiness(
        &self,
        token: &str,
        session_id: &str,
        budget: Duration,
    ) -> Result<(), ApiError> {
        let deadline = Instant::now() + budget;
        let wait = async {
            loop {
                let session = self.get_tool_session(token, session_id).await?;
                if session.id != session_id {
                    return Err(ApiError {
                        status: None,
                        code: Some("SESSION_IDENTITY_MISMATCH".into()),
                        message: format!("session readiness response does not match {session_id}"),
                    });
                }
                match session.status.as_str() {
                    "running" | "active" => return Ok(()),
                    "starting" => sleep(Duration::from_secs(1)).await,
                    _ => {
                        return Err(ApiError {
                            status: None,
                            code: Some("SESSION_NOT_ATTACHABLE".into()),
                            message: format!(
                                "session {session_id} is not attachable: {}",
                                session.status
                            ),
                        });
                    }
                }
            }
        };
        timeout_at(deadline, wait).await.unwrap_or_else(|_| {
            Err(ApiError {
                status: None,
                code: Some("SESSION_START_TIMEOUT".into()),
                message: format!(
                    "session {session_id} did not become ready within {} seconds; \
                     the existing session is retained. Retry with: agent-remote attach {session_id}",
                    budget.as_secs()
                ),
            })
        })
    }
}
#[cfg(test)]
#[path = "../../tests/unit/src/api/session_readiness_tests.rs"]
mod tests;
