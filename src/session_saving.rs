//! Bounded observation of saving after runtime stop; this never submits another stop or upload.

use crate::api::session_saving::{SaveStatus, SessionSavingStatus};
use crate::api::ApiClient;
use crate::terminal::{self, Details};
use anyhow::{bail, Result};
use tokio::time::{sleep, timeout_at, Duration, Instant};

/// Stable launcher exit code for pending, interrupted, or reviewable saving outcomes.
#[derive(Debug)]
pub struct SavingExit(pub i32);

impl std::fmt::Display for SavingExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            130 => "Saving wait interrupted; the original operation remains available.",
            3 => "Process stop or saving confirmation remains pending; query the original operation again.",
            _ => "Skill saving requires attention; inspect the original operation and recovery guidance.",
        })
    }
}

impl std::error::Error for SavingExit {}

/// Observe the original operation under one deadline and retained interruption signal.
pub async fn observe(
    client: &ApiClient,
    token: &str,
    operation_id: &str,
    session_id: Option<&str>,
    wait: bool,
    timeout: u64,
) -> Result<()> {
    let operation_id = uuid::Uuid::parse_str(operation_id)?.to_string();
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let signal = tokio::signal::ctrl_c();
    tokio::pin!(signal);
    let mut latest = None;
    let code = loop {
        let response = tokio::select! {
            biased;
            _ = &mut signal => break 130,
            response = timeout_at(deadline, client.session_saving_status(token, &operation_id)) => response,
        };
        match response {
            Err(_) => break 3,
            Ok(Err(error)) => {
                if let Some(view) = &latest {
                    render(view);
                } else {
                    Details::new().field("Operation", &operation_id).render();
                }
                return Err(error.into());
            }
            Ok(Ok(view)) => {
                if view.operation_id != operation_id
                    || session_id.is_some_and(|id| view.session_id != id)
                {
                    bail!("saving response differs from the original operation");
                }
                let terminal = view.status.terminal() && (!wait || view.process_stopped);
                let next_code = if terminal && view.status != SaveStatus::Published {
                    1
                } else {
                    0
                };
                latest = Some(view);
                if !wait || terminal {
                    break next_code;
                }
            }
        }
        tokio::select! {
            biased;
            _ = &mut signal => break 130,
            _ = sleep(deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(500))) => {}
        }
    };
    if let Some(view) = &latest {
        render(view);
    } else {
        Details::new().field("Operation", &operation_id).render();
    }
    if code != 0 {
        return Err(SavingExit(code).into());
    }
    Ok(())
}

fn render(view: &SessionSavingStatus) {
    if let Some(error) = view.capture_error {
        terminal::warning_line(
            "Process stopped; capture failed. Local durability is not confirmed.",
        );
        Details::new()
            .field("Capture error", error.label())
            .render();
        terminal::warning_line(format!(
            "Preserve the retained Node data with: agent-remote skill state export --scope account-directory --account-id {} --snapshot {} --output ./recovered-skill-state",
            view.account_id, view.operation_id
        ));
    } else if view.process_stopped && !view.status.terminal() {
        terminal::warning_line("Process stopped; data saving pending");
    } else if !view.process_stopped {
        terminal::warning_line("Process stop has not been confirmed by the Node");
    }
    Details::new()
        .field("Operation", &view.operation_id)
        .field("Session", &view.session_id)
        .status("Process", &view.process_status)
        .status("Skill saving", view.status.label())
        .field("Content retained", view.content_retained.to_string())
        .field(
            "Unclean",
            view.unclean
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".into()),
        )
        .render();
}
