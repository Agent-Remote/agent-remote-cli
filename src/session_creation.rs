//! Session creation waits only on a Server receipt proving no session was created.

use crate::api::session_takeover::{SessionAdmission, TakeoverPhase};
use crate::api::{ApiClient, CreateSessionRequest, SessionData};
use crate::terminal::{self, Details};
use anyhow::{bail, Result};
use tokio::time::{sleep, timeout_at, Duration, Instant};

/// Stable launcher exit code for bounded creation waits.
#[derive(Debug)]
pub struct CreationExit(pub i32);

impl std::fmt::Display for CreationExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0 == 130 {
            "Session creation wait interrupted."
        } else {
            "Session creation wait timed out."
        })
    }
}
impl std::error::Error for CreationExit {}

/// Retain one deadline and interrupt handler across admission, observation and one resumed creation.
pub async fn create_with_takeover_wait(
    client: &ApiClient,
    token: &str,
    request: &CreateSessionRequest,
    bound: Duration,
) -> Result<SessionData> {
    let deadline = Instant::now() + bound;
    let signal = tokio::signal::ctrl_c();
    tokio::pin!(signal);
    let first = tokio::select! {
        biased;
        _ = &mut signal => return Err(CreationExit(130).into()),
        result = timeout_at(deadline, client.create_session_admission(token, request)) => result.map_err(|_| CreationExit(3))??,
    };
    let pending = match first {
        SessionAdmission::Created(session) => return Ok(*session),
        SessionAdmission::Takeover(pending) => pending,
    };
    terminal::note("Account skill takeover is pending; existing sessions may finish normally.");
    Details::new()
        .field("Takeover operation", &pending.takeover_id)
        .render();
    loop {
        let status = tokio::select! {
            biased;
            _ = &mut signal => return Err(CreationExit(130).into()),
            result = timeout_at(deadline, client.session_takeover_status(token, &pending.takeover_id, &pending.account_id)) => result.map_err(|_| CreationExit(3))??,
        };
        if status.recovery_required {
            bail!(
                "Account takeover requires recovery; retain operation {}.",
                pending.takeover_id
            );
        }
        if status.status == TakeoverPhase::Committed {
            break;
        }
        tokio::select! {
            biased;
            _ = &mut signal => return Err(CreationExit(130).into()),
            _ = sleep(deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(500))) => {}
        }
    }
    // The original request was explicitly rejected without a session. A committed takeover allows
    // one fresh creation; an uncertain response to that write must never trigger automatic replay.
    let resumed = tokio::select! {
        biased;
        _ = &mut signal => return Err(CreationExit(130).into()),
        result = timeout_at(deadline, client.create_session_admission(token, request)) => result.map_err(|_| CreationExit(3))??,
    };
    match resumed {
        SessionAdmission::Created(session) => Ok(*session),
        SessionAdmission::Takeover(_) => {
            bail!("Account admission remains pending after the original takeover committed.")
        }
    }
}
