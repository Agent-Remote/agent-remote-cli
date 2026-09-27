//! Owned output workers cannot submit, journal, or keep cancellation waiting on a pipe.

use anyhow::{Context, Result};

/// A display worker owns only the result; it cannot acquire submission or journal authority.
pub(super) async fn review(work: impl FnOnce() -> Result<()> + Send + 'static) -> Result<()> {
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("skill-result-output".to_owned())
        .spawn(move || {
            let _ = send.send(work());
        })?;
    receive.await.context("skill result output unavailable")?
}

/// Result output is irreversible: interruption must never append another envelope.
pub(super) async fn display(work: impl FnOnce() -> Result<()> + Send + 'static) -> Result<()> {
    super::interruption::mark_result_started();
    review(work).await
}

/// Finish output without letting a blocked pipe hide a retained interruption.
pub(super) async fn finish(
    json: bool,
    work: impl FnOnce() -> Result<()> + Send + 'static,
) -> Result<()> {
    if !json && super::interruption::is_cancelled() {
        return Err(super::SkillExit(130).into());
    }
    let output = display(work);
    tokio::pin!(output);
    tokio::select! {
        biased;
        result = &mut output => {
            if super::interruption::is_cancelled() {
                return Err(super::SkillExit(130).into());
            }
            result
        }
        signal = super::interruption::cancelled() => {
            signal?;
            // A previously interrupted command still gets a bounded chance to print its
            // original receipt/error. Never append a second result or wait for a pipe forever.
            let _ = tokio::time::timeout(std::time::Duration::from_millis(250), output).await;
            Err(super::SkillExit(130).into())
        }
    }
}
