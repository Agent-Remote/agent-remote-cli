//! Bounded asynchronous input; detached threads never hold mutation authority.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::io::{BufRead, Read, Write};

pub(super) async fn confirm(prompt: &str) -> Result<bool> {
    let line = read_line(format!("{prompt} [y/N] "), 4096).await?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub(super) async fn review<T: Serialize>(request: &T) -> Result<bool> {
    confirm(&format!(
        "{}\nApply this configuration change for new sessions?",
        serde_json::to_string_pretty(request)?
    ))
    .await
}

pub(super) async fn read_line(prompt: String, limit: u64) -> Result<String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    // Neither blocked stdin nor stderr may occupy the async task that receives cancellation.
    // This thread can only return input; losing the receiver cannot authorize any operation.
    std::thread::Builder::new()
        .name("skill-input".to_owned())
        .spawn(move || {
            let result = (|| -> Result<String> {
                let mut output = std::io::stderr().lock();
                output.write_all(prompt.as_bytes())?;
                output.flush()?;
                drop(output);
                let mut line = String::new();
                std::io::stdin()
                    .lock()
                    .take(limit + 1)
                    .read_line(&mut line)?;
                if line.len() as u64 > limit {
                    bail!("interactive input exceeds its byte limit");
                }
                Ok(line)
            })();
            let _ = send.send(result);
        })?;
    receive.await.context("confirmation input unavailable")?
}

/// Output-only work remains cancellable even when a caller does not drain stderr.
pub(super) async fn write(text: String) -> Result<()> {
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("skill-source-output".to_owned())
        .spawn(move || {
            let result = (|| -> Result<()> {
                let mut output = std::io::stderr().lock();
                output.write_all(text.as_bytes())?;
                output.flush()?;
                Ok(())
            })();
            let _ = send.send(result);
        })?;
    receive.await.context("source output unavailable")?
}
