//! Output observation and bounded clipboard task ownership for an SSH attachment.
use super::{
    clipboard::CopyResult, clipboard_stream::ClipboardStream, login_clipboard::LoginScreen,
};
use anyhow::{Context, Result};
use std::{future::Future, io::Write};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) struct Feedback {
    pub native_copy: Option<bool>,
    pub incomplete: bool,
}

pub(super) async fn observe<R, W, F, C, CopyFuture>(
    output: &mut R,
    writer: &mut W,
    login_copy: bool,
    selection_copy: bool,
    size: F,
    copy: C,
    exit: Option<&super::exit::ExitState>,
) -> Result<Feedback>
where
    R: AsyncRead + Unpin,
    W: Write,
    F: Fn() -> (u16, u16),
    C: Fn(String) -> CopyFuture,
    CopyFuture: Future<Output = CopyResult> + Send + 'static,
{
    let (rows, cols) = size();
    let mut screen = login_copy.then(|| LoginScreen::new(rows, cols));
    let mut clipboard_stream = ClipboardStream::default();
    let mut buffer = [0; 16384];
    let mut settled = false;
    let mut copying = tokio::task::JoinSet::new();
    let mut pending = None;
    let mut native_copy = None;
    let mut eof = false;
    let mut terminal_exit = super::exit::Output::default();
    let mut copy_incomplete = false;
    let mut drain_deadline = tokio::time::Instant::now();
    loop {
        tokio::select! {
            read = output.read(&mut buffer), if !eof => {
                let count = read.context("failed to read SSH output")?;
                if count == 0 {
                    writer.write_all(&clipboard_stream.finish())?;
                    eof = true;
                    drain_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
                    if pending.is_none() && !settled {
                        pending = screen.as_mut().and_then(LoginScreen::take_url);
                    }
                }
                let visible = if selection_copy {
                    clipboard_stream.process(&buffer[..count])
                } else { buffer[..count].to_vec() };
                if let Some(exit) = exit {
                    terminal_exit.observe(&visible, exit);
                    if count == 0 { exit.begin(); }
                }
                let stdout = &mut *writer;
                stdout.write_all(&visible)?;
                if exit.is_some_and(|exit| exit.started()) { stdout.write_all(super::exit::RESET)?; }
                stdout.flush()?;
                let (rows, cols) = size();
                if let Some(screen) = screen.as_mut() { screen.process(&visible, rows, cols); }
                if !eof { settled = false; }
                if clipboard_stream.take_rejected() {
                    copy_incomplete = true;
                    stdout.write_all(b"\x07")?;
                    stdout.flush()?;
                }
                if let Some(text) = clipboard_stream.take_copy() {
                    pending = Some(text);
                    // Explicit selection wins over automatic login copying.
                    let _ = screen.as_mut().and_then(LoginScreen::take_url);
                    settled = true;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(150)), if !settled && !eof => {
                settled = true;
                if let Some(url) = screen.as_mut().and_then(LoginScreen::take_url) { pending = Some(url); }
            }
            _ = tokio::time::sleep_until(drain_deadline), if eof => {
                copy_incomplete = true;
                break;
            }
            result = copying.join_next(), if !copying.is_empty() => {
                match result {
                    Some(Ok(CopyResult::Native)) => {
                        native_copy = Some(true);
                    }
                    Some(Ok(CopyResult::Terminal(sequence))) => {
                        let stdout = &mut *writer;
                        stdout.write_all(sequence.as_bytes())?;
                        stdout.flush()?;
                        native_copy = Some(false);
                    }
                    _ => { copy_incomplete = true; }
                }
            }
        }
        if eof && copying.is_empty() && pending.is_none() {
            break;
        }
        if copying.is_empty() {
            if let Some(url) = pending.take() {
                copying.spawn(copy(url));
            }
        }
    }
    copying.abort_all();
    while copying.join_next().await.is_some() {}
    Ok(Feedback {
        native_copy,
        incomplete: copy_incomplete,
    })
}
#[cfg(test)]
#[path = "../../tests/unit/src/ssh/interactive/tests.rs"]
mod tests;
