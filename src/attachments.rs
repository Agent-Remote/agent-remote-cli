//! Cross-platform local attachment capture and isolated attachment staging.
//!
//! Claude's terminal UI accepts image/file paths as attachments.  A remote
//! session cannot read the local desktop clipboard or local drag paths, so the
//! launcher stages those bytes in an application-owned temporary directory,
//! transfers a bounded archive over SSH, verifies acknowledgement, and returns
//! an account-private remote path outside the project directory.

mod archive;
mod capture;
mod input;
mod paths;
pub(crate) use input::{InputDecoder, InputEvent};
pub use paths::parse_dropped_paths;
mod transfer;

use crate::{api::AttachSessionData, config::AppPaths};
use anyhow::{bail, Result};
#[cfg(unix)]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES_PER_PASTE: usize = 32;
const BRACKETED_PASTE_START: &[u8] = b"\x1b[200~";
const BRACKETED_PASTE_END: &[u8] = b"\x1b[201~";

#[derive(Clone, Debug)]
pub struct AttachmentContext {
    transfer: Arc<transfer::Transfer>,
    cancelled: Arc<AtomicBool>,
}

pub(crate) struct CancellationGuard(AttachmentContext);
impl Drop for CancellationGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClipboardPayload {
    Image {
        bytes: Vec<u8>,
        extension: &'static str,
    },
    Files(Vec<PathBuf>),
}

impl AttachmentContext {
    #[allow(dead_code)]
    pub fn new(attach: &AttachSessionData, account_path: String, backend: &str) -> Result<Self> {
        Ok(Self {
            transfer: Arc::new(transfer::Transfer::new(attach, account_path, backend)?),
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(crate) fn cancellation_guard(&self) -> CancellationGuard {
        CancellationGuard(self.clone())
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Transfer one verified batch; only acknowledged remote paths may enter the prompt.
    pub async fn stage_payload(
        &self,
        paths: &AppPaths,
        payload: ClipboardPayload,
    ) -> Result<Vec<String>> {
        let cancelled = self.cancelled.clone();
        let archive =
            tokio::task::spawn_blocking(move || archive::pack(payload, cancelled)).await??;
        if self.cancelled.load(Ordering::Acquire) {
            bail!("attachment transfer cancelled");
        }
        self.transfer.upload(paths, archive).await
    }

    /// Remove only this connection's files. Failed cleanup retains a retry receipt.
    #[allow(dead_code)]
    pub async fn cleanup(&self, paths: &AppPaths) -> Result<()> {
        self.cancel();
        self.transfer.cleanup(paths).await
    }
}

fn validate_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty()
        || session_id.len() > 128
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        bail!("invalid session id for attachment transfer");
    }
    Ok(())
}

/// Read the richest available local clipboard payload. Text is intentionally
/// omitted so ordinary Ctrl+V keeps Claude's native text behavior.
pub async fn read_clipboard_payload() -> Option<ClipboardPayload> {
    // An SSH jump host's desktop is not the requesting user's clipboard.
    if ["SSH_CONNECTION", "SSH_TTY"]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|v| !v.is_empty()))
    {
        return None;
    }
    capture::read().await
}

fn set_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
