//! Responsive input while a clipboard helper or attachment upload is in flight.
use super::{bracketed_attachment_text, exit, pty, resize_if_needed, stdin::StdinReader};
use crate::{
    attachments::{self, AttachmentContext, InputDecoder, InputEvent},
    config::AppPaths,
};
use anyhow::{bail, Result};
use std::{collections::VecDeque, future::Future, time::Duration};
use tokio::io::{AsyncWrite, AsyncWriteExt};

#[derive(Default)]
struct InputQueue {
    decoder: InputDecoder,
    detach: exit::Input,
    deferred: VecDeque<Vec<u8>>,
}

impl InputQueue {
    async fn receive(
        &mut self,
        input: &mut StdinReader,
        exit: &exit::ExitState,
    ) -> Result<Vec<u8>> {
        if let Some(bytes) = self.deferred.pop_front() {
            return Ok(bytes);
        }
        let bytes = input.recv().await?.unwrap_or_default();
        Ok(self.detach.filter(&bytes, exit).to_vec())
    }

    async fn upload<W, F>(
        &mut self,
        remote: &mut W,
        input: &mut tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
        exit: &exit::ExitState,
        attachment: &AttachmentContext,
        operation: F,
    ) -> Result<Option<Vec<String>>>
    where
        W: AsyncWrite + Unpin,
        F: Future<Output = Result<Option<Vec<String>>>>,
    {
        tokio::pin!(operation);
        let mut queued: usize = self.deferred.iter().map(Vec::len).sum();
        loop {
            tokio::select! {
                result = &mut operation => return result,
                _ = exit.cancelled() => {
                    attachment.cancel();
                    bail!("attachment transfer cancelled");
                }
                bytes = input.recv() => {
                    let bytes = bytes.transpose()?.unwrap_or_default();
                    if bytes.is_empty() { attachment.cancel(); bail!("terminal input closed"); }
                    let filtered = self.detach.filter(&bytes, exit);
                    if exit.started() {
                        // Keys received during an upload were queued locally;
                        // deliver the detach prefix once without waiting for it.
                        attachment.cancel();
                        remote.write_all(b"\x02d").await?;
                        remote.flush().await?;
                        bail!("attachment transfer cancelled");
                    }
                    queued += filtered.len();
                    self.deferred.push_back(filtered.to_vec());
                    if queued > 1024 * 1024 { bail!("too much terminal input queued during attachment transfer"); }
                }
            }
        }
    }
}

pub(super) async fn relay_input<W>(
    mut remote: W,
    resize: pty::ResizeHandle,
    mut input: StdinReader,
    paths: AppPaths,
    attachment: AttachmentContext,
    exit: exit::ExitState,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut queue = InputQueue::default();
    let mut previous_size = pty::command_size();
    loop {
        let pending_prefix = queue.decoder.has_pending_prefix();
        let bytes = tokio::select! {
            result = queue.receive(&mut input, &exit) => result?,
            _ = tokio::time::sleep(Duration::from_millis(40)), if pending_prefix => {
                remote.write_all(&queue.decoder.flush_prefix()).await?;
                remote.flush().await?;
                continue;
            }
        };
        if exit.started() {
            // The triggering bytes may end a prefix sent in an earlier read.
            // Never start a clipboard operation once detach was requested.
            remote.write_all(&bytes).await?;
            remote.flush().await?;
            attachment.cancel();
            return Ok(());
        }
        if bytes.is_empty() {
            break;
        }
        resize_if_needed(&resize, &mut previous_size);
        for event in queue.decoder.feed(&bytes) {
            let mut fallback = vec![0x16];
            let prepared = match event {
                InputEvent::Bytes(bytes) => {
                    remote.write_all(&bytes).await?;
                    continue;
                }
                InputEvent::ClipboardPaste => {
                    queue
                        .upload(
                            &mut remote,
                            &mut input.receiver,
                            &exit,
                            &attachment,
                            async {
                                let payload = tokio::time::timeout(
                                    Duration::from_secs(5),
                                    attachments::read_clipboard_payload(),
                                )
                                .await
                                .ok()
                                .flatten();
                                match payload {
                                    Some(payload) => {
                                        attachment.stage_payload(&paths, payload).await.map(Some)
                                    }
                                    None => Ok(None),
                                }
                            },
                        )
                        .await
                }
                InputEvent::BracketedPaste(value) => {
                    fallback = b"\x1b[200~".to_vec();
                    fallback.extend_from_slice(&value);
                    fallback.extend_from_slice(b"\x1b[201~");
                    queue
                        .upload(
                            &mut remote,
                            &mut input.receiver,
                            &exit,
                            &attachment,
                            async {
                                let files = tokio::time::timeout(
                                    Duration::from_secs(5),
                                    attachments::parse_dropped_paths(
                                        std::str::from_utf8(&value).unwrap_or_default(),
                                    ),
                                )
                                .await
                                .ok()
                                .flatten();
                                match files {
                                    Some(files) => attachment
                                        .stage_payload(
                                            &paths,
                                            attachments::ClipboardPayload::Files(files),
                                        )
                                        .await
                                        .map(Some),
                                    None => Ok(None),
                                }
                            },
                        )
                        .await
                }
            };
            if exit.started() {
                return Ok(());
            }
            match prepared {
                Ok(Some(files)) => remote.write_all(&bracketed_attachment_text(&files)).await?,
                Ok(None) => remote.write_all(&fallback).await?,
                Err(_) if exit.started() => return Ok(()),
                Err(_) => crate::terminal::warning_line(
                    "Attachment upload failed; no path was inserted. Retry the paste or file drop.",
                ),
            }
        }
        remote.flush().await?;
    }
    for event in queue.decoder.finish() {
        if let InputEvent::Bytes(bytes) = event {
            remote.write_all(&bytes).await?;
        }
    }
    remote.flush().await?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/src/ssh/attachment_input.rs"]
mod tests;
