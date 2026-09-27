//! Negotiated complete recovery streams use bounded entry frames and a private disk index.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::io::AsyncRead;

use super::{
    stream::{read_frame, receive_bytes, require_eof, unavailable},
    types::{digest, require, Binding, Exported},
};
use crate::{
    api::ApiError,
    skills::{
        export::ExportBundle,
        manifest::{ContentKind, Entry, EntryKind},
        recovery_export::{validate_start, RecoveryBundle, RecoverySummary},
    },
};

const FORMAT: &str = "agent-remote-skill-node-recovery-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u8,
    binding: Binding,
    recovery_digest: String,
    unclean: bool,
    entries: u64,
    file_bytes: u64,
    file_objects: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    version: u8,
    recovery_digest: String,
    entries: u64,
    file_bytes: u64,
    file_objects: u64,
    complete: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    path: String,
    kind: EntryKind,
    mode: u32,
    size: u64,
    sha256: String,
    target: String,
    content_kind: ContentKind,
    dependency: String,
}

impl Start {
    fn entry(self) -> Result<Entry, ApiError> {
        let entry = Entry {
            path: self.path,
            kind: self.kind,
            mode: self.mode,
            size: self.size,
            sha256: self.sha256,
            target: self.target,
            content_kind: self.content_kind,
            dependency: self.dependency,
        };
        validate_start(&entry).map_err(|_| unavailable())?;
        Ok(entry)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    sha256: String,
    content_kind: ContentKind,
}

#[derive(Serialize)]
struct Metadata<'a> {
    format: &'static str,
    binding: &'a Binding,
    recovery_digest: &'a str,
    unclean: bool,
    entries: u64,
    file_bytes: u64,
    file_objects: u64,
}

pub(super) async fn receive(
    reader: &mut (impl AsyncRead + Unpin),
    binding: &Binding,
    output: PathBuf,
) -> Result<(ExportBundle, Exported), ApiError> {
    let header: Header = read_frame(reader, 4096, false).await?;
    header.binding.validate()?;
    digest(&header.recovery_digest)?;
    require(
        header.version == 1
            && &header.binding == binding
            && header.entries <= i64::MAX as u64
            && header.file_bytes <= i64::MAX as u64
            && header.file_objects <= header.entries
            && (header.file_objects != 0 || header.file_bytes == 0),
    )?;
    let expected = RecoverySummary {
        entries: header.entries,
        file_bytes: header.file_bytes,
        file_objects: header.file_objects,
        digest: header.recovery_digest.clone(),
    };
    let (mut bundle, result) = tokio::task::spawn_blocking(move || {
        let bundle = RecoveryBundle::prepare(
            &output,
            &Metadata {
                format: FORMAT,
                binding: &header.binding,
                recovery_digest: &header.recovery_digest,
                unclean: header.unclean,
                entries: header.entries,
                file_bytes: header.file_bytes,
                file_objects: header.file_objects,
            },
        )
        .map_err(|_| unavailable())?;
        let result = Exported {
            format: FORMAT,
            binding: header.binding,
            tree_digest: header.recovery_digest,
            unclean: header.unclean,
            output: PathBuf::new(),
            file_objects: usize::try_from(header.file_objects).map_err(|_| unavailable())?,
        };
        Ok::<_, ApiError>((bundle, result))
    })
    .await
    .map_err(|_| unavailable())??;
    for _ in 0..expected.entries {
        let start: Start = read_frame(reader, 64 << 10, false).await?;
        let mut entry = start.entry()?;
        let observed = bundle.summary();
        require(
            entry.size <= expected.file_bytes.saturating_sub(observed.file_bytes)
                && (entry.kind != EntryKind::File || observed.file_objects < expected.file_objects),
        )?;
        let original = entry.clone();
        let (returned, file) = tokio::task::spawn_blocking(move || {
            let file = bundle.begin(original).map_err(|_| unavailable());
            (bundle, file)
        })
        .await
        .map_err(|_| unavailable())?;
        bundle = returned;
        if let Some(file) = file? {
            let writer = receive_bytes(reader, file, entry.size).await?;
            let content: Content = read_frame(reader, 4096, false).await?;
            entry.sha256 = content.sha256;
            entry.content_kind = content.content_kind;
            let actual = entry.clone();
            tokio::task::spawn_blocking(move || {
                actual.validate().map_err(|_| unavailable())?;
                require(
                    format!("{:x}", writer.digest.finalize()) == actual.sha256
                        && writer.text.finish() == (actual.content_kind == ContentKind::Text),
                )?;
                writer.file.sync_all().map_err(|_| unavailable())
            })
            .await
            .map_err(|_| unavailable())??;
        }
        bundle = tokio::task::spawn_blocking(move || {
            bundle.complete(entry).map_err(|_| unavailable())?;
            Ok::<_, ApiError>(bundle)
        })
        .await
        .map_err(|_| unavailable())??;
    }
    let footer: Completion = read_frame(reader, 4096, true).await?;
    require(
        footer.version == 1
            && footer.complete
            && footer.recovery_digest == expected.digest
            && footer.entries == expected.entries
            && footer.file_bytes == expected.file_bytes
            && footer.file_objects == expected.file_objects,
    )?;
    require_eof(reader).await?;
    let bundle =
        tokio::task::spawn_blocking(move || bundle.finish(&expected).map_err(|_| unavailable()))
            .await
            .map_err(|_| unavailable())??;
    Ok((bundle, result))
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
