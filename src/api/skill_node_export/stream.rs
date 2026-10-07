//! Framed frozen objects become publishable only after complete local verification.

use std::{fs::File, io::Write, path::PathBuf, time::Duration};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::types::{digest, require, Binding, Exported};
use crate::api::{utf8_text::Utf8Text, ApiError};
use crate::skills::{
    export::ExportBundle,
    manifest::{ContentKind, Entry, Manifest},
};

const FORMAT: &str = "agent-remote-skill-node-snapshot-v1";
const SCAN_TIMEOUT: Duration = Duration::from_secs(900);
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u8,
    binding: Binding,
    tree_digest: String,
    unclean: bool,
    manifest: Manifest,
    file_objects: usize,
}

#[derive(Serialize)]
struct Metadata<'a> {
    format: &'static str,
    binding: &'a Binding,
    tree_digest: &'a str,
    unclean: bool,
    file_objects: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    version: u8,
    tree_digest: String,
    file_objects: usize,
    complete: bool,
}

pub(super) async fn receive(
    reader: &mut (impl AsyncRead + Unpin),
    binding: &Binding,
    output: PathBuf,
) -> Result<(ExportBundle, Exported), ApiError> {
    let mut magic = [0; 8];
    read_after_scan(reader, &mut magic).await?;
    if magic == *b"ARSKRC\x00\x01" {
        return super::recovery::receive(reader, binding, output).await;
    }
    require(magic == *b"ARSKEX\x00\x01")?;
    let header: Header = read_frame(reader, 64 << 20, false).await?;
    header.binding.validate()?;
    digest(&header.tree_digest)?;
    require(header.version == 1 && &header.binding == binding)?;
    let (mut bundle, result) = tokio::task::spawn_blocking(move || {
        require(header.manifest.digest().map_err(|_| unavailable())? == header.tree_digest)?;
        let bundle = ExportBundle::prepare(
            &output,
            &header.manifest,
            &Metadata {
                format: FORMAT,
                binding: &header.binding,
                tree_digest: &header.tree_digest,
                unclean: header.unclean,
                file_objects: header.file_objects,
            },
        )
        .map_err(|_| unavailable())?;
        require(bundle.objects().len() == header.file_objects)?;
        let result = Exported {
            format: FORMAT,
            binding: header.binding,
            tree_digest: header.tree_digest,
            unclean: header.unclean,
            output: PathBuf::new(),
            file_objects: header.file_objects,
        };
        Ok::<_, ApiError>((bundle, result))
    })
    .await
    .map_err(|_| unavailable())??;
    for index in 0..bundle.objects().len() {
        let (returned, file) = tokio::task::spawn_blocking(move || {
            let file = bundle.create_object(index).map_err(|_| unavailable());
            (bundle, file)
        })
        .await
        .map_err(|_| unavailable())?;
        bundle = returned;
        receive_object(reader, file?, &bundle.objects()[index]).await?;
    }
    let completion: Completion = read_frame(reader, 4096, true).await?;
    require(
        completion.version == 1
            && completion.complete
            && completion.tree_digest == result.tree_digest
            && completion.file_objects == result.file_objects,
    )?;
    require_eof(reader).await?;
    Ok((bundle, result))
}

pub(super) async fn require_eof(reader: &mut (impl AsyncRead + Unpin)) -> Result<(), ApiError> {
    let mut extra = [0];
    let length = tokio::time::timeout(Duration::from_secs(30), reader.read(&mut extra))
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    require(length == 0)
}

async fn read_exact(
    reader: &mut (impl AsyncRead + Unpin),
    bytes: &mut [u8],
) -> Result<(), ApiError> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let count = tokio::time::timeout(READ_IDLE_TIMEOUT, reader.read(remaining))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        require(count > 0)?;
        remaining = &mut remaining[count..];
    }
    Ok(())
}

async fn read_after_scan(
    reader: &mut (impl AsyncRead + Unpin),
    bytes: &mut [u8],
) -> Result<(), ApiError> {
    let (first, remaining) = bytes.split_first_mut().ok_or_else(unavailable)?;
    // The first byte proves scan completion; partial prefixes then use ordinary progress bounds.
    tokio::time::timeout(SCAN_TIMEOUT, reader.read_exact(std::slice::from_mut(first)))
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    read_exact(reader, remaining).await
}

pub(super) async fn read_frame<T: DeserializeOwned + Send + 'static>(
    reader: &mut (impl AsyncRead + Unpin),
    maximum: usize,
    wait_for_scan: bool,
) -> Result<T, ApiError> {
    let mut size = [0; 4];
    if wait_for_scan {
        read_after_scan(reader, &mut size).await?;
    } else {
        read_exact(reader, &mut size).await?;
    }
    let size = u32::from_be_bytes(size) as usize;
    require(size > 0 && size <= maximum)?;
    let mut bytes = vec![0; size];
    read_exact(reader, &mut bytes).await?;
    tokio::task::spawn_blocking(move || serde_json::from_slice(&bytes).map_err(|_| unavailable()))
        .await
        .map_err(|_| unavailable())?
}

async fn receive_object(
    reader: &mut (impl AsyncRead + Unpin),
    file: File,
    entry: &Entry,
) -> Result<(), ApiError> {
    let writer = receive_bytes(reader, file, entry.size).await?;
    let mut verified = [0];
    read_exact(reader, &mut verified).await?;
    require(verified == [1])?;
    let expected = entry.clone();
    tokio::task::spawn_blocking(move || {
        require(
            format!("{:x}", writer.digest.finalize()) == expected.sha256
                && writer.text.finish() == (expected.content_kind == ContentKind::Text),
        )?;
        writer.file.sync_all().map_err(|_| unavailable())
    })
    .await
    .map_err(|_| unavailable())?
}

pub(super) async fn receive_bytes(
    reader: &mut (impl AsyncRead + Unpin),
    file: File,
    size: u64,
) -> Result<ObjectWriter, ApiError> {
    let mut writer = ObjectWriter {
        file,
        digest: Sha256::new(),
        text: Utf8Text::default(),
    };
    let mut remaining = size;
    while remaining > 0 {
        let length = remaining.min(64 * 1024) as usize;
        let mut bytes = vec![0; length];
        read_exact(reader, &mut bytes).await?;
        remaining -= length as u64;
        writer = tokio::task::spawn_blocking(move || {
            writer.file.write_all(&bytes).map_err(|_| unavailable())?;
            writer.digest.update(&bytes);
            writer.text.update(&bytes);
            Ok::<_, ApiError>(writer)
        })
        .await
        .map_err(|_| unavailable())??;
    }
    Ok(writer)
}

pub(super) struct ObjectWriter {
    pub(super) file: File,
    pub(super) digest: Sha256,
    pub(super) text: Utf8Text,
}

pub(super) fn unavailable() -> ApiError {
    ApiError { status: None, code: Some("STATE_EXPORT_UNAVAILABLE".to_owned()),
        message: "Snapshot export did not complete; no bundle was published. Check the source Node, local SSH key and destination, then retry.".to_owned() }
}
#[cfg(test)]
#[path = "../../../tests/unit/src/api/skill_node_export/stream_tests.rs"]
mod tests;
