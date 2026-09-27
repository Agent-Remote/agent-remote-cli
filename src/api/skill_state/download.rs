//! Stream only authorized manifest objects into private files with constant-memory verification.

use std::fs::File;
use std::io::Write;

use crate::api::utf8_text::Utf8Text;
use sha2::{Digest, Sha256};

use super::{check, CheckpointTree};
use crate::api::skills::{invalid_skill_response, SkillResult};
use crate::api::{read_response_body_bounded, ApiClient, ApiError, MAX_API_RESPONSE_BYTES};
use crate::skills::manifest::{ContentKind, Entry, EntryKind};

impl ApiClient {
    /// The caller owns private staging. Nothing is published until every object is verified.
    pub async fn download_checkpoint_file(
        &self,
        token: &str,
        tree: &CheckpointTree,
        entry: &Entry,
        file: File,
    ) -> Result<(), ApiError> {
        check::id(&tree.checkpoint_id)?;
        entry.validate().map_err(|_| invalid_skill_response())?;
        check::require(
            entry.kind == EntryKind::File
                && tree
                    .manifest
                    .entries
                    .binary_search_by(|candidate| candidate.path.cmp(&entry.path))
                    .ok()
                    .is_some_and(|index| tree.manifest.entries[index] == *entry),
        )?;
        let request = self
            .client
            .get(self.endpoint(&format!(
                "/api/v1/skills/state/checkpoints/{}/files/{}",
                tree.checkpoint_id, entry.sha256
            )))
            .bearer_auth(token)
            .timeout(std::time::Duration::from_secs(3600))
            .send();
        let mut response = tokio::time::timeout(std::time::Duration::from_secs(30), request)
            .await
            .map_err(|_| transport())?
            .map_err(|_| transport())?;
        let status = response.status();
        if !status.is_success() {
            let body = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                read_response_body_bounded(response, MAX_API_RESPONSE_BYTES),
            )
            .await
            .map_err(|_| transport())??;
            let code = serde_json::from_str::<SkillResult<serde_json::Value>>(&body)
                .ok()
                .filter(|r| {
                    r.schema_version == 1
                        && r.status == "failed"
                        && !r.committed
                        && r.data.is_none()
                })
                .and_then(|r| r.errors.into_iter().next().map(|e| e.code))
                .or_else(|| ApiError::from_error_response(status, body).code);
            return Err(ApiError {
                status: Some(status),
                code,
                message: "Checkpoint content could not be downloaded.".to_owned(),
            });
        }
        check::require(
            status == reqwest::StatusCode::OK
                && response.content_length() == Some(entry.size)
                && response
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    == Some(format!("\"{}\"", entry.sha256).as_str()),
        )?;
        let mut writer = VerifiedWriter {
            file,
            digest: Sha256::new(),
            size: 0,
            text: Utf8Text::default(),
        };
        while let Some(bytes) =
            tokio::time::timeout(std::time::Duration::from_secs(30), response.chunk())
                .await
                .map_err(|_| transport())?
                .map_err(|_| transport())?
        {
            check::require(writer.size.saturating_add(bytes.len() as u64) <= entry.size)?;
            writer = tokio::task::spawn_blocking(move || {
                writer.file.write_all(&bytes).map_err(|_| io_failure())?;
                writer.digest.update(&bytes);
                writer.text.update(&bytes);
                writer.size += bytes.len() as u64;
                Ok::<_, ApiError>(writer)
            })
            .await
            .map_err(|_| io_failure())??;
        }
        let expected = entry.clone();
        tokio::task::spawn_blocking(move || {
            check::require(
                writer.size == expected.size
                    && format!("{:x}", writer.digest.finalize()) == expected.sha256
                    && writer.text.finish() == (expected.content_kind == ContentKind::Text),
            )?;
            writer.file.sync_all().map_err(|_| io_failure())
        })
        .await
        .map_err(|_| io_failure())?
    }
}

struct VerifiedWriter {
    file: File,
    digest: Sha256,
    size: u64,
    text: Utf8Text,
}

fn transport() -> ApiError {
    ApiError {
        status: None,
        code: Some("SKILL_TRANSPORT_FAILED".to_owned()),
        message: "Checkpoint transfer could not be completed.".to_owned(),
    }
}

fn io_failure() -> ApiError {
    ApiError {
        status: None,
        code: Some("SKILL_EXPORT_IO_FAILED".to_owned()),
        message: "Checkpoint staging could not be written.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::Utf8Text;

    #[test]
    fn streaming_text_classification_matches_whole_file_at_every_boundary() {
        for bytes in [
            "ASCIIé学😄end".as_bytes(),
            b"bad\xff",
            b"zero\0",
            b"\xf0\x9f",
            b"",
        ] {
            for split in 0..=bytes.len() {
                let mut text = Utf8Text::default();
                text.update(&bytes[..split]);
                text.update(&bytes[split..]);
                assert_eq!(
                    text.finish(),
                    std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0)
                );
            }
            let mut text = Utf8Text::default();
            for byte in bytes {
                text.update(&[*byte]);
            }
            assert_eq!(
                text.finish(),
                std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0)
            );
        }
    }
}
