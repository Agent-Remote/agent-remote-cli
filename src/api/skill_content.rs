//! Authenticated package uploads; every receipt is tied to the exact captured manifest.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::skills::{invalid_skill_response, SkillResult};
use super::{ApiClient, ApiError};
use crate::skills::manifest::{Entry, EntryKind, Manifest};

const CONTENT_ENVELOPE_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillUploadStatus {
    Staged,
    Committed,
    Expired,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillUpload {
    pub id: String,
    pub status: SkillUploadStatus,
    pub tree_digest: String,
    pub reserved_bytes: u64,
    pub expires_at: String,
    pub manifest: Manifest,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillFileReceipt {
    pub upload_id: String,
    pub digest: String,
    pub created: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillTree {
    pub tree_digest: String,
    pub manifest: Manifest,
}

impl ApiClient {
    pub async fn begin_skill_upload(
        &self,
        token: &str,
        key: &str,
        manifest: &Manifest,
    ) -> Result<SkillResult<SkillUpload>, ApiError> {
        let digest = manifest.digest().map_err(|_| invalid_skill_response())?;
        if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid_skill_response());
        }
        let payload =
            serde_json::to_vec(&serde_json::json!({"idempotency_key":key,"manifest":manifest}))
                .map_err(|_| invalid_skill_response())?;
        if payload.len() > CONTENT_ENVELOPE_LIMIT {
            return Err(invalid_skill_response());
        }
        let request = self
            .client
            .post(self.endpoint("/api/v1/skills/content/uploads"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload);
        let result: SkillResult<SkillUpload> = self
            .send_skill_request_bounded(request, token, CONTENT_ENVELOPE_LIMIT)
            .await?;
        validate_upload(&result, manifest, &digest, None)?;
        Ok(result)
    }

    pub async fn skill_upload_status(
        &self,
        token: &str,
        upload_id: &str,
        manifest: &Manifest,
    ) -> Result<SkillResult<SkillUpload>, ApiError> {
        let id = uuid::Uuid::parse_str(upload_id).map_err(|_| invalid_skill_response())?;
        let digest = manifest.digest().map_err(|_| invalid_skill_response())?;
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/content/uploads/{id}")));
        let result: SkillResult<SkillUpload> = self
            .send_skill_request_bounded(request, token, CONTENT_ENVELOPE_LIMIT)
            .await?;
        validate_upload(&result, manifest, &digest, Some(id))?;
        Ok(result)
    }

    /// The caller supplies private staged bytes, not a live source path. Cloned Bytes share storage.
    pub async fn put_skill_file(
        &self,
        token: &str,
        upload_id: &str,
        entry: &Entry,
        content: Bytes,
    ) -> Result<SkillResult<SkillFileReceipt>, ApiError> {
        let id = uuid::Uuid::parse_str(upload_id).map_err(|_| invalid_skill_response())?;
        entry.validate().map_err(|_| invalid_skill_response())?;
        if entry.kind != EntryKind::File || content.len() as u64 != entry.size {
            return Err(invalid_skill_response());
        }
        let verification = content.clone();
        let digest =
            tokio::task::spawn_blocking(move || format!("{:x}", Sha256::digest(verification)))
                .await
                .map_err(|_| invalid_skill_response())?;
        if digest != entry.sha256 {
            return Err(invalid_skill_response());
        }
        let request = self
            .client
            .put(self.endpoint(&format!(
                "/api/v1/skills/content/uploads/{id}/files/{digest}"
            )))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(content);
        let result: SkillResult<SkillFileReceipt> = self.send_skill_request(request, token).await?;
        if let Some(receipt) = &result.data {
            if uuid::Uuid::parse_str(&receipt.upload_id).ok() != Some(id)
                || receipt.digest != digest
                || result.status != "persisted"
                || result.committed
                || !result.errors.is_empty()
                || result.operation_id.is_some()
            {
                return Err(invalid_skill_response());
            }
        }
        Ok(result)
    }

    pub async fn complete_skill_upload(
        &self,
        token: &str,
        upload_id: &str,
        manifest: &Manifest,
    ) -> Result<SkillResult<SkillTree>, ApiError> {
        let id = uuid::Uuid::parse_str(upload_id).map_err(|_| invalid_skill_response())?;
        let digest = manifest.digest().map_err(|_| invalid_skill_response())?;
        let request = self
            .client
            .post(self.endpoint(&format!("/api/v1/skills/content/uploads/{id}/complete")));
        let result: SkillResult<SkillTree> = self
            .send_skill_request_bounded(request, token, CONTENT_ENVELOPE_LIMIT)
            .await?;
        if let Some(tree) = &result.data {
            if tree.tree_digest != digest
                || tree.manifest != *manifest
                || result.status != "stored"
                || !result.committed
                || !result.errors.is_empty()
                || result.operation_id.is_some()
            {
                return Err(invalid_skill_response());
            }
        }
        Ok(result)
    }
}

pub(super) fn validate_upload(
    result: &SkillResult<SkillUpload>,
    manifest: &Manifest,
    digest: &str,
    identity: Option<uuid::Uuid>,
) -> Result<(), ApiError> {
    if let Some(upload) = &result.data {
        let id = uuid::Uuid::parse_str(&upload.id).map_err(|_| invalid_skill_response())?;
        let (status, committed) = match upload.status {
            SkillUploadStatus::Staged => ("staged", false),
            SkillUploadStatus::Committed => ("committed", true),
            SkillUploadStatus::Expired => ("expired", false),
        };
        if identity.is_some_and(|expected| expected != id)
            || upload.tree_digest != digest
            || upload.manifest != *manifest
            || result.status != status
            || result.committed != committed
            || !result.errors.is_empty()
            || result.operation_id.is_some()
        {
            return Err(invalid_skill_response());
        }
    }
    Ok(())
}
