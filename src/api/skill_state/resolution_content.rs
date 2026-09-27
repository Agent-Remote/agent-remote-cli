//! Conflict-bound uploads of exact privately captured state, independent of resolution acceptance.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use super::{check, ResolutionDomain};
use crate::api::skill_content::{validate_upload, SkillFileReceipt, SkillTree, SkillUpload};
use crate::api::skills::{invalid_skill_response, SkillResult};
use crate::api::{ApiClient, ApiError};
use crate::skills::manifest::{EntryKind, Manifest};
use crate::skills::state_snapshot::StateSnapshot;

pub(super) const CONTENT_LIMIT: usize = 64 * 1024 * 1024;

/// One saved attempt in one domain. IDs never serve as arbitrary request paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionTarget {
    pub kind: ResolutionDomain,
    pub conflict_id: String,
}

impl ResolutionTarget {
    pub(super) fn path(&self) -> Result<String, ApiError> {
        check::id(&self.conflict_id)?;
        let base = match self.kind {
            ResolutionDomain::Publication => "/api/v1/skills/state/conflicts",
            ResolutionDomain::Migration => "/api/v1/skills/state/migration/conflicts",
        };
        Ok(format!("{base}/{}", self.conflict_id))
    }
}

impl ApiClient {
    pub async fn begin_skill_resolution_upload(
        &self,
        token: &str,
        target: &ResolutionTarget,
        key: &str,
        snapshot: &StateSnapshot,
    ) -> Result<SkillResult<SkillUpload>, ApiError> {
        let path = target.path()?;
        check::require(
            !key.is_empty() && key.len() <= 128 && key.bytes().all(|b| b.is_ascii_graphic()),
        )?;
        // The capture already validated and hashed this manifest on a blocking worker.
        let manifest = snapshot.manifest().clone();
        let key = key.to_owned();
        #[derive(Serialize)]
        struct UploadRequest {
            idempotency_key: String,
            manifest: Manifest,
        }
        let payload = encode_content(UploadRequest {
            idempotency_key: key,
            manifest,
        })
        .await?;
        let request = self
            .client
            .post(self.endpoint(&format!("{path}/uploads")))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload);
        let result = self
            .send_skill_request_bounded(request, token, CONTENT_LIMIT)
            .await?;
        validate_upload(&result, snapshot.manifest(), snapshot.tree_digest(), None)?;
        Ok(result)
    }

    pub async fn skill_resolution_upload_status(
        &self,
        token: &str,
        target: &ResolutionTarget,
        upload_id: &str,
        snapshot: &StateSnapshot,
    ) -> Result<SkillResult<SkillUpload>, ApiError> {
        let path = target.path()?;
        check::id(upload_id)?;
        let id = uuid::Uuid::parse_str(upload_id).map_err(|_| invalid_skill_response())?;
        let request = self
            .client
            .get(self.endpoint(&format!("{path}/uploads/{id}")));
        let result = self
            .send_skill_request_bounded(request, token, CONTENT_LIMIT)
            .await?;
        validate_upload(
            &result,
            snapshot.manifest(),
            snapshot.tree_digest(),
            Some(id),
        )?;
        Ok(result)
    }

    /// Stream only an object belonging to this snapshot; the selected local source is never reopened.
    pub async fn put_skill_resolution_file(
        &self,
        token: &str,
        target: &ResolutionTarget,
        upload_id: &str,
        snapshot: Arc<StateSnapshot>,
        digest: &str,
    ) -> Result<SkillResult<SkillFileReceipt>, ApiError> {
        let path = target.path()?;
        check::id(upload_id)?;
        check::digest(digest)?;
        let entry = snapshot
            .manifest()
            .entries
            .iter()
            .find(|e| e.kind == EntryKind::File && e.sha256 == digest)
            .ok_or_else(invalid_skill_response)?;
        let size = entry.size;
        let captured = Arc::clone(&snapshot);
        let object_digest = digest.to_owned();
        let file = tokio::task::spawn_blocking(move || {
            let file = captured.open_object(&object_digest)?;
            anyhow::ensure!(
                file.metadata()?.len() == size,
                "staged state object length changed"
            );
            Ok::<_, anyhow::Error>(file)
        })
        .await
        .map_err(|_| invalid_skill_response())?
        .map_err(|_| invalid_skill_response())?;
        let source = tokio::fs::File::from_std(file).take(size);
        let body = reqwest::Body::wrap_stream(ReaderStream::with_capacity(source, 64 * 1024));
        let request = self
            .client
            .put(self.endpoint(&format!("{path}/uploads/{upload_id}/files/{digest}")))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, size)
            .timeout(std::time::Duration::from_secs(3600))
            .body(body);
        let result: SkillResult<SkillFileReceipt> = self.send_skill_request(request, token).await?;
        // Hold the private directory until the request body has finished, including on Windows.
        drop(snapshot);
        if let Some(receipt) = &result.data {
            check::require(receipt.upload_id == upload_id && receipt.digest == digest)?;
            check::query(&result, &["upload_pending"])?;
        }
        Ok(result)
    }

    pub async fn complete_skill_resolution_upload(
        &self,
        token: &str,
        target: &ResolutionTarget,
        upload_id: &str,
        snapshot: &StateSnapshot,
    ) -> Result<SkillResult<SkillTree>, ApiError> {
        let path = target.path()?;
        check::id(upload_id)?;
        let request = self
            .client
            .post(self.endpoint(&format!("{path}/uploads/{upload_id}/complete")));
        let result: SkillResult<SkillTree> = self
            .send_skill_request_bounded(request, token, CONTENT_LIMIT)
            .await?;
        if let Some(tree) = &result.data {
            check::require(
                tree.tree_digest == snapshot.tree_digest()
                    && tree.manifest == *snapshot.manifest()
                    && result.status == "stored"
                    && result.committed
                    && !result.retryable
                    && result.operation_id.is_none()
                    && result.errors.is_empty(),
            )?;
        }
        Ok(result)
    }
}

pub(super) async fn manifest_digest(manifest: Manifest) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || manifest.digest())
        .await
        .map_err(|_| invalid_skill_response())?
        .map_err(|_| invalid_skill_response())
}

/// Stop serialization at the transport limit instead of first allocating an oversized JSON body.
pub(super) async fn encode_content(
    value: impl Serialize + Send + 'static,
) -> Result<Vec<u8>, ApiError> {
    tokio::task::spawn_blocking(move || {
        let mut output = BoundedJson(Vec::new());
        serde_json::to_writer(&mut output, &value).map_err(|_| invalid_skill_response())?;
        Ok(output.0)
    })
    .await
    .map_err(|_| invalid_skill_response())?
}

struct BoundedJson(Vec<u8>);

impl std::io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > CONTENT_LIMIT {
            return Err(std::io::Error::other(
                "resolution content body exceeds transport limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
