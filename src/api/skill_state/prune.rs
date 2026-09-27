//! Prune HTTP methods keep the ordinary 1 MiB response limit and exact identity checks.

use super::{prune_validation as validate, validation as check, *};
use crate::api::{ApiClient, ApiError};

const ROOT: &str = "/api/v1/skills/state/prune";

impl ApiClient {
    pub async fn preview_skill_prune(
        &self,
        token: &str,
        request: &PrunePreviewRequest,
    ) -> Result<SkillResult<PrunePreviewPage>, ApiError> {
        check::selector(&request.selector)?;
        check::require((1..=100).contains(&request.limit))?;
        if let Some(cursor) = &request.cursor {
            validate::credential(cursor)?;
        }
        let result: SkillResult<PrunePreviewPage> = self
            .send_skill_request(
                self.client
                    .post(self.endpoint(&format!("{ROOT}/preview")))
                    .json(request),
                token,
            )
            .await?;
        check::query(&result, &["preview"])?;
        if let Some(page) = &result.data {
            validate::preview(page, request)?;
        }
        Ok(result)
    }

    pub async fn prune_skill_state(
        &self,
        token: &str,
        request: &PruneRequest,
    ) -> Result<SkillResult<PruneReceipt>, ApiError> {
        request.validate()?;
        let result = self
            .send_skill_request(self.client.post(self.endpoint(ROOT)).json(request), token)
            .await?;
        request.validate_receipt(&result)?;
        Ok(result)
    }

    pub async fn skill_prune_operation_by_key(
        &self,
        token: &str,
        key: &str,
    ) -> Result<SkillResult<PruneReceipt>, ApiError> {
        validate::key(key)?;
        let result = self
            .send_skill_request(
                self.client
                    .get(self.endpoint(&format!("{ROOT}/operations")))
                    .query(&[("key", key)]),
                token,
            )
            .await?;
        validate::receipt(&result)?;
        if let Some(receipt) = &result.data {
            check::require(receipt.idempotency_key == key)?;
        }
        Ok(result)
    }

    pub async fn skill_prune_operation(
        &self,
        token: &str,
        id: &str,
    ) -> Result<SkillResult<PruneReceipt>, ApiError> {
        check::id(id)?;
        let result = self
            .send_skill_request(
                self.client
                    .get(self.endpoint(&format!("{ROOT}/operations/{id}"))),
                token,
            )
            .await?;
        validate::receipt(&result)?;
        if let Some(receipt) = &result.data {
            check::require(receipt.operation_id == id)?;
        }
        Ok(result)
    }

    pub async fn skill_prune_entries(
        &self,
        token: &str,
        id: &str,
        offset: u64,
        limit: u16,
    ) -> Result<SkillResult<PruneReceiptPage>, ApiError> {
        check::id(id)?;
        check::require(offset <= validate::MAX_ROWS && (1..=100).contains(&limit))?;
        let result: SkillResult<PruneReceiptPage> = self
            .send_skill_request(
                self.client
                    .get(self.endpoint(&format!("{ROOT}/operations/{id}/entries")))
                    .query(&[("offset", offset.to_string()), ("limit", limit.to_string())]),
                token,
            )
            .await?;
        if let Some(page) = &result.data {
            validate::accepted(&result, id)?;
            check::require(page.operation_id == id && page.offset == offset)?;
            let end = validate::page(offset, page.total, &page.rows, limit, true)?;
            check::require(page.next_offset == if end < page.total { Some(end) } else { None })?;
        }
        Ok(result)
    }

    pub async fn skill_prune_progress(
        &self,
        token: &str,
        id: &str,
    ) -> Result<SkillResult<PruneProgress>, ApiError> {
        check::id(id)?;
        let result: SkillResult<PruneProgress> = self
            .send_skill_request(
                self.client
                    .get(self.endpoint(&format!("{ROOT}/operations/{id}/progress"))),
                token,
            )
            .await?;
        if let Some(progress) = &result.data {
            validate::accepted(&result, id)?;
            check::require(
                progress.operation_id == id
                    && progress.retrying_tasks <= progress.pending_tasks
                    && progress
                        .pending_tasks
                        .checked_add(progress.completed_tasks)
                        .is_some_and(|n| n <= validate::MAX_ROWS)
                    && (progress.pending_tasks > 0 || progress.pending_file_bytes == 0)
                    && (progress.completed_tasks > 0 || progress.deleted_file_bytes == 0),
            )?;
        }
        Ok(result)
    }
}
