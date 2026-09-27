//! Incremental migration preview, acceptance and original receipt queries.

use super::{check, migration_command_validation as validate, *};
use crate::api::{ApiClient, ApiError};

const RESPONSE_LIMIT: usize = 64 * 1024 * 1024;

impl MigrationRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        validate::request(self)
    }
}
impl MigrationView {
    pub fn validate(&self, committed: bool) -> Result<(), ApiError> {
        validate::view(self, committed)
    }
}

impl ApiClient {
    pub async fn skill_migration_current(
        &self,
        token: &str,
        selector: &MigrationSelector,
    ) -> Result<SkillResult<MigrationPrecondition>, ApiError> {
        validate::selector(selector)?;
        let http = self
            .client
            .get(self.endpoint("/api/v1/skills/state/migration/current"))
            .query(selector);
        let result: SkillResult<MigrationPrecondition> = self
            .send_skill_request_bounded(http, token, RESPONSE_LIMIT)
            .await?;
        check::query(&result, &["ready"])?;
        if let Some(current) = &result.data {
            validate::selection(selector, current)?;
        }
        Ok(result)
    }

    pub async fn migrate_skill_state(
        &self,
        token: &str,
        request: &MigrationRequest,
    ) -> Result<SkillResult<MigrationView>, ApiError> {
        request.validate()?;
        let http = self
            .client
            .post(self.endpoint("/api/v1/skills/state/migrate"))
            .json(request);
        let result: SkillResult<MigrationView> = self
            .send_skill_request_bounded(http, token, RESPONSE_LIMIT)
            .await?;
        if let Some(view) = &result.data {
            validate::view(view, !request.dry_run)?;
            check::require(
                result.committed != request.dry_run
                    && result.status == view.status
                    && result.operation_id == view.operation_id
                    && result.errors.is_empty()
                    && !result.retryable
                    && view.before == request.expected,
            )?;
        }
        Ok(result)
    }

    pub async fn skill_migration_operation_by_key(
        &self,
        token: &str,
        key: &str,
    ) -> Result<SkillResult<MigrationReceipt>, ApiError> {
        check::require(
            !key.is_empty() && key.len() <= 128 && key.bytes().all(|b| b.is_ascii_graphic()),
        )?;
        let http = self
            .client
            .get(self.endpoint("/api/v1/skills/state/migration/operations"))
            .query(&[("key", key)]);
        let result = self
            .send_skill_request_bounded(http, token, RESPONSE_LIMIT)
            .await?;
        validate::receipt(&result)?;
        Ok(result)
    }

    pub async fn skill_migration_operation(
        &self,
        token: &str,
        id: &str,
    ) -> Result<SkillResult<MigrationReceipt>, ApiError> {
        check::id(id)?;
        let http = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/state/migration/operations/{id}")));
        let result = self
            .send_skill_request_bounded(http, token, RESPONSE_LIMIT)
            .await?;
        validate::receipt(&result)?;
        if result.data.is_some() {
            check::require(result.operation_id.as_deref() == Some(id))?;
        }
        Ok(result)
    }
}
