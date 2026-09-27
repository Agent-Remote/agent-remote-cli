//! Resolution mutations and immutable receipt lookup never use library deployment response types.

use super::{check, conflict_validation, resolution_validation as validate, *};
use crate::api::skills::SkillResult;
use crate::api::{ApiClient, ApiError};

impl ResolutionRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        check::require(
            !self.idempotency_key.is_empty()
                && self.idempotency_key.len() <= 128
                && self.idempotency_key.bytes().all(|b| b.is_ascii_graphic())
                && (0..i64::MAX).contains(&self.expected_revision),
        )?;
        conflict_validation::resolution_choice(&self.choice)
    }
    pub fn validate_preview(
        &self,
        target: &ResolutionTarget,
        view: &ResolutionOutcome,
    ) -> Result<(), ApiError> {
        let mut request = self.clone();
        request.dry_run = true;
        let result = SkillResult {
            schema_version: 1,
            operation_id: None,
            status: "preview".to_owned(),
            committed: false,
            retryable: false,
            data: Some(view.clone()),
            errors: vec![],
        };
        validate::outcome(&result, Some(target), Some(&request))
    }
}

impl ApiClient {
    pub async fn skill_migration_resolution_plan(
        &self,
        token: &str,
        id: &str,
    ) -> Result<SkillResult<MigrationResolutionPlan>, ApiError> {
        let path = ResolutionTarget {
            kind: ResolutionDomain::Migration,
            conflict_id: id.to_owned(),
        }
        .path()?;
        let request = self.client.get(self.endpoint(&format!("{path}/plan")));
        let result: SkillResult<MigrationResolutionPlan> =
            self.send_skill_request(request, token).await?;
        check::query(&result, &["ready", "conflicted", "superseded"])?;
        if let Some(plan) = &result.data {
            check::require(
                plan.migration_id == id
                    && plan.current_status == result.status
                    && plan.revision >= 0,
            )?;
            for choice in &plan.choices {
                conflict_validation::resolution_choice(choice)?;
            }
        }
        Ok(result)
    }

    pub async fn resolve_skill_conflict(
        &self,
        token: &str,
        target: &ResolutionTarget,
        request: &ResolutionRequest,
    ) -> Result<SkillResult<ResolutionOutcome>, ApiError> {
        request.validate()?;
        let path = target.path()?;
        let http = self
            .client
            .post(self.endpoint(&format!("{path}/resolve")))
            .json(request);
        let result = match target.kind {
            ResolutionDomain::Publication => convert(
                self.send_skill_request_bounded(http, token, resolution_content::CONTENT_LIMIT)
                    .await?,
                |result| ResolutionOutcome::Publication { result },
            ),
            ResolutionDomain::Migration => convert(
                self.send_skill_request_bounded(http, token, resolution_content::CONTENT_LIMIT)
                    .await?,
                |result| ResolutionOutcome::Migration {
                    result: Box::new(result),
                    current: None,
                },
            ),
        };
        validate::outcome(&result, Some(target), Some(request))?;
        Ok(result)
    }

    pub async fn skill_resolution_operation_by_key(
        &self,
        token: &str,
        kind: ResolutionDomain,
        key: &str,
    ) -> Result<SkillResult<ResolutionOutcome>, ApiError> {
        check::require(
            !key.is_empty() && key.len() <= 128 && key.bytes().all(|b| b.is_ascii_graphic()),
        )?;
        let http = self
            .client
            .get(self.endpoint(operation_path(kind)))
            .query(&[("key", key)]);
        self.resolution_receipt(token, kind, http).await
    }

    pub async fn skill_resolution_operation(
        &self,
        token: &str,
        kind: ResolutionDomain,
        id: &str,
    ) -> Result<SkillResult<ResolutionOutcome>, ApiError> {
        check::id(id)?;
        let http = self
            .client
            .get(self.endpoint(&format!("{}/{id}", operation_path(kind))));
        let result = self.resolution_receipt(token, kind, http).await?;
        if result.data.is_some() {
            check::require(result.operation_id.as_deref() == Some(id))?;
        }
        Ok(result)
    }

    async fn resolution_receipt(
        &self,
        token: &str,
        kind: ResolutionDomain,
        http: reqwest::RequestBuilder,
    ) -> Result<SkillResult<ResolutionOutcome>, ApiError> {
        let result = match kind {
            ResolutionDomain::Publication => convert(
                self.send_skill_request_bounded(http, token, resolution_content::CONTENT_LIMIT)
                    .await?,
                |result| ResolutionOutcome::Publication { result },
            ),
            ResolutionDomain::Migration => convert(
                self.send_skill_request_bounded(http, token, resolution_content::CONTENT_LIMIT)
                    .await?,
                |receipt: MigrationResolutionReceipt| ResolutionOutcome::Migration {
                    result: Box::new(receipt.result),
                    current: Some(MigrationResolutionCurrent {
                        status: receipt.current_status,
                        replacement_id: receipt.replacement_id,
                        superseded_reason: receipt.superseded_reason,
                    }),
                },
            ),
        };
        validate::outcome(&result, None, None)?;
        Ok(result)
    }
}

fn convert<T>(
    result: SkillResult<T>,
    f: impl FnOnce(T) -> ResolutionOutcome,
) -> SkillResult<ResolutionOutcome> {
    SkillResult {
        schema_version: result.schema_version,
        operation_id: result.operation_id,
        status: result.status,
        committed: result.committed,
        retryable: result.retryable,
        data: result.data.map(f),
        errors: result.errors,
    }
}

fn operation_path(kind: ResolutionDomain) -> &'static str {
    match kind {
        ResolutionDomain::Publication => "/api/v1/skills/state/resolution-operations",
        ResolutionDomain::Migration => "/api/v1/skills/state/migration/resolution-operations",
    }
}
