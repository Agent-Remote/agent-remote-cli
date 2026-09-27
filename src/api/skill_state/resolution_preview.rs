//! Read-only custom-content previews retain the saved attempt's provenance and verification limits.

use serde::{Deserialize, Serialize};

use super::{
    check, conflict_validation, migration_validation, resolution_content,
    resolution_preview_validation, *,
};
use crate::api::skills::SkillResult;
use crate::api::{ApiClient, ApiError};
use crate::skills::manifest::Manifest;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionDomain {
    Publication,
    Migration,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionPreviewRequest {
    pub expected_revision: i64,
    pub choice: ResolutionChoice,
    pub manifest: Manifest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolutionContentPreview {
    pub kind: ResolutionDomain,
    pub conflict_id: String,
    pub account_id: String,
    pub plan_revision: i64,
    pub proposed_tree_digest: String,
    pub choices: Vec<ResolutionChoice>,
    pub metadata_only: bool,
    pub content_verified: bool,
    pub ready_to_publish: bool,
    pub candidate_complete: bool,
    pub result_tree_digest: Option<String>,
    pub remaining: Vec<MergeConflict>,
    pub unit: Vec<String>,
    pub current_tree_digest: String,
    pub directory_tree_digest: String,
    pub changes: Option<Vec<StatePathDiff>>,
    pub target_revision_id: Option<String>,
    pub target_modified: Option<bool>,
    pub target_changes: Option<Vec<StatePathDiff>>,
    pub original_changes: Option<Vec<StatePathDiff>>,
    pub pending_checks: Vec<String>,
}

/// The full saved query result, never newly selected live defaults, binds a metadata preview.
pub enum ResolutionPreviewSource<'a> {
    Publication(&'a PublicationConflict),
    Migration(&'a MigrationConflict),
}

impl ResolutionPreviewSource<'_> {
    pub fn target(&self) -> Result<ResolutionTarget, ApiError> {
        let (kind, conflict_id) = match self {
            Self::Publication(value) => {
                conflict_validation::publication(value)?;
                (ResolutionDomain::Publication, value.summary.id.clone())
            }
            Self::Migration(value) => {
                migration_validation::conflict(value)?;
                (ResolutionDomain::Migration, value.summary.id.clone())
            }
        };
        Ok(ResolutionTarget { kind, conflict_id })
    }

    pub(super) fn validate_provenance(
        &self,
        preview: &ResolutionContentPreview,
    ) -> Result<(), ApiError> {
        let (account, current, directory, revision) = match self {
            Self::Publication(value) => {
                check::require(
                    value.summary.status == "conflicted"
                        && preview.plan_revision == value.plan_revision,
                )?;
                (
                    &value.summary.account_id,
                    &value.current.tree_digest,
                    &value.current.tree_digest,
                    None,
                )
            }
            Self::Migration(value) => {
                check::require(value.summary.status == "conflicted")?;
                (
                    &value.summary.account_id,
                    &value.current.tree_digest,
                    &value.directory.tree_digest,
                    Some(&value.live.target.revision_id),
                )
            }
        };
        check::require(
            &preview.account_id == account
                && current.as_ref() == Some(&preview.current_tree_digest)
                && directory.as_ref() == Some(&preview.directory_tree_digest)
                && preview.target_revision_id.as_ref() == revision,
        )
    }
}

impl ApiClient {
    /// This endpoint cannot upload file bytes, save a plan or accept a mutation key.
    pub async fn preview_skill_resolution_content(
        &self,
        token: &str,
        source: &ResolutionPreviewSource<'_>,
        request: &ResolutionPreviewRequest,
    ) -> Result<SkillResult<ResolutionContentPreview>, ApiError> {
        let target = source.target()?;
        let path = target.path()?;
        conflict_validation::resolution_choice(&request.choice)?;
        check::require(
            (0..i64::MAX).contains(&request.expected_revision) && request.choice.r#use.is_none(),
        )?;
        let digest = resolution_content::manifest_digest(request.manifest.clone()).await?;
        check::require(
            request
                .choice
                .file_tree_digest
                .as_ref()
                .or(request.choice.directory_tree_digest.as_ref())
                == Some(&digest),
        )?;
        let payload = resolution_content::encode_content(request.clone()).await?;
        let http = self
            .client
            .post(self.endpoint(&format!("{path}/content-preview")))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload);
        let result: SkillResult<ResolutionContentPreview> = self
            .send_skill_request_bounded(http, token, resolution_content::CONTENT_LIMIT)
            .await?;
        check::query(&result, &["preview"])?;
        if let Some(view) = &result.data {
            resolution_preview_validation::preview(view, &target, request)?;
            source.validate_provenance(view)?;
        }
        Ok(result)
    }
}
