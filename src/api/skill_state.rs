//! Authenticated immutable state queries and bounded checkpoint content downloads.

mod command_types;
mod command_validation;
mod commands;
mod prune;
mod prune_types;
mod prune_validation;
pub use prune_types::*;
mod conflict_types;
mod conflict_validation;
mod conflicts;
mod migration_command_types;
mod migration_command_validation;
mod migration_commands;
mod migration_types;
pub use migration_command_types::*;
pub use migration_types::MigrationPrecondition;
mod migration_validation;
mod resolution_content;
mod resolution_types;
mod resolution_validation;
mod resolutions;
pub use resolution_types::*;
mod resolution_preview;
mod resolution_preview_validation;
pub use conflict_types::*;
pub use resolution_content::ResolutionTarget;
pub use resolution_preview::{
    ResolutionContentPreview, ResolutionDomain, ResolutionPreviewRequest, ResolutionPreviewSource,
};
mod download;
pub use command_types::*;
mod types;
mod validation;

pub use types::*;

use super::skills::{invalid_skill_response, SkillResult};
use super::{ApiClient, ApiError};
use validation as check;

impl ApiClient {
    pub async fn skill_state_history(
        &self,
        token: &str,
        selection: &StateSelector,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<SkillResult<CheckpointPage>, ApiError> {
        let mut query = check::selector(selection)?;
        add_page(&mut query, limit, cursor, 200)?;
        let request = self
            .client
            .get(self.endpoint("/api/v1/skills/state/checkpoints"))
            .query(&query);
        let result: SkillResult<CheckpointPage> = self.send_skill_request(request, token).await?;
        check::query(&result, &["ready"])?;
        if let Some(page) = &result.data {
            check::page(
                page.items.iter().map(|i| i.id.as_str()),
                page.next_cursor.as_deref(),
                cursor,
                limit,
            )?;
            for item in &page.items {
                check::checkpoint(item)?;
                check::require(
                    item.account_id == selection.account_id && item.scope == selection.scope,
                )?;
                if let Some(skill) = selection
                    .skill
                    .as_ref()
                    .filter(|s| uuid::Uuid::parse_str(s).is_ok())
                {
                    check::require(item.skill_id.as_ref() == Some(skill))?;
                }
            }
        }
        Ok(result)
    }

    pub async fn skill_state_pending(
        &self,
        token: &str,
        selection: &StateSelector,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<SkillResult<PendingPage>, ApiError> {
        let mut query = check::selector(selection)?;
        add_page(&mut query, limit, cursor, 200)?;
        let request = self
            .client
            .get(self.endpoint("/api/v1/skills/state/pending"))
            .query(&query);
        let result: SkillResult<PendingPage> = self.send_skill_request(request, token).await?;
        check::query(&result, &["ready"])?;
        if let Some(page) = &result.data {
            check::page(
                page.items.iter().map(|i| i.id.as_str()),
                page.next_cursor.as_deref(),
                cursor,
                limit,
            )?;
            for item in &page.items {
                for id in [
                    &item.id,
                    &item.snapshot_id,
                    &item.session_reference_id,
                    &item.node_id,
                ] {
                    check::id(id)?;
                }
                check::digest(&item.incoming_digest)?;
                check::require(
                    item.status == "upload_pending"
                        && item.storage_location == "source_node"
                        && !item.exportable_from_server,
                )?;
            }
        }
        Ok(result)
    }

    pub async fn skill_checkpoint(
        &self,
        token: &str,
        id: &str,
    ) -> Result<SkillResult<Checkpoint>, ApiError> {
        check::id(id)?;
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/state/checkpoints/{id}")));
        let result: SkillResult<Checkpoint> = self.send_skill_request(request, token).await?;
        check::query(&result, &["ready", "state_expired"])?;
        if let Some(value) = &result.data {
            check::checkpoint(value)?;
            check::require(value.id == id && value.retained == (result.status == "ready"))?;
        }
        Ok(result)
    }

    pub async fn skill_checkpoint_members(
        &self,
        token: &str,
        id: &str,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<SkillResult<MemberPage>, ApiError> {
        check::id(id)?;
        let mut query = Vec::new();
        add_page(&mut query, limit, cursor, 200)?;
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/state/checkpoints/{id}/members")))
            .query(&query);
        let result: SkillResult<MemberPage> = self.send_skill_request(request, token).await?;
        check::query(&result, &["ready"])?;
        if let Some(page) = &result.data {
            check::require(page.checkpoint_id == id && page.items.len() <= usize::from(limit))?;
            let mut previous = cursor.unwrap_or("");
            for member in &page.items {
                check::prefix(&member.entry_name)?;
                check::require(
                    member.entry_name.as_str() > previous
                        && member.entry_name.len() <= 64
                        && member.installation_epoch >= 1
                        && member.state_epoch.is_none_or(|epoch| epoch >= 1),
                )?;
                for id in [
                    &member.state_id,
                    &member.checkpoint_id,
                    &member.skill_id,
                    &member.revision_id,
                ] {
                    check::id(id)?;
                }
                previous = &member.entry_name;
            }
            if let Some(next) = &page.next_cursor {
                check::require(
                    !page.items.is_empty()
                        && next == previous
                        && page.items.len() == usize::from(limit),
                )?;
            }
        }
        Ok(result)
    }

    pub async fn skill_current_diff(
        &self,
        token: &str,
        selection: &StateSelector,
        limit: u16,
    ) -> Result<SkillResult<CheckpointDiff>, ApiError> {
        let mut query = check::selector(selection)?;
        add_page(&mut query, limit, None, 500)?;
        let request = self
            .client
            .get(self.endpoint("/api/v1/skills/state/diff"))
            .query(&query);
        let result: SkillResult<CheckpointDiff> = self.send_skill_request(request, token).await?;
        validate_diff(&result, limit, None)?;
        Ok(result)
    }

    pub async fn skill_checkpoint_diff(
        &self,
        token: &str,
        id: &str,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<SkillResult<CheckpointDiff>, ApiError> {
        check::id(id)?;
        if let Some(cursor) = cursor {
            check::path(cursor)?;
        }
        let mut query = Vec::new();
        add_page(&mut query, limit, cursor, 500)?;
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/state/checkpoints/{id}/diff")))
            .query(&query);
        let result: SkillResult<CheckpointDiff> = self.send_skill_request(request, token).await?;
        validate_diff(&result, limit, cursor)?;
        if let Some(value) = &result.data {
            check::require(value.checkpoint_id == id)?;
        }
        Ok(result)
    }

    pub async fn skill_checkpoint_tree(
        &self,
        token: &str,
        checkpoint: &Checkpoint,
    ) -> Result<SkillResult<CheckpointTree>, ApiError> {
        check::checkpoint(checkpoint)?;
        let request = self.client.get(self.endpoint(&format!(
            "/api/v1/skills/state/checkpoints/{}/tree",
            checkpoint.id
        )));
        let result: SkillResult<CheckpointTree> = self
            .send_skill_request_bounded(request, token, 64 * 1024 * 1024)
            .await?;
        check::query(&result, &["ready"])?;
        if let Some(tree) = &result.data {
            check::require(
                tree.checkpoint_id == checkpoint.id
                    && tree.source_tree_digest == checkpoint.content_digest
                    && tree.subtree_prefix == checkpoint.subtree_prefix,
            )?;
            check::digest(&tree.tree_digest)?;
            // Hashing a large manifest must not block cancellation or the async executor.
            let manifest = tree.manifest.clone();
            let actual = tokio::task::spawn_blocking(move || manifest.digest())
                .await
                .map_err(|_| invalid_skill_response())?
                .map_err(|_| invalid_skill_response())?;
            check::require(tree.tree_digest == actual)?;
            let mut roots = std::collections::BTreeSet::new();
            for root in &tree.dependency_roots {
                check::prefix(root)?;
                check::require(
                    !root.is_empty() && root != &tree.subtree_prefix && roots.insert(root.as_str()),
                )?;
            }
            if checkpoint.scope == StateScope::AccountDirectory || tree.subtree_prefix.is_empty() {
                check::require(
                    tree.dependency_roots.is_empty()
                        && !tree.locally_removed
                        && tree.tree_digest == tree.source_tree_digest,
                )?;
            } else {
                let selected = tree
                    .manifest
                    .entries
                    .iter()
                    .any(|e| e.path == tree.subtree_prefix);
                check::require(tree.locally_removed != selected)?;
                for entry in &tree.manifest.entries {
                    let root = entry
                        .path
                        .split('/')
                        .next()
                        .ok_or_else(invalid_skill_response)?;
                    check::require(root == tree.subtree_prefix || roots.contains(root))?;
                }
            }
        }
        Ok(result)
    }
}

fn add_page(
    query: &mut Vec<(&'static str, String)>,
    limit: u16,
    cursor: Option<&str>,
    maximum: u16,
) -> Result<(), ApiError> {
    check::require((1..=maximum).contains(&limit))?;
    query.push(("limit", limit.to_string()));
    if let Some(cursor) = cursor {
        check::require(!cursor.is_empty() && cursor.len() <= 4096)?;
        query.push(("cursor", cursor.to_owned()));
    }
    Ok(())
}

fn validate_diff(
    result: &SkillResult<CheckpointDiff>,
    limit: u16,
    cursor: Option<&str>,
) -> Result<(), ApiError> {
    check::query(result, &["ready"])?;
    if let Some(value) = &result.data {
        check::diff(value, limit, cursor)?;
    }
    Ok(())
}
