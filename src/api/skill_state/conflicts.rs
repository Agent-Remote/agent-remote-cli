//! User-authenticated conflict reads; every domain keeps its own endpoint and cursor.

use super::{check, conflict_validation as validate, migration_validation, *};
use crate::api::{ApiClient, ApiError};

impl ApiClient {
    pub async fn skill_publication_conflicts(
        &self,
        token: &str,
        selection: &StateSelector,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<SkillResult<ConflictPage<PublicationConflictSummary>>, ApiError> {
        let query = list_query(selection, limit, cursor)?;
        let request = self
            .client
            .get(self.endpoint("/api/v1/skills/state/conflicts"))
            .query(&query);
        let result: SkillResult<ConflictPage<PublicationConflictSummary>> =
            self.send_skill_request(request, token).await?;
        check::query(&result, &["ready"])?;
        if let Some(page) = &result.data {
            check::page(
                page.items.iter().map(|v| v.id.as_str()),
                page.next_cursor.as_deref(),
                cursor,
                limit,
            )?;
            for item in &page.items {
                validate::publication_summary(item)?;
                check::require(
                    item.account_id == selection.account_id
                        && ["conflicted", "superseded"].contains(&item.status.as_str()),
                )?;
            }
        }
        Ok(result)
    }

    pub async fn skill_migration_conflicts(
        &self,
        token: &str,
        selection: &StateSelector,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<SkillResult<ConflictPage<MigrationConflictSummary>>, ApiError> {
        let query = list_query(selection, limit, cursor)?;
        let request = self
            .client
            .get(self.endpoint("/api/v1/skills/state/migration/conflicts"))
            .query(&query);
        let result: SkillResult<ConflictPage<MigrationConflictSummary>> =
            self.send_skill_request(request, token).await?;
        check::query(&result, &["ready"])?;
        if let Some(page) = &result.data {
            check::page(
                page.items.iter().map(|v| v.id.as_str()),
                page.next_cursor.as_deref(),
                cursor,
                limit,
            )?;
            for item in &page.items {
                validate::migration_summary(item)?;
                check::require(
                    item.account_id == selection.account_id
                        && ["conflicted", "superseded"].contains(&item.status.as_str()),
                )?;
                if let Some(skill) = selection
                    .skill
                    .as_ref()
                    .filter(|s| uuid::Uuid::parse_str(s).is_ok())
                {
                    check::require(&item.skill_id == skill)?;
                }
            }
        }
        Ok(result)
    }

    pub async fn skill_publication_conflict(
        &self,
        token: &str,
        id: &str,
    ) -> Result<SkillResult<PublicationConflict>, ApiError> {
        check::id(id)?;
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/state/conflicts/{id}")));
        let result: SkillResult<PublicationConflict> =
            self.send_skill_request(request, token).await?;
        check::query(
            &result,
            &["conflicted", "superseded", "published", "detached"],
        )?;
        if let Some(value) = &result.data {
            validate::publication(value)?;
            check::require(value.summary.id == id && value.summary.status == result.status)?;
        }
        Ok(result)
    }

    pub async fn skill_migration_conflict(
        &self,
        token: &str,
        id: &str,
    ) -> Result<SkillResult<MigrationConflict>, ApiError> {
        check::id(id)?;
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/state/migration/conflicts/{id}")));
        let result: SkillResult<MigrationConflict> =
            self.send_skill_request(request, token).await?;
        check::query(&result, &["conflicted", "superseded", "ready"])?;
        if let Some(value) = &result.data {
            migration_validation::conflict(value)?;
            check::require(value.summary.id == id && value.summary.status == result.status)?;
        }
        Ok(result)
    }

    pub async fn skill_publication_conflict_diff(
        &self,
        token: &str,
        conflict: &PublicationConflict,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<SkillResult<PublicationConflictDiff>, ApiError> {
        validate::publication(conflict)?;
        if let Some(cursor) = cursor {
            check::path(cursor)?;
        }
        let mut query = Vec::new();
        add_page(&mut query, limit, cursor, 500)?;
        let request = self
            .client
            .get(self.endpoint(&format!(
                "/api/v1/skills/state/conflicts/{}/diff",
                conflict.summary.id
            )))
            .query(&query);
        let result: SkillResult<PublicationConflictDiff> =
            self.send_skill_request(request, token).await?;
        check::query(&result, &["ready"])?;
        if let Some(value) = &result.data {
            check::require(value.publication_id == conflict.summary.id)?;
            validate::paths(&value.items, limit, cursor, value.next_cursor.as_deref())?;
        }
        Ok(result)
    }

    pub async fn skill_migration_conflict_diff(
        &self,
        token: &str,
        conflict: &MigrationConflict,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<SkillResult<MigrationConflictDiff>, ApiError> {
        migration_validation::conflict(conflict)?;
        let after = cursor
            .map(|v| migration_validation::cursor(v, conflict))
            .transpose()?;
        let mut query = Vec::new();
        add_page(&mut query, limit, None, 500)?;
        if let Some(cursor) = cursor {
            query.push(("cursor", cursor.to_owned()));
        }
        let request = self
            .client
            .get(self.endpoint(&format!(
                "/api/v1/skills/state/migration/conflicts/{}/diff",
                conflict.summary.id
            )))
            .query(&query);
        let result: SkillResult<MigrationConflictDiff> =
            self.send_skill_request(request, token).await?;
        check::query(&result, &["ready"])?;
        if let Some(value) = &result.data {
            check::require(
                value.migration_id == conflict.summary.id && value.comparison == "saved_inputs",
            )?;
            let next = value
                .next_cursor
                .as_deref()
                .map(|v| migration_validation::cursor(v, conflict))
                .transpose()?;
            validate::paths(&value.items, limit, after.as_deref(), next.as_deref())?;
        }
        Ok(result)
    }
}

fn list_query(
    selection: &StateSelector,
    limit: u16,
    cursor: Option<&str>,
) -> Result<Vec<(&'static str, String)>, ApiError> {
    let mut query = check::selector(selection)?;
    query.retain(|(key, _)| *key != "scope");
    if let Some(cursor) = cursor {
        check::id(cursor)?;
    }
    add_page(&mut query, limit, cursor, 200)?;
    Ok(query)
}
