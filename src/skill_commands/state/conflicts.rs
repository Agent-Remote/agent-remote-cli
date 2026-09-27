//! Conflict reads use saved attempts, never fresh branch preparation or resolution commands.

use crate::api::skill_state::{ConflictComparison, ConflictHistory};
use crate::api::ApiClient;
use crate::cli::skills::StateConflictsArgs;
use crate::skill_commands::remote_result;
use anyhow::Result;

pub(super) async fn list(
    client: &ApiClient,
    token: &str,
    args: StateConflictsArgs,
) -> Result<ConflictHistory> {
    let mut selector = args.selection.selector();
    if let Some(skill) = &selector.skill {
        if uuid::Uuid::parse_str(skill).is_err() {
            selector.skill = Some(
                remote_result::data(
                    client
                        .skill_info(token, skill, None, Some(&selector.account_id))
                        .await?,
                )?
                .id()
                .to_owned(),
            );
        }
    }
    let publications = remote_result::data(
        client
            .skill_publication_conflicts(token, &selector, args.limit, args.cursor.as_deref())
            .await?,
    )?;
    let migrations = remote_result::data(
        client
            .skill_migration_conflicts(
                token,
                &selector,
                args.limit,
                args.migration_cursor.as_deref(),
            )
            .await?,
    )?;
    Ok(ConflictHistory {
        selector,
        publications,
        migrations,
    })
}

pub(super) async fn diff(
    client: &ApiClient,
    token: &str,
    id: &str,
    limit: u16,
    cursor: Option<&str>,
) -> Result<ConflictComparison> {
    let publication = client.skill_publication_conflict(token, id).await?;
    // Only a definite domain miss permits migration lookup; auth, transport and expiry stay errors.
    let absent = publication.data.is_none()
        && !publication.committed
        && publication.operation_id.is_none()
        && publication.status == "failed"
        && !publication.retryable
        && publication.errors.len() == 1
        && publication.errors[0].code == "CONFLICT_NOT_FOUND";
    if !absent {
        let conflict = remote_result::data(publication)?;
        let diff = remote_result::data(
            client
                .skill_publication_conflict_diff(token, &conflict, limit, cursor)
                .await?,
        )?;
        return Ok(ConflictComparison::Publication {
            conflict: Box::new(conflict),
            diff,
        });
    }
    let conflict = remote_result::data(client.skill_migration_conflict(token, id).await?)?;
    let diff = remote_result::data(
        client
            .skill_migration_conflict_diff(token, &conflict, limit, cursor)
            .await?,
    )?;
    Ok(ConflictComparison::Migration {
        conflict: Box::new(conflict),
        diff,
    })
}
