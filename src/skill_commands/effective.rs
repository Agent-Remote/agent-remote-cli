//! Render current account observations separately from original snapshot evidence.

use anyhow::Result;

use crate::api::skill_effective::{AccountSkillView, ReleaseValue, SystemSkillView};
use crate::api::ApiClient;
use crate::cli::skills::SkillListArgs;
use crate::terminal::{Details, Table};

use super::{print_json, query_exit, render_summary, safe};

pub(super) async fn session(
    client: &ApiClient,
    token: &str,
    args: &SkillListArgs,
    json: bool,
) -> Result<i32> {
    let result = client
        .session_skills(
            token,
            args.session.as_deref().unwrap_or_default(),
            args.limit.unwrap_or(100),
            args.cursor.as_deref(),
        )
        .await?;
    if json {
        print_json(&result)?;
    } else {
        render_summary(&result);
        if let Some(view) = &result.data {
            Details::new()
                .field("Session", safe(&view.session_id))
                .field("Account", safe(&view.account_id))
                .field("Selection basis", safe(&view.basis))
                .field(
                    "Original snapshot",
                    safe(view.snapshot_id.as_deref().unwrap_or("unknown")),
                )
                .field(
                    "Snapshot lifecycle",
                    safe(view.snapshot_status.as_deref().unwrap_or("unknown")),
                )
                .field(
                    "Content retained",
                    view.content_retained
                        .map_or("unknown".to_owned(), |v| v.to_string()),
                )
                .field("Fixed backend", safe(&view.runtime_backend))
                .field(
                    "Original generation",
                    view.library_generation
                        .map_or("unknown".to_owned(), |v| v.to_string()),
                )
                .field(
                    "Original directory epoch",
                    view.directory_epoch
                        .map_or("unknown".to_owned(), |v| v.to_string()),
                )
                .field(
                    "Starting checkpoint",
                    safe(view.starting_checkpoint_id.as_deref().unwrap_or("unknown")),
                )
                .field(
                    "Original tree digest",
                    safe(view.tree_digest.as_deref().unwrap_or("unknown")),
                )
                .render();
            let mut table = Table::new([
                "Original name",
                "Source",
                "Revision",
                "Install epoch",
                "State",
                "State epoch",
                "Starting checkpoint",
                "Retained",
                "Rule origins",
            ]);
            for item in &view.items {
                table.row([
                    safe(&item.name),
                    format!("{} {}", safe(&item.origin), safe(&item.skill_id)),
                    safe(&item.revision_id),
                    item.installation_epoch.to_string(),
                    safe(&item.state_id),
                    item.state_epoch.to_string(),
                    safe(&item.checkpoint_id),
                    item.checkpoint_retained.to_string(),
                    format!(
                        "enabled: {}; revision: {}",
                        safe(&item.resolution.enabled_source),
                        safe(&item.resolution.revision_source)
                    ),
                ]);
            }
            table.render();
            systems(&view.system_items);
            if let Some(cursor) = &view.next_cursor {
                eprintln!(
                    "More original members: repeat with --cursor {}",
                    safe(cursor)
                );
            }
            eprintln!("Project discovery: not_inspected. Saved selection does not prove model loading. Legacy unrecorded means the original selection is unknown.");
        }
    }
    Ok(query_exit(&result))
}

pub(super) fn systems(items: &[SystemSkillView]) {
    if items.is_empty() {
        return;
    }
    let mut table = Table::new([
        "System skill (read-only)",
        "Selected",
        "Selection reason",
        "Release reference",
    ]);
    for item in items {
        let release = item
            .release
            .iter()
            .map(|(key, value)| {
                format!(
                    "{}={}",
                    safe(key),
                    match value {
                        ReleaseValue::Text(v) => safe(v),
                        ReleaseValue::Number(v) => v.to_string(),
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        table.row([
            safe(&item.name),
            item.selected
                .map_or("conditional/unknown".to_owned(), |v| v.to_string()),
            safe(&item.selection_reason),
            release,
        ]);
    }
    table.render();
}

pub(super) fn account(name: &str, view: &AccountSkillView) {
    Details::new()
        .field("Skill state", safe(name))
        .field("Account", safe(&view.account_id))
        .field(
            "Version selection reason",
            safe(&view.revision_selection_reason),
        )
        .field("Directory mode", safe(&view.directory_mode))
        .field(
            "Directory epoch",
            view.directory_epoch
                .map_or("unknown".to_owned(), |v| v.to_string()),
        )
        .field(
            "Directory checkpoint",
            safe(view.directory_checkpoint_id.as_deref().unwrap_or("none")),
        )
        .field(
            "Selected state",
            safe(view.state_id.as_deref().unwrap_or("uninitialized")),
        )
        .field(
            "State epoch",
            view.state_epoch
                .map_or("unknown".to_owned(), |v| v.to_string()),
        )
        .field(
            "Current checkpoint",
            safe(view.checkpoint_id.as_deref().unwrap_or("none")),
        )
        .field("Preparation", safe(&view.preparation))
        .field("State expired", view.state_expired)
        .field(
            "Publication conflicts (all revisions/epochs)",
            view.publication_conflicts,
        )
        .field(
            "Latest publication conflict",
            safe(
                view.latest_publication_conflict_id
                    .as_deref()
                    .unwrap_or("none"),
            ),
        )
        .field(
            "Migration conflicts (all revisions/epochs)",
            view.migration_conflicts,
        )
        .field(
            "Latest migration conflict",
            safe(
                view.latest_migration_conflict_id
                    .as_deref()
                    .unwrap_or("none"),
            ),
        )
        .field(
            "Last recorded content sync",
            safe(view.last_recorded_sync_at.as_deref().unwrap_or("unknown")),
        )
        .field("Historical sync times missing", view.unknown_sync_times)
        .render();
}
