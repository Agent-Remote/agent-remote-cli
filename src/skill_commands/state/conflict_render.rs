//! Terminal-safe saved provenance, live drift and metadata-only comparisons.

use crate::api::skill_state::*;
use crate::skill_commands::safe;
use crate::terminal::{Details, Table};

pub(super) fn history(value: &ConflictHistory) {
    Details::new()
        .field("Account", safe(&value.selector.account_id))
        .field("Skill", optional(value.selector.skill.as_deref()))
        .render();
    let mut publications = Table::new([
        "Publication conflict",
        "Status",
        "Finalization",
        "Attempt",
        "Reason",
    ]);
    for item in &value.publications.items {
        publications.row([
            safe(&item.id),
            safe(&item.status),
            safe(&item.finalization_id),
            item.attempt.to_string(),
            optional(item.reason.as_deref()),
        ]);
    }
    publications.render();
    let mut migrations = Table::new([
        "Migration conflict",
        "Skill",
        "Mode",
        "Status",
        "Source epoch",
        "Target epoch",
        "Replacement",
    ]);
    for item in &value.migrations.items {
        migrations.row([
            safe(&item.id),
            safe(&item.skill_id),
            safe(&item.mode),
            safe(&item.status),
            epoch(item.source_epoch),
            item.target_epoch.to_string(),
            optional(item.replacement_id.as_deref()),
        ]);
    }
    migrations.render();
    Details::new()
        .field(
            "Next publication cursor",
            optional(value.publications.next_cursor.as_deref()),
        )
        .field(
            "Next migration cursor",
            optional(value.migrations.next_cursor.as_deref()),
        )
        .render();
    eprintln!("Publication conflicts cover the complete account directory, including related unchanged members. Continue pages separately with --cursor and --migration-cursor.");
}

pub(super) fn comparison(value: &ConflictComparison) {
    let (items, cursor) = match value {
        ConflictComparison::Publication { conflict, diff } => {
            Details::new()
                .field("Kind", "session publication")
                .field("Conflict", safe(&conflict.summary.id))
                .field("Account", safe(&conflict.summary.account_id))
                .field("Status", safe(&conflict.summary.status))
                .field("Scope", "account-directory")
                .field("Session", safe(&conflict.session_reference_id))
                .field("Plan revision", conflict.plan_revision.to_string())
                .field("Replacement", optional(conflict.replacement_id.as_deref()))
                .render();
            let mut table = Table::new(["Saved side", "Source", "Reference", "Tree digest"]);
            for (label, side) in [
                ("base", &conflict.base),
                ("current", &conflict.current),
                ("incoming", &conflict.incoming),
            ] {
                table.row([
                    label.to_owned(),
                    safe(&side.source),
                    safe(&side.reference_id),
                    optional(side.tree_digest.as_deref()),
                ]);
            }
            table.render();
            let mut branches = Table::new([
                "Member",
                "Original revision",
                "State",
                "Saved epoch",
                "Saved head",
                "Changed",
            ]);
            for branch in &conflict.branches {
                branches.row([
                    safe(&branch.entry_name),
                    safe(&branch.revision_id),
                    safe(&branch.state_id),
                    branch.state_epoch.to_string(),
                    optional(branch.checkpoint_id.as_deref()),
                    branch.changed.to_string(),
                ]);
            }
            branches.render();
            merge_conflicts(&conflict.conflicts);
            let mut choices =
                Table::new(["Choice path", "Unit", "Use", "File tree", "Directory tree"]);
            for choice in &conflict.choices {
                choices.row([
                    optional(choice.path.as_deref()),
                    safe(&choice.unit.join(", ")),
                    optional(choice.r#use.as_deref()),
                    optional(choice.file_tree_digest.as_deref()),
                    optional(choice.directory_tree_digest.as_deref()),
                ]);
            }
            choices.render();
            (&diff.items, diff.next_cursor.as_deref())
        }
        ConflictComparison::Migration { conflict, diff } => {
            Details::new()
                .field("Kind", "version migration")
                .field("Conflict", safe(&conflict.summary.id))
                .field("Account", safe(&conflict.summary.account_id))
                .field("Skill", safe(&conflict.summary.skill_id))
                .field("Mode", safe(&conflict.summary.mode))
                .field("Current status", safe(&conflict.summary.status))
                .field("Original status", safe(&conflict.original.status))
                .field(
                    "Replacement",
                    optional(conflict.summary.replacement_id.as_deref()),
                )
                .field(
                    "Superseded reason",
                    optional(conflict.summary.superseded_reason.as_deref()),
                )
                .render();
            let mut table = Table::new([
                "Saved side",
                "Source",
                "Revision",
                "Checkpoint",
                "Tree digest",
            ]);
            for (label, side) in [
                ("base", &conflict.base),
                ("current", &conflict.current),
                ("incoming", &conflict.incoming),
                ("directory context", &conflict.directory),
            ] {
                table.row([
                    label.to_owned(),
                    safe(&side.source),
                    optional(side.revision_id.as_deref()),
                    optional(side.checkpoint_id.as_deref()),
                    optional(side.tree_digest.as_deref()),
                ]);
            }
            table.render();
            merge_conflicts(&conflict.original.conflicts);
            let mut live = Table::new([
                "Live branch",
                "State",
                "Revision",
                "Epoch",
                "Head",
                "Expired",
            ]);
            for (label, branch) in [
                ("source", conflict.live.source.as_ref()),
                ("target", Some(&conflict.live.target)),
            ] {
                if let Some(branch) = branch {
                    live.row([
                        label.to_owned(),
                        safe(&branch.state_id),
                        safe(&branch.revision_id),
                        branch.epoch.to_string(),
                        optional(branch.checkpoint_id.as_deref()),
                        branch.expired.to_string(),
                    ]);
                }
            }
            live.render();
            Details::new()
                .field("Source head advanced", conflict.live.source_head_advanced)
                .field(
                    "Recomputation reasons",
                    safe(&conflict.live.recomputation_reasons.join(", ")),
                )
                .render();
            eprintln!("The diff compares saved inputs. Live branch changes do not replace those inputs or automatically recompute this attempt.");
            (&diff.items, diff.next_cursor.as_deref())
        }
    };
    let mut table = Table::new(["Path", "Saved base", "Saved current", "Saved incoming"]);
    for item in items {
        table.row([
            safe(&item.path),
            super::render::entry(item.base.as_ref()),
            super::render::entry(item.current.as_ref()),
            super::render::entry(item.incoming.as_ref()),
        ]);
    }
    table.render();
    Details::new()
        .field("Next cursor", optional(cursor))
        .render();
    eprintln!("Metadata differences only. Continue with the same --conflict ID and the returned --cursor.");
}

fn merge_conflicts(items: &[MergeConflict]) {
    let mut table = Table::new(["Conflict path", "Reason", "Linked unit"]);
    for item in items {
        table.row([
            safe(&item.path),
            safe(&item.reason),
            safe(&item.unit.join(", ")),
        ]);
    }
    table.render();
}
fn optional(value: Option<&str>) -> String {
    safe(value.unwrap_or("none"))
}
fn epoch(value: Option<i64>) -> String {
    value.map_or_else(|| "none".to_owned(), |v| v.to_string())
}
