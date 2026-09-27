//! Terminal-safe metadata presentation without reading or guessing file contents.

use super::{Checkpoint, CheckpointDiff, Exported, History, Info};
use crate::api::skill_state::{StateBaseline, StateScope};
use crate::skill_commands::safe;
use crate::skills::manifest::Entry;
use crate::terminal::{Details, Table};

pub(super) fn history(value: &History) {
    Details::new()
        .field("Account", safe(&value.selector.account_id))
        .field("Scope", scope(value.selector.scope))
        .render();
    let mut table = Table::new([
        "Checkpoint",
        "Revision",
        "Install epoch",
        "State epoch",
        "Directory epoch",
        "Head",
        "Retained",
        "Finalization",
    ]);
    for item in &value.checkpoints.items {
        table.row([
            safe(&item.id),
            optional(item.revision_id.as_deref()),
            epoch(item.installation_epoch),
            epoch(item.state_epoch),
            epoch(item.directory_epoch),
            item.is_head.to_string(),
            item.retained.to_string(),
            optional(item.finalization_status.as_deref()),
        ]);
    }
    table.render();
    let mut pending = Table::new([
        "Pending finalization",
        "Source Node",
        "Status",
        "Incoming digest",
    ]);
    for item in &value.pending.items {
        pending.row([
            safe(&item.id),
            safe(&item.node_id),
            safe(&item.status),
            safe(&item.incoming_digest),
        ]);
    }
    pending.render();
    Details::new()
        .field(
            "Next checkpoint cursor",
            optional(value.checkpoints.next_cursor.as_deref()),
        )
        .field(
            "Next pending cursor",
            optional(value.pending.next_cursor.as_deref()),
        )
        .render();
    eprintln!("Pending finalizations are held by the source Node and are not Server-exportable checkpoints.");
}

pub(super) fn info(value: &Info) {
    checkpoint(&value.checkpoint);
    if let Some(storage) = &value.checkpoint.storage {
        crate::skill_commands::diagnostics::storage(storage);
    }
    if let Some(retention) = &value.checkpoint.retention {
        crate::skill_commands::diagnostics::retention(retention);
    }
    if let Some(page) = &value.members {
        let mut table = Table::new([
            "Member",
            "Skill",
            "Revision",
            "Checkpoint",
            "Install epoch",
            "State epoch",
        ]);
        for member in &page.items {
            table.row([
                safe(&member.entry_name),
                safe(&member.skill_id),
                safe(&member.revision_id),
                safe(&member.checkpoint_id),
                member.installation_epoch.to_string(),
                epoch(member.state_epoch),
            ]);
        }
        table.render();
        Details::new()
            .field("Next member cursor", optional(page.next_cursor.as_deref()))
            .render();
    }
}

fn checkpoint(value: &Checkpoint) {
    Details::new()
        .field("Checkpoint", safe(&value.id))
        .field("Account", safe(&value.account_id))
        .field("Scope", scope(value.scope))
        .field("Skill", optional(value.skill_id.as_deref()))
        .field(
            "Origin",
            match value.origin {
                Some(crate::api::skill_state::StateOrigin::UserLibrary) => "user_library",
                Some(crate::api::skill_state::StateOrigin::AccountLocal) => "account_local",
                None => "none",
            },
        )
        .field("Revision", optional(value.revision_id.as_deref()))
        .field("Branch", optional(value.state_id.as_deref()))
        .field("Installation epoch", epoch(value.installation_epoch))
        .field("Checkpoint state epoch", epoch(value.state_epoch))
        .field("Current state epoch", epoch(value.current_state_epoch))
        .field("Checkpoint directory epoch", epoch(value.directory_epoch))
        .field(
            "Current directory epoch",
            epoch(value.current_directory_epoch),
        )
        .field("Parent", optional(value.parent_id.as_deref()))
        .field(
            "Backing directory",
            optional(value.backing_directory_id.as_deref()),
        )
        .field("Subtree prefix", safe(&value.subtree_prefix))
        .field("Content digest", safe(&value.content_digest))
        .field("Head", value.is_head)
        .field("Retained", value.retained)
        .field("Invalid skill format", value.invalid_skill_format)
        .field("Storage", if value.retained { "server" } else { "expired" })
        .field(
            "Source session",
            optional(value.source_session_reference_id.as_deref()),
        )
        .field("Finalization", optional(value.finalization_id.as_deref()))
        .field(
            "Finalization status",
            optional(value.finalization_status.as_deref()),
        )
        .field("Created", safe(&value.created_at))
        .render();
}

pub(super) fn diff(value: &CheckpointDiff) {
    let kind = match value.base_kind {
        StateBaseline::PackageRevision => "package_revision",
        StateBaseline::LocalInitialRevision => "local_initial_revision",
        StateBaseline::DirectoryCheckpoint => "directory_checkpoint",
    };
    Details::new()
        .field("Checkpoint", safe(&value.checkpoint_id))
        .field("Baseline kind", kind)
        .field("Baseline reference", safe(&value.base_reference_id))
        .field("Baseline digest", safe(&value.base_tree_digest))
        .field("Checkpoint digest", safe(&value.current_tree_digest))
        .render();
    let mut table = Table::new(["Path", "Baseline", "Checkpoint"]);
    for change in &value.items {
        table.row([
            safe(&change.path),
            entry(change.base.as_ref()),
            entry(change.current.as_ref()),
        ]);
    }
    table.render();
    Details::new()
        .field("Next cursor", optional(value.next_cursor.as_deref()))
        .render();
    if value.next_cursor.is_some() {
        eprintln!(
            "Continue with --checkpoint {} and --cursor; the current head may change.",
            safe(&value.checkpoint_id)
        );
    }
    eprintln!("Metadata differences only; export the checkpoint to inspect complete file bytes.");
}

pub(super) fn exported(value: &Exported) {
    Details::new()
        .field("Checkpoint", safe(&value.checkpoint.id))
        .field("Output", safe(&value.output.to_string_lossy()))
        .field("Format", value.format)
        .field("Tree digest", safe(&value.tree_digest))
        .field("Verified file objects", value.file_objects.to_string())
        .render();
    eprintln!("manifest.json retains original paths, permissions and links; objects/<sha256> contains file bytes. No links were created locally.");
}

fn scope(value: StateScope) -> &'static str {
    match value {
        StateScope::Item => "item",
        StateScope::AccountDirectory => "account-directory",
    }
}
fn optional(value: Option<&str>) -> String {
    safe(value.unwrap_or("none"))
}
fn epoch(value: Option<i64>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |v| v.to_string())
}
pub(in crate::skill_commands) fn entry(value: Option<&Entry>) -> String {
    match value {
        None => "absent".to_owned(),
        Some(value) => format!(
            "{:?} mode={:03o} bytes={} sha256={} target={} dependency={}",
            value.kind,
            value.mode,
            value.size,
            safe(&value.sha256),
            safe(&value.target),
            safe(&value.dependency)
        ),
    }
}
