//! State previews and original receipts keep branch data loss and scope visible.

use crate::api::skill_state::{StateCommandRequest, StateCommandView, StatePathDiff};
use crate::api::skills::SkillResult;
use crate::skill_commands::{print_json, render_summary, safe, SkillExit};
use crate::terminal::{Details, Table};
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct Preview<'a> {
    pub request: &'a StateCommandRequest,
    pub preview: &'a StateCommandView,
    pub recovering_original_request: bool,
}

pub(super) fn preview(
    request: &StateCommandRequest,
    result: &SkillResult<StateCommandView>,
    recovering: bool,
    json: bool,
) -> Result<()> {
    if let Some(view) = &result.data {
        let data = Preview {
            request,
            preview: view,
            recovering_original_request: recovering,
        };
        if json {
            print_json(&SkillResult {
                schema_version: 1,
                operation_id: None,
                status: "preview".to_owned(),
                committed: false,
                retryable: false,
                data: Some(data),
                errors: Vec::new(),
            })?;
        } else {
            show_plan(&data)?;
        }
    }
    Ok(())
}

pub(super) fn show_plan(data: &impl Serialize) -> Result<()> {
    for line in serde_json::to_string_pretty(data)?.lines() {
        eprintln!("{}", safe(line));
    }
    eprintln!("State heads and epochs change for future sessions. Existing sessions keep their fixed snapshots; late old-epoch writes remain detached history.");
    Ok(())
}

pub(in crate::skill_commands) fn render(
    result: &SkillResult<StateCommandView>,
    code: i32,
    json: bool,
) -> Result<()> {
    if json {
        print_json(result)?;
    } else {
        render_summary(result);
        if let Some(view) = &result.data {
            Details::new()
                .field(
                    "Operation",
                    safe(view.operation_id.as_deref().unwrap_or("none")),
                )
                .field("Action", format!("{:?}", view.action))
                .field("Account", safe(&view.before.selector.account_id))
                .field(
                    "Directory checkpoint",
                    safe(view.result_checkpoint_id.as_deref().unwrap_or("none")),
                )
                .field("Result tree", safe(&view.result_tree_digest))
                .field("Directory epoch advances", view.directory_epoch_advances)
                .field(
                    "Superseded conflicts",
                    view.superseded_conflicts.to_string(),
                )
                .render();
            let mut table = Table::new([
                "Name",
                "Source",
                "Revision",
                "Prior state epoch",
                "Prior head",
            ]);
            for target in &view.affected {
                table.row([
                    safe(&target.name),
                    safe(&target.skill_id),
                    safe(&target.revision_id),
                    target
                        .state_epoch
                        .map_or_else(|| "uninitialized".to_owned(), |n| n.to_string()),
                    safe(target.head_checkpoint_id.as_deref().unwrap_or("none")),
                ]);
            }
            table.render();
            changes("Account directory before publication", &view.changes);
            for (branch, target) in view.branch_changes.iter().zip(&view.affected) {
                let label = format!("Original branch: {}", safe(&target.name));
                if let Some(items) = &branch.changes {
                    changes(&label, items);
                } else {
                    eprintln!("{label}: prior content expired; data changes cannot be enumerated.");
                }
            }
        }
        if result.status == "unknown" {
            if let Some(key) = result
                .errors
                .first()
                .and_then(|e| e.details.get("idempotency_key"))
                .and_then(|v| v.as_str())
            {
                eprintln!("Retained original key: {}", safe(key));
            }
        }
    }
    if code == 0 {
        Ok(())
    } else {
        Err(SkillExit(code).into())
    }
}

fn changes(label: &str, values: &[StatePathDiff]) {
    use crate::skill_commands::state::render::entry;
    Details::new().field("Comparison", label).render();
    let mut table = Table::new(["Path", "Before", "Published"]);
    for value in values {
        table.row([
            safe(&value.path),
            entry(value.base.as_ref()),
            entry(value.current.as_ref()),
        ]);
    }
    table.render();
}
