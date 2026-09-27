//! Explain current storage observations without changing or reusing an operation receipt.

use anyhow::Result;

use super::{print_failure, print_json, query_exit, remote_result, safe, SkillExit};
use crate::api::skill_diagnostics::{HistoryDiagnostic, StorageView};
use crate::api::ApiClient;
use crate::terminal::{Details, Table};

pub(super) async fn status(client: &ApiClient, token: &str, json: bool) -> Result<i32> {
    let result = tokio::select! {
        result = client.skill_storage(token) => result?,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            let error = remote_result::failure("SKILL_INTERRUPTED", "Storage query interrupted; no remote state was changed.", None);
            print_failure(&error, json);
            return Err(SkillExit(130).into());
        }
    };
    if json {
        print_json(&result)?;
    } else {
        super::render_summary(&result);
        if let Some(value) = &result.data {
            storage(value);
        }
    }
    Ok(query_exit(&result))
}

pub(super) fn storage(value: &StorageView) {
    Details::new()
        .field("Storage scope", "current user, Server only")
        .field("Observed at", safe(&value.observed_at))
        .render();
    let mut table = Table::new(["Category", "Stored bytes", "Reserved bytes", "Limit bytes"]);
    table.row([
        "Package".to_owned(),
        value.package_bytes.to_string(),
        value.package_reserved_bytes.to_string(),
        value.policy.user_package_bytes.to_string(),
    ]);
    table.row([
        "State".to_owned(),
        value.state_bytes.to_string(),
        value.state_reserved_bytes.to_string(),
        value.policy.user_state_bytes.to_string(),
    ]);
    table.render();
    Details::new()
        .field(
            "Package staging limit bytes",
            value.policy.user_staging_bytes,
        )
        .field("Ordinary history days", value.policy.history_days)
        .field("Archived history days", value.policy.archive_days)
        .field("Inactive upload hours", value.policy.staging_hours)
        .field("Pending deletion tasks", value.deletion.pending_tasks)
        .field("Retrying deletion tasks", value.deletion.retrying_tasks)
        .field("Pending deletion bytes", value.deletion.pending_file_bytes)
        .field("Completed deletion tasks", value.deletion.completed_tasks)
        .field(
            "Cumulative deleted bytes",
            value.deletion.cumulative_deleted_bytes,
        )
        .render();
    eprintln!("These are user-wide Server counters. Cumulative deletion is not free disk space; Node disk and session copies are not observed.");
}

pub(super) fn retention(value: &HistoryDiagnostic) {
    Details::new()
        .field(
            "History",
            format!("{} {}", safe(&value.kind), safe(&value.id)),
        )
        .field("Retention", safe(&value.state))
        .field("Archived", value.archived)
        .field("Retention days", value.retention_days)
        .field(
            "Released at",
            safe(value.released_at.as_deref().unwrap_or("unknown")),
        )
        .field(
            "Retention deadline",
            safe(value.expires_at.as_deref().unwrap_or("none")),
        )
        .field("Protected by", safe(&value.protected_by.join(", ")))
        .render();
    if value.state == "due" {
        eprintln!("This waiting period has elapsed. Complete dependency review and revalidation are still required before cleanup.");
    }
}
