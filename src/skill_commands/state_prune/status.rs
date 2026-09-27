//! Original disclosure and current physical progress are queried without resubmitting cleanup.

use std::cell::Cell;

use anyhow::{bail, Context, Result};
use serde_json::json;

use super::{review::Counts, spool::Spool};
use crate::api::skill_state::PruneReceipt;
use crate::api::skills::SkillResult;
use crate::api::ApiClient;
use crate::skill_commands::remote_result;

pub(in crate::skill_commands) async fn display(
    client: &ApiClient,
    token: &str,
    result: SkillResult<PruneReceipt>,
    json: bool,
    displaying: &Cell<bool>,
) -> Result<i32> {
    if result.data.is_none() {
        super::render(&result, 1, json)?;
        return Ok(1);
    }
    let receipt = result.data.as_ref().context("prune receipt missing")?;
    let mut spool = Spool::new().await?;
    let mut counts = Counts::default();
    loop {
        let page = remote_result::data(
            client
                .skill_prune_entries(token, &receipt.operation_id, spool.rows, 100)
                .await?,
        )?;
        if page.total != receipt.disclosure_rows {
            bail!("prune receipt disclosure total changed");
        }
        counts.include(&page.rows)?;
        spool = spool.append(page.rows).await?;
        if page.next_offset.is_none() {
            break;
        }
    }
    if spool.rows != receipt.disclosure_rows {
        bail!("prune receipt disclosure is incomplete");
    }
    counts.finish(&receipt.summary)?;
    let progress = remote_result::data(
        client
            .skill_prune_progress(token, &receipt.operation_id)
            .await?,
    )?;
    if progress
        .pending_file_bytes
        .checked_add(progress.deleted_file_bytes)
        != Some(receipt.summary.pending_file_bytes)
    {
        bail!("prune physical byte totals differ from original acceptance");
    }
    let display = SkillResult {
        schema_version: result.schema_version,
        operation_id: result.operation_id,
        status: result.status,
        committed: result.committed,
        retryable: result.retryable,
        errors: result.errors,
        data: Some(
            json!({"receipt":receipt,"deletion_progress":progress,"disclosure_rows":receipt.disclosure_rows}),
        ),
    };
    spool.display(display, json, displaying).await?;
    Ok(0)
}
