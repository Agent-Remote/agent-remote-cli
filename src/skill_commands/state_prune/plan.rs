//! Recover pending intent before resolving names or acquiring a new confirmation.

use anyhow::{bail, Context, Result};

use super::{
    journal::{self, Kind, Saved},
    review::Counts,
    spool::Spool,
};
use crate::api::skill_state::{PrunePreviewRequest, PruneRequest, PruneSummary, StateSelector};
use crate::local_state::{skill_command_state, SkillCommandRecord};
use crate::skill_commands::{context::ContextData, remote_result, requests};

pub(super) enum Plan {
    Pending {
        record: SkillCommandRecord,
        saved: Saved,
    },
    Fresh(Review),
}

pub(super) struct Review {
    pub summary: PruneSummary,
    pub total: u64,
    pub confirmation: Option<String>,
    pub spool: Spool,
}

pub(super) async fn prepare(
    context: &ContextData,
    selection: &StateSelector,
    early: bool,
) -> Result<Plan> {
    let lookup = (
        context.server.clone(),
        context.user.clone(),
        journal::intent(selection, early)?,
    );
    if let Some(record) = skill_command_state(context.paths.clone(), move |state| {
        state.pending_skill_command(&lookup.0, &lookup.1, &lookup.2)
    })
    .await?
    {
        let saved = journal::saved(&record)?.context("retained command is not prune")?;
        if saved.selection != *selection || saved.all_unreferenced != early {
            bail!("retained prune intent differs");
        }
        return Ok(Plan::Pending { record, saved });
    }
    let mut request = PrunePreviewRequest {
        selector: selection.clone(),
        all_unreferenced: early,
        cursor: None,
        limit: 100,
    };
    let mut spool = Spool::new().await?;
    let mut counts = Counts::default();
    let mut original = None;
    loop {
        let page = remote_result::data(
            context
                .client
                .preview_skill_prune(&context.token, &request)
                .await?,
        )?;
        if page.offset != spool.rows {
            bail!("prune preview skipped or repeated rows");
        }
        if let Some((summary, total)) = &original {
            if summary != &page.summary || *total != page.total {
                bail!("prune preview changed during traversal");
            }
        } else {
            original = Some((page.summary.clone(), page.total));
        }
        counts.include(&page.rows)?;
        spool = spool.append(page.rows).await?;
        match page.next_cursor {
            Some(cursor) => {
                request.cursor = Some(cursor);
                request.selector = page.summary.binding.selector;
            }
            None => {
                if spool.rows != page.total {
                    bail!("prune preview is incomplete");
                }
                counts.finish(&page.summary)?;
                return Ok(Plan::Fresh(Review {
                    summary: page.summary,
                    total: page.total,
                    confirmation: page.confirmation,
                    spool,
                }));
            }
        }
    }
}

pub(super) fn record(
    context: &ContextData,
    selection: StateSelector,
    summary: PruneSummary,
    total: u64,
    confirmation: String,
) -> Result<SkillCommandRecord> {
    let early = summary.binding.all_unreferenced;
    let saved = Saved {
        command: Kind::Prune,
        selection,
        all_unreferenced: early,
        request: PruneRequest {
            idempotency_key: requests::new_key()?,
            confirmation,
        },
        summary,
        total,
    };
    let record = SkillCommandRecord {
        server_url: context.server.clone(),
        user_id: context.user.clone(),
        intent_digest: journal::intent(&saved.selection, early)?,
        idempotency_key: saved.request.idempotency_key.clone(),
        request_json: serde_json::to_string(&saved)?,
    };
    journal::saved(&record)?.context("invalid prune recovery record")?;
    Ok(record)
}
