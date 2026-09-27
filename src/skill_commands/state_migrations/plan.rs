//! Recover the original command before reading live branches or selecting new versions.

use super::journal::{self, Kind, Saved};
use crate::api::skill_state::{
    MigrationReceipt, MigrationRequest, MigrationSelector, MigrationView,
};
use crate::api::skills::SkillResult;
use crate::local_state::{skill_command_state, SkillCommandRecord};
use crate::skill_commands::{context::ContextData, remote_result, requests, state_mutations};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

pub(super) struct Plan {
    pub record: SkillCommandRecord,
    pub saved: Saved,
    pub preview: Option<SkillResult<MigrationView>>,
    pub recovered: Option<SkillResult<MigrationReceipt>>,
    pub recovering: bool,
}

pub(super) fn intent(selection: &MigrationSelector) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&("state_migration", selection))?)
    ))
}

pub(super) async fn prepare(
    context: &ContextData,
    selection: MigrationSelector,
    dry_run: bool,
) -> Result<Plan> {
    let digest = intent(&selection)?;
    let lookup = (context.server.clone(), context.user.clone(), digest.clone());
    let pending = skill_command_state(context.paths.clone(), move |state| {
        state.pending_skill_command(&lookup.0, &lookup.1, &lookup.2)
    })
    .await?;
    if let Some(record) = pending {
        let saved = journal::saved(&record)?.context("retained command is not a migration")?;
        if saved.selection != selection {
            bail!("retained migration intent differs");
        }
        let mut plan = Plan {
            record,
            saved,
            preview: None,
            recovered: None,
            recovering: true,
        };
        if dry_run {
            let original = context
                .client
                .skill_migration_operation_by_key(
                    &context.token,
                    &plan.saved.request.idempotency_key,
                )
                .await?;
            if original.data.is_some() {
                plan.saved.validate_receipt(&original)?;
                plan.recovered = Some(original);
            } else if state_mutations::not_found(&original) {
                let mut request = plan.saved.request.clone();
                request.dry_run = true;
                let preview = context
                    .client
                    .migrate_skill_state(&context.token, &request)
                    .await?;
                let view = remote_result::data(preview.clone())?;
                plan.saved.validate_view(&view, false)?;
                plan.preview = Some(preview);
            } else {
                remote_result::data(original)?;
            }
        }
        return Ok(plan);
    }
    let current = remote_result::data(
        context
            .client
            .skill_migration_current(&context.token, &selection)
            .await?,
    )?;
    let stable = MigrationSelector {
        account_id: current.account_id.clone(),
        skill: current.skill_id.clone(),
        from_revision: current.source.revision_id.clone(),
        to_revision: current.target.revision_id.clone(),
    };
    let mut request = MigrationRequest {
        selector: stable,
        expected: current,
        idempotency_key: requests::new_key()?,
        dry_run: true,
    };
    let preview = context
        .client
        .migrate_skill_state(&context.token, &request)
        .await?;
    let reviewed = remote_result::data(preview.clone())?;
    request.dry_run = false;
    let saved = Saved {
        command: Kind::Migration,
        selection,
        request,
        reviewed,
    };
    let request_json = serde_json::to_string(&saved)?;
    if request_json.len() > 4 * 1024 * 1024 {
        return Err(remote_result::failure(
            "LIMIT_EXCEEDED",
            "The exact migration request and review exceed the 4 MiB recovery journal limit.",
            Some(saved.request.selector.account_id.clone()),
        ));
    }
    let record = SkillCommandRecord {
        server_url: context.server.clone(),
        user_id: context.user.clone(),
        intent_digest: digest,
        idempotency_key: saved.request.idempotency_key.clone(),
        request_json,
    };
    journal::saved(&record)?.context("invalid migration journal")?;
    Ok(Plan {
        record,
        saved,
        preview: Some(preview),
        recovered: None,
        recovering: false,
    })
}
