//! Pending acceptance is recovered before touching a possibly changed or missing local input.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use super::{content, source};
use super::{
    journal::{self, Saved},
    preview::{self, Preview, Review},
};
use crate::api::skill_state::*;
use crate::api::skills::SkillResult;
use crate::cli::skills::{ResolutionSide, StateResolveArgs};
use crate::local_state::{skill_command_state, SkillCommandRecord};
use crate::skill_commands::{context::ContextData, remote_result, requests, state_mutations};
use crate::skills::state_snapshot::CaptureCancellation;

pub(super) enum Plan {
    ReadOnly(Preview),
    Recovered(SkillResult<ResolutionOutcome>),
    Submit {
        record: SkillCommandRecord,
        recovering: bool,
    },
}

#[derive(Serialize)]
struct Intent<'a> {
    command: &'static str,
    conflict: &'a str,
    path: &'a Option<String>,
    side: &'a Option<ResolutionSide>,
    file: Option<PathBuf>,
    directory: Option<PathBuf>,
}

pub(super) async fn prepare(
    context: &ContextData,
    args: &StateResolveArgs,
    cancellation: &CaptureCancellation,
) -> Result<Plan> {
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&Intent {
            command: "state_resolution",
            conflict: &args.conflict,
            path: &args.path,
            side: &args.use_side,
            file: intent_path(args.file.as_deref())?,
            directory: intent_path(args.directory.as_deref())?,
        })?)
    );
    let lookup = (context.server.clone(), context.user.clone(), digest.clone());
    let pending = skill_command_state(context.paths.clone(), move |state| {
        state.pending_skill_command(&lookup.0, &lookup.1, &lookup.2)
    })
    .await?;
    if let Some(record) = pending {
        return recover(context, args, record).await;
    }

    let (source, revision, prior_choices) = source::load(context, &args.conflict).await?;
    let target = source.borrowed().target()?;
    let snapshot = content::capture(args, cancellation).await?;
    let choice = ResolutionChoice {
        path: args.path.clone(),
        unit: vec![],
        r#use: args.use_side.map(|s| {
            match s {
                ResolutionSide::Current => "current",
                ResolutionSide::Incoming => "incoming",
            }
            .to_owned()
        }),
        file_tree_digest: snapshot
            .as_ref()
            .filter(|_| args.file.is_some())
            .map(|s| s.tree_digest().to_owned()),
        directory_tree_digest: snapshot
            .as_ref()
            .filter(|_| args.directory.is_some())
            .map(|s| s.tree_digest().to_owned()),
    };
    let mut request = ResolutionRequest {
        idempotency_key: requests::new_key()?,
        expected_revision: revision,
        choice,
        dry_run: true,
    };
    let review = if let Some(snapshot) = &snapshot {
        let preview = context
            .client
            .preview_skill_resolution_content(
                &context.token,
                &source.borrowed(),
                &ResolutionPreviewRequest {
                    expected_revision: revision,
                    choice: request.choice.clone(),
                    manifest: snapshot.manifest().clone(),
                },
            )
            .await?;
        remote_result::data(preview.clone())?;
        Review::Metadata(Box::new(preview))
    } else {
        let result = context
            .client
            .resolve_skill_conflict(&context.token, &target, &request)
            .await?;
        remote_result::data(result.clone())?;
        Review::Verified(Box::new(result))
    };
    if args.options.dry_run {
        return Ok(Plan::ReadOnly(Preview { source, review }));
    }
    if !args.options.yes {
        let displayed = Preview {
            source: source.clone(),
            review: review.clone(),
        };
        crate::skill_commands::output::review(move || preview::render(&displayed, false)).await?;
        if !crate::skill_commands::confirmation::confirm(
            "Save this choice and publish if all conflicts are resolved?",
        )
        .await?
        {
            return Err(remote_result::failure(
                "CHANGE_CANCELLED",
                "No content was uploaded and no resolution choice was submitted.",
                Some(args.conflict.clone()),
            ));
        }
    }
    let verified = match review {
        Review::Verified(result) => *result,
        Review::Metadata(review) => {
            let snapshot = snapshot.context("custom snapshot unavailable")?;
            content::upload(context, &target, snapshot).await?;
            let result = context
                .client
                .resolve_skill_conflict(&context.token, &target, &request)
                .await?;
            let view = remote_result::data(result.clone())?;
            source.validate_outcome(&view)?;
            preview::verify_metadata(
                review
                    .data
                    .as_ref()
                    .context("metadata review unavailable")?,
                &view,
            )?;
            result
        }
    };
    let reviewed = remote_result::data(verified)?;
    request.dry_run = false;
    let saved = Saved {
        command: journal::Kind::StateResolution,
        target,
        request,
        prior_choices,
        reviewed,
        source,
    };
    let request_json = serde_json::to_string(&saved)?;
    if request_json.len() > 4 * 1024 * 1024 {
        return Err(remote_result::failure(
            "LIMIT_EXCEEDED",
            "The exact reviewed resolution exceeds the 4 MiB recovery journal limit.",
            Some(args.conflict.clone()),
        ));
    }
    let record = SkillCommandRecord {
        server_url: context.server.clone(),
        user_id: context.user.clone(),
        intent_digest: digest,
        idempotency_key: saved.request.idempotency_key.clone(),
        request_json,
    };
    journal::saved(&record)?.context("resolution journal unavailable")?;
    Ok(Plan::Submit {
        record,
        recovering: false,
    })
}

fn intent_path(path: Option<&Path>) -> Result<Option<PathBuf>> {
    path.map(|path| {
        if path.is_absolute() {
            Ok(path.to_owned())
        } else {
            Ok(std::env::current_dir()?.join(path))
        }
    })
    .transpose()
}

async fn recover(
    context: &ContextData,
    args: &StateResolveArgs,
    record: SkillCommandRecord,
) -> Result<Plan> {
    let saved = journal::saved(&record)?.context("retained command is not a resolution")?;
    if saved.target.conflict_id != args.conflict || saved.request.choice.path != args.path {
        bail!("retained resolution intent differs");
    }
    if !args.options.dry_run {
        return Ok(Plan::Submit {
            record,
            recovering: true,
        });
    }
    let original = context
        .client
        .skill_resolution_operation_by_key(
            &context.token,
            saved.target.kind,
            &saved.request.idempotency_key,
        )
        .await?;
    if original.data.is_some() {
        saved.validate_receipt(&original)?;
        return Ok(Plan::Recovered(original));
    }
    if !state_mutations::not_found(&original) {
        remote_result::data(original)?;
    }
    let mut request = saved.request.clone();
    request.dry_run = true;
    let result = context
        .client
        .resolve_skill_conflict(&context.token, &saved.target, &request)
        .await?;
    let view = remote_result::data(result.clone())?;
    saved.source.validate_outcome(&view)?;
    if !view.stale() && journal::review_form(&view) != journal::review_form(&saved.reviewed) {
        bail!("original resolution preview changed");
    }
    Ok(Plan::ReadOnly(Preview {
        source: saved.source,
        review: Review::Verified(Box::new(result)),
    }))
}
