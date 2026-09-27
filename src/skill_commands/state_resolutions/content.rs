//! Runtime-state capture and scoped upload; only confirmed staged bytes reach the network.

use crate::api::skill_state::ResolutionTarget;
use crate::cli::skills::StateResolveArgs;
use crate::skill_commands::{context::ContextData, remote_result, requests};
use crate::skills::state_snapshot::{CaptureCancellation, StateLimits, StateSnapshot};
use anyhow::{bail, Result};
use std::sync::Arc;

pub(super) async fn capture(
    args: &StateResolveArgs,
    cancellation: &CaptureCancellation,
) -> Result<Option<Arc<StateSnapshot>>> {
    let Some(path) = args.file.as_ref().or(args.directory.as_ref()).cloned() else {
        return Ok(None);
    };
    let file = args.file.is_some();
    let cancellation = cancellation.clone();
    tokio::task::spawn_blocking(move || {
        let snapshot = if file {
            StateSnapshot::file(&path, StateLimits::ITEM, &cancellation)?
        } else {
            StateSnapshot::directory(&path, StateLimits::DIRECTORY, &cancellation)?
        };
        if !file {
            reject_export_bundle(&snapshot)?;
        }
        Ok(Some(Arc::new(snapshot)))
    })
    .await?
    .map_err(capture_error)
}

fn reject_export_bundle(snapshot: &StateSnapshot) -> Result<()> {
    use crate::skills::manifest::EntryKind;
    use std::io::Read;
    let manifest = snapshot.manifest();
    if !manifest.entries.iter().any(|e| e.path == "manifest.json")
        || !manifest
            .entries
            .iter()
            .any(|e| e.path == "objects" && e.kind == EntryKind::Directory)
    {
        return Ok(());
    }
    if let Some(entry) = manifest
        .entries
        .iter()
        .find(|e| e.path == "checkpoint.json" && e.kind == EntryKind::File && e.size <= 1024 * 1024)
    {
        let mut bytes = Vec::new();
        snapshot
            .open_object(&entry.sha256)?
            .take(entry.size + 1)
            .read_to_end(&mut bytes)?;
        if serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("format").and_then(|v| v.as_str()).map(str::to_owned))
            .as_deref()
            == Some("agent-remote-skill-checkpoint-v1")
        {
            return Err(remote_result::failure(
                "INVALID_RESOLUTION_SOURCE",
                "--directory requires a materialized tree, not a checkpoint export bundle.",
                None,
            ));
        }
    }
    Ok(())
}

pub(super) async fn upload(
    context: &ContextData,
    target: &ResolutionTarget,
    snapshot: Arc<StateSnapshot>,
) -> Result<()> {
    let key = requests::new_key()?;
    let upload = remote_result::data(
        context
            .client
            .begin_skill_resolution_upload(&context.token, target, &key, &snapshot)
            .await?,
    )?;
    // Validate the scoped lease before bytes; a previously complete lease needs no retransmission.
    let current = remote_result::data(
        context
            .client
            .skill_resolution_upload_status(&context.token, target, &upload.id, &snapshot)
            .await?,
    )?;
    if matches!(
        current.status,
        crate::api::skill_content::SkillUploadStatus::Expired
    ) {
        bail!("resolution upload lease expired");
    }
    if !matches!(
        current.status,
        crate::api::skill_content::SkillUploadStatus::Committed
    ) {
        let mut uploaded = std::collections::BTreeSet::new();
        for entry in &snapshot.manifest().entries {
            if entry.kind == crate::skills::manifest::EntryKind::File
                && uploaded.insert(&entry.sha256)
            {
                remote_result::data(
                    context
                        .client
                        .put_skill_resolution_file(
                            &context.token,
                            target,
                            &upload.id,
                            Arc::clone(&snapshot),
                            &entry.sha256,
                        )
                        .await?,
                )?;
            }
        }
    }
    remote_result::data(
        context
            .client
            .complete_skill_resolution_upload(&context.token, target, &upload.id, &snapshot)
            .await?,
    )?;
    Ok(())
}

fn capture_error(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<remote_result::Rejected>().is_some() {
        return error;
    }
    let detail = error.to_string();
    let (code, message) = if detail.starts_with("RUNTIME_LINK_METADATA_REQUIRED:") {
        ("RUNTIME_LINK_METADATA_REQUIRED","A local absolute link has no runtime dependency identity. Choose a saved side or provide a self-contained tree with ordinary relative links.")
    } else if detail.starts_with("SOURCE_UNSTABLE:") {
        ("SOURCE_UNSTABLE","The local resolution source changed during capture. Stop writers and retry before confirming a new candidate.")
    } else if detail.starts_with("QUOTA_EXCEEDED:") {
        ("QUOTA_EXCEEDED","The local resolution source exceeds its state byte or entry limit. No content was uploaded.")
    } else {
        ("INVALID_RESOLUTION_SOURCE","Cannot capture the selected local input. Use an ordinary file or a stable materialized directory with portable names and internal relative links.")
    };
    remote_result::failure(code, message, None)
}
