//! Transfer complete private snapshots, never reading live sources during HTTP requests.

use super::{acceptance::retryable_transport, remote_result::data};
use crate::api::skill_content::SkillUploadStatus;
use crate::api::{ApiClient, ApiError};
use crate::skills::manifest::EntryKind;
use crate::skills::snapshot::PackageSnapshot;
use anyhow::{bail, Result};
use bytes::Bytes;
use std::collections::BTreeSet;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

pub(super) async fn package(
    client: &ApiClient,
    token: &str,
    key: &str,
    snapshot: Arc<PackageSnapshot>,
) -> Result<()> {
    let mut identity = None;
    for attempt in 0..3 {
        match transfer(client, token, key, &snapshot, &mut identity).await {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt < 2
                    && error
                        .downcast_ref::<ApiError>()
                        .is_some_and(retryable_transport) =>
            {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => return Err(error),
        }
    }
    bail!("package upload could not be completed")
}

async fn transfer(
    client: &ApiClient,
    token: &str,
    key: &str,
    snapshot: &Arc<PackageSnapshot>,
    identity: &mut Option<String>,
) -> Result<()> {
    let plan = data(match identity.as_deref() {
        Some(id) => {
            client
                .skill_upload_status(token, id, snapshot.manifest())
                .await?
        }
        None => {
            client
                .begin_skill_upload(token, key, snapshot.manifest())
                .await?
        }
    })?;
    *identity = Some(plan.id.clone());
    match plan.status {
        SkillUploadStatus::Committed => return Ok(()),
        SkillUploadStatus::Expired => {
            return Err(super::remote_result::failure(
                "UPLOAD_EXPIRED",
                "Package upload lease expired; no installation was submitted.",
                Some(plan.id),
            ))
        }
        SkillUploadStatus::Staged => {}
    }
    let mut transferred = BTreeSet::new();
    for entry in &snapshot.manifest().entries {
        if entry.kind != EntryKind::File || !transferred.insert(&entry.sha256) {
            continue;
        }
        let source = Arc::clone(snapshot);
        let selected = entry.clone();
        let content = tokio::task::spawn_blocking(move || -> Result<Bytes> {
            let mut bytes = Vec::new();
            source
                .open_object(&selected.sha256)?
                .take(selected.size.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != selected.size {
                bail!("captured object length changed");
            }
            Ok(Bytes::from(bytes))
        })
        .await??;
        data(
            client
                .put_skill_file(token, &plan.id, entry, content)
                .await?,
        )?;
    }
    data(
        client
            .complete_skill_upload(token, &plan.id, snapshot.manifest())
            .await?,
    )?;
    Ok(())
}
