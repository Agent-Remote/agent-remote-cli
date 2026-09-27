//! Source policy, exact library identity and immutable update observations.

use super::{
    install_source::{self, Captured},
    remote_result,
};
use crate::api::skills::{SkillDetails, SkillInstallation, SkillRevision};
use crate::api::ApiClient;
use crate::skills::discovery::Selection;
use crate::skills::git_source::{GitReference, GitSource};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub(super) async fn details(
    client: &ApiClient,
    token: &str,
    identifier: &str,
) -> Result<SkillInstallation> {
    let detail = remote_result::data(client.skill_info(token, identifier, None, None).await?)?;
    let matches = match uuid::Uuid::parse_str(identifier) {
        Ok(id) => uuid::Uuid::parse_str(detail.id()).ok() == Some(id),
        Err(_) => detail.name() == identifier,
    };
    if !matches {
        bail!("INVALID_SKILL_RESPONSE: details do not match the requested skill");
    }
    let SkillDetails::Library(item) = detail else {
        bail!("LOCAL_SKILL_COMMAND_UNSUPPORTED: account-local sources use state history, not package updates");
    };
    validate(&item)?;
    Ok(item)
}

pub(super) fn validate(item: &SkillInstallation) -> Result<()> {
    uuid::Uuid::parse_str(&item.id).context("INVALID_SKILL_RESPONSE: invalid skill ID")?;
    if item.removed {
        bail!("SKILL_REMOVED: this installation has been removed");
    }
    current(item)?;
    if !item.source.subpath.is_empty() {
        crate::skills::manifest::validate_path(&item.source.subpath)?;
    }
    match item.source.kind.as_str() {
        "local"
            if item.source.locator.len() == 64
                && item
                    .source
                    .locator
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) => {}
        "git" => {
            if !item.source.locator.contains("://") {
                bail!("INVALID_SKILL_RESPONSE: repository URL is missing its HTTPS scheme");
            }
            GitSource::parse(&item.source.locator)?
                .context("INVALID_SKILL_RESPONSE: expected HTTPS repository")?;
            if !item.source.subpath.is_empty() {
                crate::skills::manifest::validate_path(&item.source.subpath)?;
            }
            match item
                .tracking
                .get("ref_kind")
                .and_then(|value| value.as_str())
            {
                Some("branch" | "tag" | "commit" | "fixed") => {}
                _ => bail!("INVALID_SKILL_RESPONSE: unknown upstream tracking policy"),
            }
        }
        _ => bail!("INVALID_SKILL_RESPONSE: invalid source identity"),
    }
    Ok(())
}

pub(super) fn current(item: &SkillInstallation) -> Result<&SkillRevision> {
    let matches = item
        .revisions
        .iter()
        .filter(|revision| revision.id == item.default_revision_id)
        .collect::<Vec<_>>();
    let [revision] = matches.as_slice() else {
        bail!("INVALID_SKILL_RESPONSE: current revision is missing or duplicated");
    };
    uuid::Uuid::parse_str(&revision.id).context("INVALID_SKILL_RESPONSE: invalid revision ID")?;
    if revision.content_digest.len() != 64
        || !revision
            .content_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("INVALID_SKILL_RESPONSE: invalid content digest");
    }
    Ok(revision)
}

pub(super) fn skipped(item: &SkillInstallation) -> Option<&'static str> {
    if item.source.kind == "local" {
        Some("local_source")
    } else if item
        .tracking
        .get("ref_kind")
        .and_then(|value| value.as_str())
        != Some("branch")
    {
        Some("pinned")
    } else {
        None
    }
}

pub(super) async fn observe(
    item: &SkillInstallation,
    reference: Option<&str>,
    from: Option<&Path>,
) -> Result<Captured> {
    validate(item)?;
    let catalog = if item.source.kind == "local" {
        if reference.is_some() {
            bail!("INVALID_ARGUMENT: local source updates use --from, not --ref");
        }
        let from = from.context(
            "LOCAL_SOURCE_REQUIRED: provide --from with a complete local skill directory",
        )?;
        install_source::acquire(from.to_owned(), None, GitReference::DefaultBranch, None).await?
    } else {
        if from.is_some() {
            bail!("INVALID_ARGUMENT: Git updates cannot replace the repository with --from");
        }
        let reference = match reference {
            Some(value) => GitReference::parse(Some(value))?,
            None => {
                if skipped(item).is_some() {
                    bail!("SOURCE_PINNED: use an explicit --ref to switch fixed tracking");
                }
                let name = item
                    .tracking
                    .get("ref")
                    .and_then(|value| value.as_str())
                    .context("INVALID_SKILL_RESPONSE: tracked branch is missing")?;
                GitReference::parse(Some(&format!("refs/heads/{name}")))?
            }
        };
        let source = GitSource::parse(&item.source.locator)?
            .context("INVALID_SKILL_RESPONSE: invalid Git source")?;
        install_source::acquire(
            PathBuf::new(),
            Some(source),
            reference,
            (!item.source.subpath.is_empty()).then(|| item.source.subpath.clone()),
        )
        .await
        .map_err(|error| {
            if error
                .downcast_ref::<crate::skills::git_objects::MissingGitDirectory>()
                .is_some()
            {
                layout_error(item, serde_json::Value::Null, serde_json::json!([]))
            } else {
                error
            }
        })?
    };
    // The installed root itself must remain a skill. Never follow a renamed/moved nested candidate.
    let candidates = catalog.candidates();
    if candidates.len() != 1
        || !candidates[0].path.is_empty()
        || candidates[0].metadata.name != item.name
    {
        return Err(layout_error(
            item,
            serde_json::to_value(candidates)?,
            serde_json::to_value(catalog.issues())?,
        ));
    }
    let mut packages = catalog.capture(Selection::Automatic, false).await?;
    let mut captured = packages
        .pop()
        .context("INCOMPLETE_SOURCE: source produced no package")?;
    if item.source.kind == "local" {
        // --from is explicit on every device; never turn a host path into a remote source locator.
        captured.item.source.clone_from(&item.source);
    }
    if captured.item.source.subpath != item.source.subpath {
        bail!("SOURCE_LAYOUT_CHANGED: source subpath changed");
    }
    if captured.item.provenance.ref_kind == "tag" {
        let observed = &captured.item.provenance;
        if item.revisions.iter().any(|revision| {
            revision.provenance.ref_kind == "tag"
                && revision.provenance.r#ref == observed.r#ref
                && revision.provenance.commit != observed.commit
        }) {
            bail!("SOURCE_DRIFT: a previously recorded tag moved to another commit");
        }
    }
    Ok(captured)
}

fn layout_error(
    item: &SkillInstallation,
    actual: serde_json::Value,
    issues: serde_json::Value,
) -> anyhow::Error {
    let mut error = remote_result::failure("SOURCE_LAYOUT_CHANGED", "The installed name or source root no longer matches the source; update does not follow moves.", Some(item.id.clone()));
    if let Some(rejected) = error.downcast_mut::<remote_result::Rejected>() {
        rejected.0.errors[0].details = std::collections::BTreeMap::from([
            (
                "expected".into(),
                serde_json::json!({"name":item.name,"subpath":item.source.subpath}),
            ),
            ("actual".into(), actual),
            ("issues".into(), issues),
        ]);
    }
    error
}
