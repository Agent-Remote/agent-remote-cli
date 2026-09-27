//! Local discovery and complete private snapshots, kept off asynchronous runtime threads.

use crate::api::skill_git::{self, GitRepository};
use crate::api::skill_mutations::SkillInstallItem;
use crate::api::skills::{SkillProvenance, SkillSource};
use crate::skills::discovery::{
    select_candidates, DiscoveryIssue, Selection, SkillCandidate, SourceCatalog,
};
use crate::skills::git_catalog::GitCatalog;
use crate::skills::git_source::{GitReference, GitSource};
use crate::skills::snapshot::{PackageLimits, PackageSnapshot};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub(super) struct Captured {
    pub item: SkillInstallItem,
    pub snapshot: Arc<PackageSnapshot>,
}

pub(super) async fn discover(
    root: PathBuf,
    subpath: Option<String>,
) -> Result<(SourceCatalog, PathBuf)> {
    tokio::task::spawn_blocking(move || {
        let canonical = root.canonicalize()?;
        let (catalog, selected_root) = match subpath {
            Some(path) => (
                SourceCatalog::discover_subpath(&canonical, &path)?,
                canonical.join(path),
            ),
            None => (SourceCatalog::discover(&canonical)?, canonical),
        };
        Ok((catalog, selected_root))
    })
    .await?
}

pub(super) async fn capture(
    catalog: SourceCatalog,
    root: PathBuf,
    selection: Selection,
    interactive: bool,
) -> Result<Vec<Captured>> {
    let selected = choose(
        catalog.candidates(),
        catalog.issues(),
        selection,
        interactive,
    )
    .await?;
    tokio::task::spawn_blocking(move || {
        let mut captured = Vec::new();
        for candidate in selected {
            let snapshot = catalog.capture(&candidate, PackageLimits::default())?;
            let path = if candidate.path.is_empty() {
                root.clone()
            } else {
                root.join(&candidate.path)
            };
            let locator = format!("{:x}", Sha256::digest(path.as_os_str().as_encoded_bytes()));
            captured.push(Captured {
                item: SkillInstallItem {
                    name: candidate.metadata.name,
                    source: SkillSource {
                        kind: "local".to_owned(),
                        locator,
                        subpath: String::new(),
                    },
                    provenance: SkillProvenance {
                        ref_kind: "local".to_owned(),
                        r#ref: String::new(),
                        commit: String::new(),
                    },
                    tree_digest: snapshot.tree_digest().to_owned(),
                },
                snapshot: Arc::new(snapshot),
            });
        }
        Ok(captured)
    })
    .await?
}

async fn choose(
    candidates: &[SkillCandidate],
    issues: &[DiscoveryIssue],
    selection: Selection,
    interactive: bool,
) -> Result<Vec<SkillCandidate>> {
    let mut prompt = String::new();
    for issue in issues {
        prompt.push_str(&format!(
            "Skipped invalid source {}: {}\n",
            super::safe(&issue.path),
            super::safe(&issue.message)
        ));
    }
    if !prompt.is_empty() {
        super::confirmation::write(std::mem::take(&mut prompt)).await?;
    }
    let selected = match select_candidates(candidates, &selection) {
        Err(_)
            if matches!(selection, Selection::Automatic) && candidates.len() > 1 && interactive =>
        {
            for candidate in candidates {
                prompt.push_str(&format!(
                    "{}  {}\n",
                    super::safe(&candidate.metadata.name),
                    super::safe(&candidate.path)
                ));
            }
            prompt.push_str("Select comma-separated skill names, or * for all: ");
            let line = super::confirmation::read_line(std::mem::take(&mut prompt), 8192).await?;
            let selection = if line.trim() == "*" {
                Selection::All
            } else {
                Selection::Names(
                    line.trim()
                        .split(',')
                        .map(|v| v.trim().to_owned())
                        .collect(),
                )
            };
            select_candidates(candidates, &selection)?
        }
        result => result?,
    };
    if selected.len() > 100 {
        bail!("SELECTION_REQUIRED: at most 100 skills can be installed atomically");
    }
    Ok(selected)
}

/// Local roots retain their original identity; Git packages retain repository-relative provenance.
pub(super) enum Acquired {
    Local(SourceCatalog, PathBuf),
    Git {
        catalog: GitCatalog,
        repository: GitRepository,
        prefix: String,
    },
}
impl Acquired {
    pub(super) fn candidates(&self) -> &[SkillCandidate] {
        match self {
            Self::Local(catalog, _) => catalog.candidates(),
            Self::Git { catalog, .. } => catalog.candidates(),
        }
    }
    pub(super) fn issues(&self) -> &[DiscoveryIssue] {
        match self {
            Self::Local(catalog, _) => catalog.issues(),
            Self::Git { catalog, .. } => catalog.issues(),
        }
    }
    pub(super) async fn capture(
        self,
        selection: Selection,
        interactive: bool,
    ) -> Result<Vec<Captured>> {
        match self {
            Self::Local(catalog, root) => capture(catalog, root, selection, interactive).await,
            Self::Git {
                catalog,
                repository,
                prefix,
            } => {
                let candidates = catalog.candidates().to_vec();
                let issues = catalog.issues().to_vec();
                let selected = choose(&candidates, &issues, selection, interactive).await?;
                let mut captured = Vec::new();
                for candidate in selected {
                    let snapshot = bounded_git(catalog.capture(&candidate)).await?;
                    let subpath = [prefix.as_str(), candidate.path.as_str()]
                        .into_iter()
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>()
                        .join("/");
                    captured.push(Captured {
                        item: SkillInstallItem {
                            name: candidate.metadata.name,
                            source: SkillSource {
                                kind: "git".into(),
                                locator: repository.source.url.clone(),
                                subpath,
                            },
                            provenance: SkillProvenance {
                                ref_kind: repository.reference.kind.clone(),
                                r#ref: repository.reference.name.clone(),
                                commit: repository.reference.commit.clone(),
                            },
                            tree_digest: snapshot.tree_digest().into(),
                        },
                        snapshot: Arc::new(snapshot),
                    });
                }
                Ok(captured)
            }
        }
    }
}

pub(super) async fn acquire(
    root: PathBuf,
    git: Option<GitSource>,
    reference: GitReference,
    subpath: Option<String>,
) -> Result<Acquired> {
    let Some(source) = git else {
        let (catalog, root) = discover(root, subpath).await?;
        return Ok(Acquired::Local(catalog, root));
    };
    bounded_git(acquire_git(source, reference, subpath)).await
}

async fn acquire_git(
    source: GitSource,
    reference: GitReference,
    subpath: Option<String>,
) -> Result<Acquired> {
    let repository = skill_git::acquire(source, reference).await?;
    let prefix = subpath.unwrap_or_default();
    let root_name = if prefix.is_empty() {
        repository
            .source
            .url
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .strip_suffix(".git")
            .unwrap_or_else(|| repository.source.url.rsplit('/').next().unwrap_or(""))
    } else {
        prefix.rsplit('/').next().unwrap_or("")
    };
    let catalog = GitCatalog::discover(
        repository.directory.path(),
        &repository.reference.commit,
        (!prefix.is_empty()).then_some(prefix.as_str()),
        root_name,
    )
    .await?;
    Ok(Acquired::Git {
        catalog,
        repository,
        prefix,
    })
}

async fn bounded_git<T>(work: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(240), work) => {
            result.map_err(|_| anyhow::anyhow!("SOURCE_TIMEOUT: Git source acquisition exceeded 240 seconds"))?
        }
        result = crate::skill_commands::interruption::cancelled() => {
            result?;
            bail!("SOURCE_INTERRUPTED: Git acquisition was interrupted");
        }
    }
}
