//! HTTPS-only Git acquisition; remote configuration and credentials never become package content.

use crate::auth::git::{self, GitCredential};
use crate::skills::git_process;
use crate::skills::git_refs::{self, ResolvedReference};
use crate::skills::git_source::{GitReference, GitSource};
use anyhow::{bail, Context, Result};
use std::time::Duration;
use tempfile::TempDir;

/// Owns the private bare object store until all selected packages have been captured.
pub struct GitRepository {
    pub directory: TempDir,
    pub source: GitSource,
    pub reference: ResolvedReference,
}

pub async fn acquire(source: GitSource, reference: GitReference) -> Result<GitRepository> {
    let directory = tempfile::Builder::new()
        .prefix("agent-remote-git-")
        .tempdir()?;
    let credential = git::load(&source, directory.path()).await?;
    let resolved = if matches!(reference, GitReference::Commit(_)) {
        git_refs::resolve(&reference, b"")?
    } else {
        let mut command = remote_command(&directory, &source, credential.as_ref());
        command.args(["ls-remote", "--symref", "--", &source.url]);
        match &reference {
            GitReference::DefaultBranch => {
                command.arg("HEAD");
            }
            GitReference::Named(name) => {
                command.args([
                    format!("refs/heads/{name}"),
                    format!("refs/tags/{name}"),
                    format!("refs/tags/{name}^{{}}"),
                ]);
            }
            GitReference::Branch(name) => {
                command.arg(format!("refs/heads/{name}"));
            }
            GitReference::Tag(name) => {
                command.args([
                    format!("refs/tags/{name}"),
                    format!("refs/tags/{name}^{{}}"),
                ]);
            }
            GitReference::Commit(_) => unreachable!(),
        }
        let output = git_process::run(command, b"", 1024 * 1024, Duration::from_secs(60), None).await?
            .context("GIT_FETCH_FAILED: repository unavailable; check URL, ref and native Git credentials")?;
        git_refs::resolve(&reference, &output)?
    };
    let mut init = git_process::command(directory.path(), false);
    init.args([
        "init",
        "--bare",
        "--template=",
        if resolved.commit.len() == 64 {
            "--object-format=sha256"
        } else {
            "--object-format=sha1"
        },
        ".",
    ]);
    git_process::run(init, b"", 64 * 1024, Duration::from_secs(30), None)
        .await?
        .context("GIT_UNAVAILABLE: native Git cannot initialize the required object format")?;
    let mut fetch = remote_command(&directory, &source, credential.as_ref());
    fetch.args([
        "fetch",
        "--quiet",
        "--depth=1",
        "--no-tags",
        "--no-recurse-submodules",
        "--no-write-fetch-head",
        "--",
        &source.url,
        &format!("{}:refs/agent-remote/source", resolved.commit),
    ]);
    git_process::run(
        fetch,
        b"",
        64 * 1024,
        Duration::from_secs(120),
        Some(directory.path()),
    )
    .await?
    .context(
        "GIT_FETCH_FAILED: exact commit unavailable; check native Git credentials and retry",
    )?;
    let mut verify = git_process::command(directory.path(), false);
    verify.args(["cat-file", "-t", &resolved.commit]);
    let kind = git_process::run(verify, b"", 64, Duration::from_secs(30), None)
        .await?
        .context("SOURCE_INVALID: fetched object is unavailable")?;
    if kind != b"commit\n" {
        bail!("INVALID_REF: reference must resolve to a commit");
    }
    Ok(GitRepository {
        directory,
        source,
        reference: resolved,
    })
}

fn remote_command(
    directory: &TempDir,
    source: &GitSource,
    credential: Option<&GitCredential>,
) -> tokio::process::Command {
    let mut command = git_process::command(directory.path(), false);
    if let Some(credential) = credential {
        credential.apply(&mut command, source);
    }
    command
}
