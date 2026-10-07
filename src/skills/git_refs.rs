//! Resolve literal advertised refs without revision expressions or branch/tag guessing.

use super::git_source::{is_object_id, validate_ref_name, GitReference};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedReference {
    pub kind: String,
    pub name: String,
    pub commit: String,
}

pub fn resolve(reference: &GitReference, output: &[u8]) -> Result<ResolvedReference> {
    if let GitReference::Commit(commit) = reference {
        return Ok(ResolvedReference {
            kind: "commit".into(),
            name: commit.clone(),
            commit: commit.clone(),
        });
    }
    let mut refs = BTreeMap::new();
    let mut default = None;
    for line in std::str::from_utf8(output)
        .context("SOURCE_INVALID: Git refs are not UTF-8")?
        .lines()
    {
        let (value, name) = line
            .split_once('\t')
            .context("SOURCE_INVALID: malformed Git advertisement")?;
        if let Some(target) = value.strip_prefix("ref: ") {
            if name != "HEAD" || default.replace(target).is_some() {
                bail!("SOURCE_INVALID: invalid default branch advertisement");
            }
        } else if !is_object_id(value)
            || value.bytes().all(|b| b == b'0')
            || refs.insert(name, value).is_some()
        {
            bail!("SOURCE_INVALID: invalid Git object advertisement");
        }
    }
    let (kind, name) = match reference {
        GitReference::DefaultBranch => {
            let name = default
                .and_then(|value| value.strip_prefix("refs/heads/"))
                .context("REF_REQUIRED: remote HEAD has no default branch; provide --ref")?;
            validate_ref_name(name)?;
            let commit = refs
                .get("HEAD")
                .context("REF_NOT_FOUND: remote default branch has no commit")?;
            return Ok(ResolvedReference {
                kind: "branch".into(),
                name: name.into(),
                commit: (*commit).into(),
            });
        }
        GitReference::Branch(name) => ("branch", name),
        GitReference::Tag(name) => ("tag", name),
        GitReference::Named(name) => {
            let branch = refs.contains_key(format!("refs/heads/{name}").as_str());
            let tag = refs.contains_key(format!("refs/tags/{name}").as_str());
            match (branch, tag) {
                (true, true) => {
                    bail!("REF_AMBIGUOUS: both branch and tag exist; use refs/heads/ or refs/tags/")
                }
                (true, false) => ("branch", name),
                (false, true) => ("tag", name),
                _ => bail!("REF_NOT_FOUND: branch or tag was not advertised"),
            }
        }
        GitReference::Commit(_) => unreachable!(),
    };
    let key = format!(
        "refs/{}/{name}",
        if kind == "branch" { "heads" } else { "tags" }
    );
    let object = refs
        .get(key.as_str())
        .context("REF_NOT_FOUND: requested ref was not advertised")?;
    let commit = if kind == "tag" {
        refs.get(format!("{key}^{{}}").as_str()).unwrap_or(object)
    } else {
        object
    };
    Ok(ResolvedReference {
        kind: kind.into(),
        name: name.clone(),
        commit: (*commit).into(),
    })
}

#[cfg(test)]
#[path = "../../tests/unit/src/skills/git_refs.rs"]
mod tests;
