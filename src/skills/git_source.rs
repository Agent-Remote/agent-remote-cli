//! Credential-free repository identities and strict branch/tag/commit selection.

use anyhow::{bail, Result};
use reqwest::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSource {
    pub url: String,
}

impl GitSource {
    /// Plain owner/repo means GitHub; prefix a relative local path with ./ to disambiguate it.
    pub fn parse(value: &str) -> Result<Option<Self>> {
        if value.starts_with('.')
            || value.starts_with('/')
            || value.starts_with('~')
            || value.as_bytes().get(1) == Some(&b':') && !value.contains("://")
        {
            return Ok(None);
        }
        let locator = if value.contains("://") {
            value.to_owned()
        } else {
            let parts: Vec<_> = value.split('/').collect();
            if parts.len() != 2
                || parts.iter().any(|part| {
                    part.is_empty()
                        || !part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                })
            {
                return Ok(None);
            }
            format!("https://github.com/{value}")
        };
        if locator.len() > 2048
            || locator.chars().any(|c| c.is_whitespace() || c.is_control())
            || locator.contains('\\')
        {
            bail!("INVALID_SOURCE: expected an HTTPS Git repository without credentials");
        }
        let mut url = Url::parse(&locator)
            .map_err(|_| anyhow::anyhow!("INVALID_SOURCE: malformed repository URL"))?;
        let authority = locator
            .split_once("://")
            .map(|(_, rest)| rest.split('/').next().unwrap_or(""))
            .unwrap_or("");
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || authority.contains('@')
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path().trim_matches('/').is_empty()
        {
            bail!("INVALID_SOURCE: expected an HTTPS Git repository without credentials");
        }
        if url.host_str() == Some("github.com") {
            let path = url.path().trim_matches('/');
            let path = path.strip_suffix(".git").unwrap_or(path);
            let parts: Vec<_> = path.split('/').collect();
            if parts.len() != 2
                || parts.iter().any(|part| {
                    part.is_empty()
                        || !part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                })
            {
                bail!("INVALID_SOURCE: use a GitHub repository URL and select directories with --path");
            }
            url.set_path(&format!("{}.git", path.to_ascii_lowercase()));
        }
        Ok(Some(Self {
            url: url.to_string(),
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitReference {
    DefaultBranch,
    Named(String),
    Branch(String),
    Tag(String),
    Commit(String),
}

impl GitReference {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        let Some(value) = value else {
            return Ok(Self::DefaultBranch);
        };
        if is_object_id(value) {
            return Ok(Self::Commit(value.to_owned()));
        }
        let (kind, name) = if let Some(name) = value.strip_prefix("refs/heads/") {
            ("branch", name)
        } else if let Some(name) = value.strip_prefix("refs/tags/") {
            ("tag", name)
        } else if value.starts_with("refs/") {
            bail!("INVALID_REF: select a branch, tag or full commit");
        } else {
            ("named", value)
        };
        validate_ref_name(name)?;
        Ok(match kind {
            "branch" => Self::Branch(name.to_owned()),
            "tag" => Self::Tag(name.to_owned()),
            _ => Self::Named(name.to_owned()),
        })
    }
}

pub fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn validate_ref_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value == "@"
        || value.starts_with('-')
        || value.ends_with('.')
        || value.contains("..")
        || value.contains("@{")
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "~^:?*[\\".contains(c))
        || value
            .split('/')
            .any(|part| part.is_empty() || part.starts_with('.') || part.ends_with(".lock"))
    {
        bail!("INVALID_REF: select a literal branch/tag name or full commit");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/src/skills/git_source.rs"]
mod tests;
