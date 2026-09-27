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
mod tests {
    use super::*;
    #[test]
    fn source_normalizes_github_but_rejects_credentials_and_webpage_paths() {
        assert_eq!(
            GitSource::parse("Owner/Repo").unwrap().unwrap().url,
            "https://github.com/owner/repo.git"
        );
        assert_eq!(
            GitSource::parse("https://github.com/Owner/Repo.git/")
                .unwrap()
                .unwrap()
                .url,
            "https://github.com/owner/repo.git"
        );
        for source in [
            "https://user:secret@example.test/repo.git",
            "https://@example.test/repo",
            "https://example.test/repo?token=secret",
            "https://example.test/repo#main",
            "http://example.test/repo",
            "ssh://git@example.test/repo",
            "https://github.com/a/b/tree/main",
            "https://github.com/a/b/blob/main/SKILL.md",
        ] {
            assert!(GitSource::parse(source).is_err(), "{source}");
        }
        for source in ["./owner/repo", "/tmp/repo", "../repo", "repo", "C:\\repo"] {
            assert!(GitSource::parse(source).unwrap().is_none());
        }
    }
    #[test]
    fn refs_are_literal_and_namespace_selection_is_explicit() {
        assert_eq!(
            GitReference::parse(None).unwrap(),
            GitReference::DefaultBranch
        );
        assert_eq!(
            GitReference::parse(Some("refs/heads/release/one")).unwrap(),
            GitReference::Branch("release/one".into())
        );
        assert_eq!(
            GitReference::parse(Some("refs/tags/v1")).unwrap(),
            GitReference::Tag("v1".into())
        );
        assert!(matches!(
            GitReference::parse(Some(&"a".repeat(40))).unwrap(),
            GitReference::Commit(_)
        ));
        for value in [
            "-main",
            "HEAD~1",
            "v1^{}",
            "a:b",
            "a b",
            "a\\b",
            "a//b",
            ".hidden",
            "a.lock",
            "a/../b",
            "@{1}",
            "refs/pull/1/head",
        ] {
            assert!(GitReference::parse(Some(value)).is_err(), "{value}");
        }
    }
}
