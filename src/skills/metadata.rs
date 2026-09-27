//! Bounded, non-executing Claude frontmatter interpretation for source selection.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use yaml_rust2::scanner::{Scanner, TokenType};
use yaml_rust2::{Yaml, YamlLoader};

pub(super) const DOCUMENT_PREFIX_BYTES: u64 = 65_536 + 4_096;

/// Display metadata only; packaging always retains the original SKILL.md bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SkillMetadata {
    pub name: String,
    pub description: String,
}

pub(super) fn parse(bytes: &[u8], fallback_name: &str) -> Result<SkillMetadata> {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) if error.error_len().is_none() => {
            std::str::from_utf8(&bytes[..error.valid_up_to()])?
        }
        Err(_) => bail!("INVALID_SKILL_FORMAT: SKILL.md must be UTF-8 text"),
    };
    if text.contains('\0') {
        bail!("INVALID_SKILL_FORMAT: SKILL.md contains NUL bytes");
    }
    let document = text.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    let mut body = document.as_str();
    let mut fields = None;
    if let Some(rest) = document.strip_prefix("---\n") {
        let mut offset = 0;
        let closing = rest
            .split_inclusive('\n')
            .find_map(|line| {
                let start = offset;
                offset += line.len();
                (line.trim_end_matches('\n') == "---").then_some((start, offset))
            })
            .context("INVALID_SKILL_FORMAT: frontmatter is incomplete or too large")?;
        if closing.0 > 65_536 {
            bail!("INVALID_SKILL_FORMAT: frontmatter exceeds 64 KiB");
        }
        fields = Some(parse_mapping(&rest[..closing.0])?);
        body = &rest[closing.1..];
    }
    let field = |key: &str| {
        fields
            .as_ref()
            .and_then(|map| map.get(&Yaml::String(key.into())))
    };
    let name = match field("name") {
        None => fallback_name,
        Some(value) => value
            .as_str()
            .context("INVALID_SKILL_FORMAT: name must be text")?,
    };
    validate_name(name)?;
    let description = match field("description") {
        None => body
            .trim()
            .split('\n')
            .next()
            .unwrap_or("")
            .chars()
            .take(1024)
            .collect(),
        Some(value) => value
            .as_str()
            .context("INVALID_SKILL_FORMAT: description must be text")?
            .to_owned(),
    };
    if description.chars().count() > 1024 {
        bail!("INVALID_SKILL_FORMAT: description exceeds 1024 characters");
    }
    Ok(SkillMetadata {
        name: name.to_owned(),
        description,
    })
}

fn parse_mapping(header: &str) -> Result<yaml_rust2::yaml::Hash> {
    let mut scanner = Scanner::new(header.chars());
    let mut depth = 0usize;
    for token in scanner.by_ref() {
        match token.1 {
            TokenType::Alias(_) | TokenType::Anchor(_) => {
                bail!("INVALID_SKILL_FORMAT: YAML aliases and anchors are unsupported")
            }
            TokenType::Tag(ref handle, ref suffix)
                if handle != "!!"
                    || !["str", "bool", "int", "float", "null", "seq", "map"]
                        .contains(&suffix.as_str()) =>
            {
                bail!("INVALID_SKILL_FORMAT: unsupported YAML tag");
            }
            TokenType::FlowSequenceStart
            | TokenType::FlowMappingStart
            | TokenType::BlockSequenceStart
            | TokenType::BlockMappingStart => {
                depth += 1;
                if depth > 64 {
                    bail!("INVALID_SKILL_FORMAT: excessive YAML nesting");
                }
            }
            TokenType::FlowSequenceEnd | TokenType::FlowMappingEnd | TokenType::BlockEnd => {
                depth = depth.saturating_sub(1)
            }
            _ => {}
        }
    }
    if scanner.get_error().is_some() {
        bail!("INVALID_SKILL_FORMAT: malformed YAML");
    }
    let documents =
        YamlLoader::load_from_str(header).context("INVALID_SKILL_FORMAT: malformed YAML")?;
    if documents.is_empty() || documents == [Yaml::Null] {
        return Ok(Default::default());
    }
    if documents.len() != 1 {
        bail!("INVALID_SKILL_FORMAT: expected one frontmatter mapping");
    }
    let map = documents[0]
        .as_hash()
        .context("INVALID_SKILL_FORMAT: frontmatter must be a mapping")?;
    if map.keys().any(|key| key.as_str().is_none()) {
        bail!("INVALID_SKILL_FORMAT: frontmatter keys must be text");
    }
    Ok(map.clone())
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        bail!("INVALID_SKILL_FORMAT: name must be 1–64 lowercase letters, digits or hyphens, starting with a letter or digit");
    }
    if ["ego-browser", "agent-remote-device"].contains(&name) {
        bail!("INVALID_SKILL_FORMAT: skill name is reserved");
    }
    Ok(())
}
