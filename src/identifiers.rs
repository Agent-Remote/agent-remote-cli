use anyhow::{bail, Result};

pub fn short_id(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character != '-')
        .take(12)
        .collect()
}

pub fn resolve_id<'a>(
    reference: &str,
    kind: &str,
    identifiers: impl Iterator<Item = &'a str>,
) -> Result<String> {
    match match_id(reference, kind, identifiers)? {
        IdMatch::Unique(identifier) => Ok(identifier.to_owned()),
        IdMatch::NotFound => bail!("no {kind} matches ID prefix {reference}"),
        IdMatch::Ambiguous => {
            bail!("{kind} ID prefix {reference} is ambiguous; use more characters")
        }
    }
}

pub enum IdMatch<'a> {
    Unique(&'a str),
    NotFound,
    Ambiguous,
}

pub fn match_id<'a>(
    reference: &str,
    kind: &str,
    identifiers: impl Iterator<Item = &'a str>,
) -> Result<IdMatch<'a>> {
    let normalized = normalize_id(reference, kind)?;
    if normalized.len() < 4 {
        bail!("{kind} ID prefix must contain at least 4 hexadecimal characters");
    }
    let matches: Vec<_> = identifiers
        .filter(|identifier| {
            normalize_id(identifier, kind)
                .is_ok_and(|identifier| identifier.starts_with(&normalized))
        })
        .collect();
    match matches.as_slice() {
        [identifier] => Ok(IdMatch::Unique(identifier)),
        [] => Ok(IdMatch::NotFound),
        _ => Ok(IdMatch::Ambiguous),
    }
}

fn normalize_id(value: &str, kind: &str) -> Result<String> {
    let normalized = value.replace('-', "").to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 32
        || !normalized
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!("invalid {kind} ID: {value}");
    }
    Ok(normalized)
}

#[cfg(test)]
#[path = "../tests/unit/src/identifiers.rs"]
mod tests;
