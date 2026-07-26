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
        [identifier] => Ok((*identifier).to_string()),
        [] => bail!("no {kind} matches ID prefix {reference}"),
        _ => bail!("{kind} ID prefix {reference} is ambiguous; use more characters"),
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
mod tests {
    use super::{resolve_id, short_id};

    #[test]
    fn short_ids_resolve_unique_normalized_prefixes() {
        let first = "b68873d4-8e07-44cd-a5d3-f5d759a0f9c2";
        let second = "92d04887-fe38-4993-b651-e492cdd9ab0c";
        assert_eq!(short_id(first), "b68873d48e07");
        assert_eq!(
            resolve_id("b68873d48e07", "session", [first, second].into_iter()).unwrap(),
            first
        );
    }

    #[test]
    fn ambiguous_prefixes_are_rejected() {
        let error = resolve_id(
            "b688",
            "session",
            [
                "b68873d4-8e07-44cd-a5d3-f5d759a0f9c2",
                "b688ffff-1111-2222-3333-444444444444",
            ]
            .into_iter(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("ambiguous"));
    }
}
