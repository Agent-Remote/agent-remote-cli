// Tests for src/identifiers.rs.

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
