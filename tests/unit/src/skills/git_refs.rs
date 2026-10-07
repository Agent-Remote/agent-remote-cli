// Tests for src/skills/git_refs.rs.

use super::*;
#[test]
fn ambiguity_and_annotated_tags_are_explicit() {
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    let refs = format!("{a}\trefs/heads/v1\n{a}\trefs/tags/v1\n{b}\trefs/tags/v1^{{}}\n");
    assert!(resolve(&GitReference::Named("v1".into()), refs.as_bytes()).is_err());
    let tag = resolve(&GitReference::Tag("v1".into()), refs.as_bytes()).unwrap();
    assert_eq!(tag.commit, b);
    assert_eq!(tag.kind, "tag");
    let head = format!("ref: refs/heads/main\tHEAD\n{a}\tHEAD\n");
    assert_eq!(
        resolve(&GitReference::DefaultBranch, head.as_bytes())
            .unwrap()
            .name,
        "main"
    );
    assert!(resolve(
        &GitReference::DefaultBranch,
        format!("{a}\tHEAD\n").as_bytes()
    )
    .is_err());
}
