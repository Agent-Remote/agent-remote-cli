// Tests for src/skills/git_source.rs.

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
