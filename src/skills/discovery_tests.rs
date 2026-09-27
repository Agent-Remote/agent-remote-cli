use super::*;
use std::fs;
use tempfile::TempDir;

fn write_skill(root: &TempDir, path: &str, text: &str) {
    let directory = root.path().join(path);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("SKILL.md"), text).unwrap();
}

#[test]
fn discovery_stops_at_skill_roots_and_skips_dependency_caches() {
    let root = tempfile::tempdir().unwrap();
    for path in [
        "skills/one",
        "skills/one/references/nested",
        "node_modules/hidden",
        ".git/hidden",
        "venv/hidden",
    ] {
        write_skill(&root, path, "Instructions");
    }
    write_skill(
        &root,
        "skills/two",
        "---\nname: declared-name\ndescription: |\n  One line\n  Another line\n---\nInstructions",
    );
    let catalog = SourceCatalog::discover(root.path()).unwrap();
    assert!(catalog.issues().is_empty());
    assert_eq!(catalog.candidates().len(), 2);
    assert_eq!(catalog.candidates()[0].metadata.name, "one");
    assert_eq!(catalog.candidates()[1].metadata.name, "declared-name");
    assert_eq!(
        catalog.candidates()[1].metadata.description,
        "One line\nAnother line\n"
    );
    assert!(catalog
        .select(&Selection::Automatic)
        .unwrap_err()
        .to_string()
        .contains("SELECTION_REQUIRED"));
    assert_eq!(catalog.select(&Selection::All).unwrap().len(), 2);
    let selected = catalog
        .select(&Selection::Names(vec!["declared-name".into()]))
        .unwrap();
    let package = catalog
        .capture(&selected[0], PackageLimits::default())
        .unwrap();
    assert_eq!(package.manifest().entries[0].path, "SKILL.md");
}

#[test]
fn duplicate_names_need_path_disambiguation_and_do_not_partially_select() {
    let root = tempfile::tempdir().unwrap();
    for path in ["one", "two"] {
        write_skill(&root, path, "---\nname: same\n---\nBody");
    }
    let catalog = SourceCatalog::discover(root.path()).unwrap();
    for selection in [
        Selection::All,
        Selection::Names(vec!["same".into()]),
        Selection::Names(vec!["same".into(), "missing".into()]),
    ] {
        assert!(catalog.select(&selection).is_err());
    }
    let narrowed = SourceCatalog::discover(&root.path().join("one")).unwrap();
    assert_eq!(
        narrowed.select(&Selection::Automatic).unwrap()[0]
            .metadata
            .name,
        "same"
    );
}

#[test]
fn missing_or_repeated_explicit_selection_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    write_skill(&root, "one", "Body");
    let catalog = SourceCatalog::discover(root.path()).unwrap();
    for names in [
        vec![],
        vec!["missing".into()],
        vec!["one".into(), "one".into()],
        vec!["one".into(), "missing".into()],
    ] {
        assert!(catalog.select(&Selection::Names(names)).is_err());
    }
}

#[test]
fn invalid_metadata_is_reported_without_discovering_nested_assets() {
    let root = tempfile::tempdir().unwrap();
    for (path, text) in [
        ("one", "---\nname: ../bad\n---\nBody"),
        ("two", "---\nname: ego-browser\n---\nBody"),
        (
            "three",
            "---\ndescription: &text hello\nname: *text\n---\nBody",
        ),
        ("four", "---\n[not, a, mapping]\n---\nBody"),
        ("five", "---\ndescription: 42\n---\nBody"),
        ("six", "---\nname: incomplete"),
    ] {
        write_skill(&root, path, text);
    }
    write_skill(&root, "one/references/hidden", "Body");
    let catalog = SourceCatalog::discover(root.path()).unwrap();
    assert_eq!(catalog.issues().len(), 6);
    assert!(catalog.candidates().is_empty());
    assert!(catalog.select(&Selection::All).is_err());
}

#[test]
fn optional_frontmatter_eof_delimiter_bom_and_unicode_descriptions_are_supported() {
    for text in [
        "# Instructions\nBody",
        "---\n---\n# Instructions",
        "---\nname: valid\n---",
        "\u{feff}---\r\nname: valid\r\ndescription: 中文\r\n---\r\nBody",
    ] {
        let metadata = metadata::parse(text.as_bytes(), "valid").unwrap();
        assert_eq!(metadata.name, "valid");
    }
    assert_eq!(
        metadata::parse(b"Instructions", "valid")
            .unwrap()
            .description,
        "Instructions"
    );
}

#[test]
fn metadata_size_nesting_and_non_text_are_bounded() {
    for text in [
        format!("---\ndescription: {}\n---\n", "x".repeat(1025)),
        format!("---\n#{}\n---\n", "x".repeat(65_536)),
        format!("---\nextra: {}0{}\n---\n", "[".repeat(100), "]".repeat(100)),
        "---\nname: !program execute\n---\n".to_owned(),
    ] {
        assert!(metadata::parse(text.as_bytes(), "valid").is_err());
    }
    assert!(metadata::parse(b"bad\0text", "valid").is_err());
    assert!(metadata::parse(b"bad\xfftext", "valid").is_err());
}

#[test]
fn changed_names_and_forged_candidates_cannot_be_captured() {
    let root = tempfile::tempdir().unwrap();
    write_skill(&root, "one", "---\nname: original\n---\nBody");
    let catalog = SourceCatalog::discover(root.path()).unwrap();
    let mut candidate = catalog.select(&Selection::Automatic).unwrap().remove(0);
    write_skill(&root, "one", "---\nname: changed\n---\nBody");
    assert!(catalog
        .capture(&candidate, PackageLimits::default())
        .unwrap_err()
        .to_string()
        .contains("SOURCE_LAYOUT_CHANGED"));
    candidate.path = "../other".into();
    assert!(catalog
        .capture(&candidate, PackageLimits::default())
        .is_err());
}

#[cfg(unix)]
#[test]
fn internal_skill_document_links_work_but_external_links_do_not() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("one/docs")).unwrap();
    fs::write(
        root.path().join("one/docs/instructions"),
        "---\nname: valid\n---\nBody",
    )
    .unwrap();
    symlink("docs/instructions", root.path().join("one/SKILL.md")).unwrap();
    fs::create_dir(root.path().join("bad")).unwrap();
    symlink("/etc/passwd", root.path().join("bad/SKILL.md")).unwrap();
    let catalog = SourceCatalog::discover(root.path()).unwrap();
    assert_eq!(catalog.issues().len(), 1);
    let selected = catalog.select(&Selection::Automatic).unwrap();
    let package = catalog
        .capture(&selected[0], PackageLimits::default())
        .unwrap();
    assert_eq!(
        package.manifest().resolve("SKILL.md").unwrap().path,
        "docs/instructions"
    );
}

#[test]
fn explicit_subpath_discovers_inside_the_original_source() {
    let root = tempfile::tempdir().unwrap();
    write_skill(&root, "skills/nested", "Instructions");
    let catalog = SourceCatalog::discover_subpath(root.path(), "skills/nested").unwrap();
    let selected = catalog.select(&Selection::Automatic).unwrap();
    assert_eq!(selected[0].path, "");
    assert_eq!(selected[0].metadata.name, "nested");
    assert!(SourceCatalog::discover_subpath(root.path(), "../outside").is_err());
}

#[cfg(unix)]
#[test]
fn explicit_subpath_cannot_follow_a_replaced_directory_link() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    write_skill(&outside, "outside", "Instructions");
    symlink(outside.path().join("outside"), root.path().join("link")).unwrap();
    assert!(SourceCatalog::discover_subpath(root.path(), "link").is_err());
}
