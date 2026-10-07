use super::*;

fn entry(path: &str, kind: EntryKind, target: &str) -> Entry {
    Entry {
        path: path.into(),
        kind,
        mode: if matches!(kind, EntryKind::Symlink | EntryKind::RuntimeLink) {
            0o777
        } else {
            0o700
        },
        size: 0,
        sha256: String::new(),
        target: target.into(),
        content_kind: ContentKind::Empty,
        dependency: String::new(),
    }
}

fn add(bundle: &mut RecoveryBundle, entry: Entry, content: Option<&[u8]>) {
    let mut start = entry.clone();
    if entry.kind == EntryKind::File {
        start.sha256.clear();
        start.content_kind = ContentKind::Empty;
    }
    let file = bundle.begin(start).unwrap();
    if let Some(mut file) = file {
        file.write_all(content.unwrap()).unwrap();
        file.sync_all().unwrap();
    }
    bundle.complete(entry).unwrap();
}

#[test]
fn recovery_disk_index_validates_forward_links_and_explicit_parents() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("bundle");
    let mut bundle = RecoveryBundle::prepare(&output, &serde_json::json!({})).unwrap();
    add(&mut bundle, entry("link", EntryKind::Symlink, "dir"), None);
    add(&mut bundle, entry("dir", EntryKind::Directory, ""), None);
    add(
        &mut bundle,
        entry("dir/empty", EntryKind::Directory, ""),
        None,
    );
    let expected = bundle.summary();
    let staged = bundle.finish(&expected).unwrap();
    assert!(!output.exists());
    drop(staged);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn recovery_disk_index_rejects_duplicates_missing_parents_and_unsafe_links() {
    for kind in [
        "duplicate",
        "parent",
        "escape",
        "missing",
        "cycle",
        "ancestor",
        "non_directory",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("bundle");
        let mut bundle = RecoveryBundle::prepare(&output, &serde_json::json!({})).unwrap();
        match kind {
            "duplicate" => {
                add(&mut bundle, entry("dir", EntryKind::Directory, ""), None);
                assert!(bundle
                    .begin(entry("dir", EntryKind::Directory, ""))
                    .is_err());
                drop(bundle);
            }
            "parent" => {
                assert!(bundle
                    .begin(entry("absent/dir", EntryKind::Directory, ""))
                    .is_err());
                drop(bundle);
            }
            _ => {
                add(&mut bundle, entry("dir", EntryKind::Directory, ""), None);
                let (path, target) = match kind {
                    "escape" => ("link", "../outside"),
                    "missing" => ("link", "missing"),
                    "cycle" => ("link", "link"),
                    "ancestor" => ("dir/link", "."),
                    "non_directory" => ("link", "file/../file"),
                    _ => unreachable!(),
                };
                if kind == "non_directory" {
                    let mut file = entry("file", EntryKind::File, "");
                    file.sha256 = format!("{:x}", Sha256::digest(b""));
                    file.content_kind = ContentKind::Text;
                    add(&mut bundle, file, Some(b""));
                }
                add(&mut bundle, entry(path, EntryKind::Symlink, target), None);
                let expected = bundle.summary();
                assert!(bundle.finish(&expected).is_err(), "{kind}");
            }
        }
        assert!(!output.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0, "{kind}");
    }
}

#[test]
fn recovery_never_replaces_a_destination_that_gains_data() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("bundle");
    let bundle = RecoveryBundle::prepare(&output, &serde_json::json!({})).unwrap();
    let summary = bundle.summary();
    let staged = bundle.finish(&summary).unwrap();
    fs::create_dir(&output).unwrap();
    fs::write(output.join("keep"), b"original").unwrap();
    assert!(staged.publish().is_err());
    assert_eq!(fs::read(output.join("keep")).unwrap(), b"original");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
#[ignore = "actual 100001-entry private destination acceptance"]
fn recovery_disk_index_accepts_over_manifest_limit() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("bundle");
    let mut bundle = RecoveryBundle::prepare(&output, &serde_json::json!({})).unwrap();
    for index in 0..100_001 {
        add(
            &mut bundle,
            entry(&format!("dir-{index:06}"), EntryKind::Directory, ""),
            None,
        );
    }
    let expected = bundle.summary();
    assert_eq!(expected.entries, 100_001);
    let staged = bundle.finish(&expected).unwrap();
    staged.publish().unwrap();
    assert_eq!(
        fs::read_dir(output.join("entries")).unwrap().count(),
        100_001
    );
    assert!(!output.join("manifest.json").exists());
}
