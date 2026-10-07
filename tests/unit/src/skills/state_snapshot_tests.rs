use super::*;
use crate::skills::manifest::{ContentKind, EntryKind};
use crate::skills::source_fs::SourceEntries;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
};

fn capture(path: &Path) -> StateSnapshot {
    StateSnapshot::directory(
        path,
        StateLimits::DIRECTORY,
        &CaptureCancellation::default(),
    )
    .unwrap()
}

#[test]
fn state_preserves_git_data_lfs_text_binary_empty_directories_and_no_skill_metadata() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join(".git/empty")).unwrap();
    fs::write(root.path().join(".git/config"), b"runtime git data\n").unwrap();
    let lfs = b"version https://git-lfs.github.com/spec/v1\r\noid sha256:123\r\nsize 12\r\n";
    fs::write(root.path().join("lfs.txt"), lfs).unwrap();
    fs::write(root.path().join("database"), b"\0\xff\r\n").unwrap();
    let snapshot = capture(root.path());
    assert_eq!(snapshot.manifest().entries.len(), 5);
    assert_eq!(snapshot.manifest().entries[0].path, ".git");
    assert_eq!(snapshot.manifest().entries[2].kind, EntryKind::Directory);
    for entry in &snapshot.manifest().entries {
        if entry.kind == EntryKind::File {
            let mut bytes = Vec::new();
            snapshot
                .open_object(&entry.sha256)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            entry.verify_content(&bytes).unwrap();
            assert_eq!(bytes, fs::read(root.path().join(&entry.path)).unwrap());
        }
    }
    assert_eq!(
        snapshot.tree_digest(),
        snapshot.manifest().digest().unwrap()
    );
}

#[test]
fn file_capture_reads_no_siblings_and_remains_exact_after_source_removal() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("chosen"), b"\xff\0\r\n").unwrap();
    fs::write(root.path().join("private-sibling"), b"not selected").unwrap();
    let snapshot = StateSnapshot::file(
        &root.path().join("chosen"),
        StateLimits::ITEM,
        &CaptureCancellation::default(),
    )
    .unwrap();
    fs::remove_dir_all(root.path()).unwrap();
    let [entry] = snapshot.manifest().entries.as_slice() else {
        panic!("one file expected")
    };
    assert_eq!(entry.path, "content");
    assert_eq!(entry.content_kind, ContentKind::Binary);
    assert_eq!(snapshot.total_bytes(), 4);
    let mut bytes = Vec::new();
    snapshot
        .open_object(&entry.sha256)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"\xff\0\r\n");
    assert!(snapshot.open_object("../../private-sibling").is_err());
}

#[test]
fn state_large_file_exceeds_package_file_limit_and_classifies_split_utf8() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("large");
    let mut output = fs::File::create(&path).unwrap();
    let chunk = [b'a'; 65_536];
    for _ in 0..160 {
        output.write_all(&chunk).unwrap();
    }
    output.write_all(&chunk[..65_535]).unwrap();
    output.write_all("你好".as_bytes()).unwrap();
    drop(output);
    let snapshot =
        StateSnapshot::file(&path, StateLimits::ITEM, &CaptureCancellation::default()).unwrap();
    let entry = &snapshot.manifest().entries[0];
    assert!(entry.size > 10 * 1024 * 1024);
    assert_eq!(entry.content_kind, ContentKind::Text);
    assert!(PackageSnapshot::capture(root.path(), PackageLimits::default()).is_err());
}

#[test]
fn state_limits_count_duplicate_expanded_bytes_and_git_entries() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/a"), b"same").unwrap();
    fs::write(root.path().join("b"), b"same").unwrap();
    assert_eq!(capture(root.path()).total_bytes(), 8);
    for limits in [
        StateLimits {
            total_bytes: 7,
            entries: 3,
        },
        StateLimits {
            total_bytes: 8,
            entries: 2,
        },
        StateLimits {
            total_bytes: 0,
            entries: 3,
        },
        StateLimits {
            total_bytes: 8,
            entries: 100_001,
        },
    ] {
        assert!(
            StateSnapshot::directory(root.path(), limits, &CaptureCancellation::default()).is_err()
        );
        if limits.total_bytes == 0 || limits.entries > 100_000 {
            assert!(StateSnapshot::file(
                &root.path().join("b"),
                limits,
                &CaptureCancellation::default()
            )
            .is_err());
        }
    }
}

#[test]
fn empty_directory_and_empty_file_are_distinct_valid_snapshots() {
    let root = tempfile::tempdir().unwrap();
    let empty = capture(root.path());
    assert!(empty.manifest().entries.is_empty());
    fs::write(root.path().join("zero"), b"").unwrap();
    let file = StateSnapshot::file(
        &root.path().join("zero"),
        StateLimits::ITEM,
        &CaptureCancellation::default(),
    )
    .unwrap();
    assert_eq!(file.manifest().entries[0].content_kind, ContentKind::Text);
    assert_ne!(empty.tree_digest(), file.tree_digest());
}

#[test]
fn final_state_rewalk_includes_git_and_rejects_replaced_data() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/config"), b"before").unwrap();
    let dir = source_fs::open_root(root.path()).unwrap();
    let expected = BTreeMap::from([
        (String::new(), dir.dir_metadata().unwrap()),
        (".git".into(), dir.symlink_metadata(".git").unwrap()),
        (
            ".git/config".into(),
            dir.symlink_metadata(".git/config").unwrap(),
        ),
    ]);
    assert_eq!(
        source_fs::verify_selected_tree(&dir, "", &expected, SourceEntries::All, &|| Ok(()))
            .unwrap(),
        3
    );
    let config = root.path().join(".git/config");
    fs::write(&config, b"after!").unwrap();
    // Equal-length writes can share an mtime on Windows. Make the mutation
    // deterministic without depending on the runner's filesystem clock tick.
    let file = fs::OpenOptions::new().write(true).open(&config).unwrap();
    let changed = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
    file.set_times(std::fs::FileTimes::new().set_modified(changed))
        .unwrap();
    drop(file);
    assert!(
        source_fs::verify_selected_tree(&dir, "", &expected, SourceEntries::All, &|| Ok(()))
            .is_err()
    );
}

#[test]
fn cancelled_capture_and_rewalk_fail_without_returning_partial_trees() {
    let cancellation = CaptureCancellation::default();
    let worker = cancellation.clone();
    cancellation.cancel();
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("data"), b"x").unwrap();
    assert!(
        StateSnapshot::directory(root.path(), StateLimits::DIRECTORY, &worker)
            .unwrap_err()
            .to_string()
            .contains("SKILL_INTERRUPTED")
    );
    assert!(StateSnapshot::file(&root.path().join("data"), StateLimits::ITEM, &worker).is_err());
    let dir = source_fs::open_root(root.path()).unwrap();
    let expected = BTreeMap::from([(String::new(), dir.dir_metadata().unwrap())]);
    assert!(
        source_fs::verify_selected_tree(&dir, "", &expected, SourceEntries::All, &|| worker
            .check())
        .unwrap_err()
        .to_string()
        .contains("SKILL_INTERRUPTED")
    );
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn links_modes_and_private_staging_are_preserved_without_following_links() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("run"), b"executable data").unwrap();
        fs::set_permissions(root.path().join("run"), fs::Permissions::from_mode(0o4751)).unwrap();
        fs::create_dir(root.path().join("empty")).unwrap();
        fs::set_permissions(root.path().join("empty"), fs::Permissions::from_mode(0o750)).unwrap();
        symlink("run", root.path().join("alias")).unwrap();
        let snapshot = capture(root.path());
        assert_eq!(snapshot.manifest().entries[0].kind, EntryKind::Symlink);
        assert_eq!(snapshot.manifest().entries[0].target, "run");
        assert_eq!(snapshot.manifest().entries[1].mode, 0o750);
        let file = &snapshot.manifest().entries[2];
        assert_eq!(file.mode, 0o751);
        assert_eq!(
            snapshot
                .open_object(&file.sha256)
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(StateSnapshot::file(
            &root.path().join("alias"),
            StateLimits::ITEM,
            &CaptureCancellation::default()
        )
        .is_err());
    }

    #[test]
    fn unsupported_absolute_links_and_invalid_relative_links_fail_explicitly() {
        for target in ["/etc/passwd", "missing", "alias", "../outside", "."] {
            let root = tempfile::tempdir().unwrap();
            symlink(target, root.path().join("alias")).unwrap();
            let error = StateSnapshot::directory(
                root.path(),
                StateLimits::DIRECTORY,
                &CaptureCancellation::default(),
            )
            .unwrap_err();
            if target.starts_with('/') {
                assert!(error.to_string().contains("RUNTIME_LINK_METADATA_REQUIRED"));
            }
        }
    }

    #[test]
    fn fifo_input_is_rejected_without_opening_or_waiting_for_a_writer() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(
            StateSnapshot::file(&path, StateLimits::ITEM, &CaptureCancellation::default()).is_err()
        );
        assert!(StateSnapshot::directory(
            root.path(),
            StateLimits::DIRECTORY,
            &CaptureCancellation::default()
        )
        .is_err());
    }
}
