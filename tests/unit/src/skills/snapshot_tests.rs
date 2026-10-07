use super::*;
use std::fs;
use std::io::Read;

fn source() -> TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("SKILL.md"), b"# A skill\n").unwrap();
    root
}

#[test]
fn staging_preserves_exact_bytes_and_is_independent_of_source_edits() {
    let root = source();
    fs::create_dir(root.path().join("empty")).unwrap();
    fs::write(root.path().join("binary"), b"\0\xff\r\n").unwrap();
    let package = PackageSnapshot::capture(root.path(), PackageLimits::default()).unwrap();
    let digest = package.tree_digest().to_owned();
    fs::write(root.path().join("SKILL.md"), b"replaced").unwrap();
    fs::remove_file(root.path().join("binary")).unwrap();
    for entry in &package.manifest().entries {
        if entry.kind == EntryKind::File {
            let mut bytes = Vec::new();
            package
                .open_object(&entry.sha256)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            entry.verify_content(&bytes).unwrap();
            assert_ne!(bytes, b"replaced");
        }
    }
    assert_eq!(digest, package.manifest().digest().unwrap());
    assert!(package
        .manifest()
        .entries
        .iter()
        .any(|e| e.path == "empty" && e.kind == EntryKind::Directory));
    assert!(package.open_object("../SKILL.md").is_err());
}

#[test]
fn repeated_bytes_are_deduplicated_but_count_towards_expanded_quota() {
    let root = source();
    fs::write(root.path().join("copy"), b"# A skill\n").unwrap();
    let package = PackageSnapshot::capture(root.path(), PackageLimits::default()).unwrap();
    assert_eq!(package.objects.len(), 1);
    assert_eq!(package.total_bytes(), 20);
    let limits = PackageLimits {
        total_bytes: 19,
        ..PackageLimits::default()
    };
    assert!(PackageSnapshot::capture(root.path(), limits)
        .unwrap_err()
        .to_string()
        .contains("QUOTA_EXCEEDED"));
}

#[test]
fn file_and_entry_limits_fail_without_returning_partial_packages() {
    let root = source();
    fs::create_dir_all(root.path().join("a/b")).unwrap();
    for limits in [
        PackageLimits {
            file_bytes: 9,
            ..PackageLimits::default()
        },
        PackageLimits {
            entries: 2,
            ..PackageLimits::default()
        },
        PackageLimits {
            entries: 0,
            ..PackageLimits::default()
        },
    ] {
        assert!(PackageSnapshot::capture(root.path(), limits).is_err());
    }
}

#[test]
fn git_metadata_is_excluded_but_skill_assets_are_preserved() {
    let root = source();
    fs::create_dir(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/config"), b"must not upload").unwrap();
    fs::create_dir(root.path().join("node_modules")).unwrap();
    fs::write(root.path().join("node_modules/needed.js"), b"asset").unwrap();
    let package = PackageSnapshot::capture(root.path(), PackageLimits::default()).unwrap();
    assert!(package
        .manifest()
        .entries
        .iter()
        .all(|e| !e.path.starts_with(".git")));
    assert!(package
        .manifest()
        .entries
        .iter()
        .any(|e| e.path == "node_modules/needed.js"));
}

#[test]
fn unresolved_lfs_objects_are_never_treated_as_complete_assets() {
    let root = source();
    fs::write(
        root.path().join("large.bin"),
        b"version https://git-lfs.github.com/spec/v1\noid sha256:123\nsize 1024\n",
    )
    .unwrap();
    let error = PackageSnapshot::capture(root.path(), PackageLimits::default()).unwrap_err();
    assert!(error.to_string().contains("INCOMPLETE_SOURCE"));
}

#[test]
fn streaming_classification_handles_split_utf8_and_truncated_sequences() {
    let root = source();
    let mut bytes = vec![b'a'; 65_535];
    bytes.extend_from_slice("你好".as_bytes());
    fs::write(root.path().join("text"), &bytes).unwrap();
    bytes.pop();
    fs::write(root.path().join("truncated"), &bytes).unwrap();
    let package = PackageSnapshot::capture(root.path(), PackageLimits::default()).unwrap();
    for entry in &package.manifest().entries {
        let bytes = fs::read(root.path().join(&entry.path)).unwrap();
        entry.verify_content(&bytes).unwrap();
    }
}

#[test]
fn final_rewalk_rejects_same_length_replacement() {
    let root = source();
    let dir = source_fs::open_root(root.path()).unwrap();
    let expected = BTreeMap::from([
        (String::new(), dir.dir_metadata().unwrap()),
        ("SKILL.md".into(), dir.symlink_metadata("SKILL.md").unwrap()),
    ]);
    fs::write(root.path().join("replacement"), b"# B skill\n").unwrap();
    fs::rename(
        root.path().join("replacement"),
        root.path().join("SKILL.md"),
    )
    .unwrap();
    assert!(source_fs::verify_tree(&dir, "", &expected).is_err());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn root_alias_and_internal_links_are_preserved_without_uploading_external_targets() {
        let root = source();
        symlink("SKILL.md", root.path().join("alias")).unwrap();
        let parent = tempfile::tempdir().unwrap();
        symlink(root.path(), parent.path().join("root")).unwrap();
        let package =
            PackageSnapshot::capture(&parent.path().join("root"), PackageLimits::default())
                .unwrap();
        let alias = package
            .manifest()
            .entries
            .iter()
            .find(|e| e.path == "alias")
            .unwrap();
        assert_eq!(alias.kind, EntryKind::Symlink);
        assert_eq!(alias.target, "SKILL.md");
        assert_eq!(package.objects.len(), 1);
        symlink(parent.path(), root.path().join("outside")).unwrap();
        assert!(PackageSnapshot::capture(root.path(), PackageLimits::default()).is_err());
    }

    #[test]
    fn dangling_cycles_and_parent_links_are_rejected() {
        for target in ["missing", "alias", "../secret", "."] {
            let root = source();
            symlink(target, root.path().join("alias")).unwrap();
            assert!(
                PackageSnapshot::capture(root.path(), PackageLimits::default()).is_err(),
                "{target}"
            );
        }
    }

    #[test]
    fn permissions_preserve_execute_and_drop_special_bits() {
        let root = source();
        fs::write(root.path().join("run"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(root.path().join("run"), fs::Permissions::from_mode(0o4755)).unwrap();
        let package = PackageSnapshot::capture(root.path(), PackageLimits::default()).unwrap();
        assert_eq!(
            package
                .manifest()
                .entries
                .iter()
                .find(|e| e.path == "run")
                .unwrap()
                .mode,
            0o755
        );
        assert_eq!(
            fs::metadata(package.staging.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn sockets_and_non_utf8_names_are_rejected() {
        use std::os::unix::net::UnixListener;
        let root = source();
        let socket = root.path().join("sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        assert!(PackageSnapshot::capture(root.path(), PackageLimits::default()).is_err());
        fs::remove_file(socket).unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStringExt;
            fs::write(
                root.path().join(std::ffi::OsString::from_vec(vec![0xff])),
                b"x",
            )
            .unwrap();
            assert!(PackageSnapshot::capture(root.path(), PackageLimits::default()).is_err());
        }
    }

    #[test]
    fn opened_file_cannot_be_replaced_with_an_external_symlink() {
        let root = source();
        let dir = source_fs::open_root(root.path()).unwrap();
        let before = dir.symlink_metadata("SKILL.md").unwrap();
        fs::remove_file(root.path().join("SKILL.md")).unwrap();
        symlink("/etc/passwd", root.path().join("SKILL.md")).unwrap();
        assert!(source_fs::open_file(&dir, "SKILL.md", &before).is_err());
    }
}
