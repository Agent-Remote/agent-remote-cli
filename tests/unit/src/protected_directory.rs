use super::*;
use std::io::{Read, Write};

#[test]
fn private_children_preserve_names_and_round_trip_files_through_handles() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    let child = root.create_child("request-123").unwrap();
    assert!(child.path().ends_with("request-123"));
    let mut file = child.create_file("agent-remote.conf").unwrap();
    file.write_all(b"fixture-only").unwrap();
    file.sync_all().unwrap();
    child.verify_file(&file).unwrap();
    let mut read = child.open_file("agent-remote.conf").unwrap().unwrap();
    let mut content = String::new();
    read.read_to_string(&mut content).unwrap();
    assert_eq!(content, "fixture-only");
    assert!(child.create_file("agent-remote.conf").is_err());
    assert!(root.create_child("request-123").is_err());
    assert!(root.open_child("missing").unwrap().is_none());
    assert!(child.open_file("missing").unwrap().is_none());
    let reopened = root.open_child("request-123").unwrap().unwrap();
    reopened.verify().unwrap();
    assert_eq!(reopened.path(), child.path());
    #[cfg(unix)]
    assert_eq!(child.sync().unwrap(), DirectorySync::Synced);
    #[cfg(windows)]
    assert_eq!(child.sync().unwrap(), DirectorySync::Unsupported);
    assert!(root.dir().dir_metadata().unwrap().is_dir());
}

#[test]
fn entry_names_cannot_escape_the_held_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    for name in [
        "",
        ".",
        "..",
        "../outside",
        "a/b",
        "a\\b",
        "C:stream",
        "bad\nname",
        &"x".repeat(129),
    ] {
        assert!(root.create_file(name).is_err());
        assert!(root.open_file(name).is_err());
        assert!(root.create_child(name).is_err());
        assert!(root.open_child(name).is_err());
    }
}

#[test]
fn renamed_or_replaced_directory_never_silently_retargets_the_capability() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    let child = root.create_child("request").unwrap();
    root.dir().rename("request", root.dir(), "moved").unwrap();
    assert!(child.verify().is_err());
    assert!(child.create_file("secret").is_err());
    let replacement = root.create_child("request").unwrap();
    assert!(child.verify().is_err());
    assert!(child.open_file("secret").is_err());
    replacement.verify().unwrap();
    assert!(replacement.open_file("secret").unwrap().is_none());
}

#[test]
fn file_and_directory_type_confusion_is_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    root.create_file("file").unwrap();
    root.create_child("directory").unwrap();
    assert!(root.open_file("directory").is_err());
    assert!(root.open_child("file").is_err());
    assert!(root.create_file("directory").is_err());
    assert!(root.create_child("file").is_err());
}

#[test]
fn caller_owned_temp_root_is_not_a_production_authority() {
    let temporary = tempfile::tempdir().unwrap();
    // Even a root test process must reject the unprotected /tmp ancestry.
    #[cfg(unix)]
    assert!(ProtectedDirectory::open_existing(temporary.path()).is_err());
    #[cfg(windows)]
    if native::require_privileged().is_err() {
        assert!(ProtectedDirectory::open_existing(temporary.path()).is_err());
    }
    assert!(ProtectedDirectory::open_existing(Path::new("relative")).is_err());
}
