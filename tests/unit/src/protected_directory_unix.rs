use super::*;
use crate::platform::protected_directory::ProtectedDirectory;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn unix_modes_are_private_at_creation_and_widening_is_detected() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    assert_eq!(
        std::fs::metadata(root.path()).unwrap().mode() & 0o777,
        0o700
    );
    let file = root.create_file("secret").unwrap();
    assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
    let child = root.create_child("request").unwrap();
    assert_eq!(
        std::fs::metadata(child.path()).unwrap().mode() & 0o777,
        0o700
    );
    file.set_permissions(std::fs::Permissions::from_mode(0o644))
        .unwrap();
    assert!(root.verify_file(&file).is_err());
    assert!(root.open_file("secret").is_err());
    std::fs::set_permissions(child.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(child.verify().is_err());
    assert!(root.open_child("request").is_err());
}

#[test]
fn symlinks_hardlinks_and_fifos_never_become_secret_handles() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    root.create_file("secret").unwrap();
    symlink("secret", root.path().join("link")).unwrap();
    assert!(root.open_file("link").is_err());
    assert!(root.create_file("link").is_err());
    root.create_child("child").unwrap();
    symlink("child", root.path().join("dirlink")).unwrap();
    assert!(root.open_child("dirlink").is_err());
    std::fs::hard_link(root.path().join("secret"), root.path().join("hard")).unwrap();
    assert!(root.open_file("hard").is_err());
    assert!(root.open_file("secret").is_err());
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(root.path().join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(root.open_file("fifo").is_err());
}

#[test]
fn protected_walk_checks_every_ancestor_and_rejects_symbolic_roots() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    let parent = root.create_child("parent").unwrap();
    let leaf = parent.create_child("leaf").unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(leaf.verify().is_err());
    assert!(leaf.create_file("secret").is_err());
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    leaf.verify().unwrap();
    let alias = temporary.path().with_extension("symlink-test");
    symlink(temporary.path(), &alias).unwrap();
    assert!(ProtectedDirectory::open_test_root(&alias).is_err());
    std::fs::remove_file(alias).unwrap();
}

#[test]
fn production_policy_rejects_nonroot_owner_and_writable_ancestors() {
    let temporary = tempfile::tempdir().unwrap();
    let file = File::open(temporary.path()).unwrap();
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(validate_directory(&file, false, &Authority::Privileged).is_err());
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    if unsafe { libc::geteuid() } != 0 {
        assert!(validate_directory(&file, true, &Authority::Privileged).is_err());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn extended_acl_grants_are_rejected_even_with_private_mode_bits() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    let child = root.create_child("child").unwrap();
    let leaf = child.create_child("leaf").unwrap();
    let file = child.create_file("fixture").unwrap();
    for path in [child.path().join("fixture"), child.path().to_owned()] {
        assert!(std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(path)
            .status()
            .unwrap()
            .success());
    }
    assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(child.path()).unwrap().mode() & 0o777,
        0o700
    );
    assert!(root.verify_file(&file).is_err());
    assert!(child.verify().is_err());
    assert!(leaf.verify().is_err());
    assert!(root.open_child("child").is_err());
    // Ancestors receive the same conservative ACL policy as private roots.
    assert!(validate_directory(
        &child.dir().try_clone().unwrap().into_std_file(),
        false,
        &root.authority
    )
    .is_err());
}
