use super::*;
use crate::platform::protected_directory::ProtectedDirectory;

#[test]
fn windows_children_use_explicit_private_descriptor_and_do_not_claim_directory_sync() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    let child = root.create_child("request").unwrap();
    let file = child.create_file("agent-remote.conf").unwrap();
    child.verify_file(&file).unwrap();
    assert_eq!(root.sync().unwrap(), DirectorySync::Unsupported);
    for name in [
        "CON",
        "NUL.txt",
        "LPT1",
        "COM9.conf",
        "trailing.",
        "name:stream",
    ] {
        assert!(root.create_file(name).is_err());
        assert!(root.create_child(name).is_err());
    }
}

#[test]
fn system_policy_does_not_trust_a_current_user_private_file() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    let file = root.create_file("fixture").unwrap();
    let user = current_user().unwrap();
    let identities = Identities::new(&Authority::Privileged).unwrap();
    if !identities.trusts(user_sid(&user)) {
        assert!(validate_file(&file, &Authority::Privileged).is_err());
        assert!(validate_directory(
            &root.dir().try_clone().unwrap().into_std_file(),
            true,
            &Authority::Privileged
        )
        .is_err());
    }
}

#[test]
fn widened_acl_is_rejected_for_files_and_each_directory_ancestor() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    let child = root.create_child("child").unwrap();
    let leaf = child.create_child("leaf").unwrap();
    let file = child.create_file("fixture").unwrap();
    grant_everyone_full_access(&file);
    assert!(child.verify_file(&file).is_err());
    assert!(child.open_file("fixture").is_err());
    grant_everyone_full_access(&child.dir().try_clone().unwrap().into_std_file());
    assert!(child.verify().is_err());
    assert!(leaf.verify().is_err());
    assert!(leaf.create_file("fixture").is_err());
}

#[test]
fn hardlinks_do_not_become_private_file_handles() {
    let temporary = tempfile::tempdir().unwrap();
    let root = ProtectedDirectory::open_test_root(temporary.path()).unwrap();
    let file = root.create_file("fixture").unwrap();
    std::fs::hard_link(root.path().join("fixture"), root.path().join("alias")).unwrap();
    assert!(root.verify_file(&file).is_err());
    assert!(root.open_file("fixture").is_err());
    assert!(root.open_file("alias").is_err());
}

fn grant_everyone_full_access(file: &File) {
    use windows_sys::Win32::Security::GetSecurityDescriptorDacl;

    let text: Vec<u16> = "D:P(A;;FA;;;WD)".encode_utf16().chain(Some(0)).collect();
    let mut raw = null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                null_mut(),
            )
        },
        0
    );
    let descriptor = Local(raw);
    let (mut present, mut defaulted, mut acl) = (0, 0, null_mut());
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) },
        0
    );
    assert_ne!(present, 0);
    assert_eq!(
        unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null(),
            )
        },
        0
    );
}
