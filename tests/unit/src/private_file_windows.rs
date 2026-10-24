use super::*;
use std::io::Write;

#[test]
fn private_file_acl_is_applied_before_writing_and_identity_is_handle_bound() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("credential");
    let mut file = File::create(&path).unwrap();
    restrict(&file, false).unwrap();
    validate(&file).unwrap();
    validate_kind(&file).unwrap();
    file.write_all(b"fixture-only").unwrap();
    let identity_before = identity(&file).unwrap();
    assert_eq!(
        identity_before,
        identity(&file.try_clone().unwrap()).unwrap()
    );
    let other = File::create(directory.path().join("other")).unwrap();
    assert_ne!(identity_before, identity(&other).unwrap());
    assert_eq!(identity_before.split(':').nth(1).unwrap().len(), 32);
}

#[test]
fn configuration_acl_grants_system_read_and_current_user_full_control() {
    let directory = tempfile::tempdir().unwrap();
    let file = File::create(directory.path().join("configuration")).unwrap();
    restrict(&file, true).unwrap();
    validate_wireguard(&file).unwrap();
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    let _allocation = LocalAllocation(descriptor);
    assert!(!acl.is_null());
    let user = current_user().unwrap();
    let mut system = [0usize; 16];
    let mut size = std::mem::size_of_val(&system) as u32;
    assert_ne!(
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                null_mut(),
                system.as_mut_ptr().cast(),
                &mut size,
            )
        },
        0
    );
    let (mut found_user, mut found_system) = (false, false);
    for index in 0..unsafe { (*acl).AceCount } {
        let mut raw = null_mut();
        assert_ne!(unsafe { GetAce(acl, u32::from(index), &mut raw) }, 0);
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        assert_eq!(ace.Header.AceType, 0);
        let sid = (&ace.SidStart as *const u32).cast_mut().cast();
        if unsafe { EqualSid(sid, user_sid(&user)) } != 0 {
            found_user = true;
            assert_eq!(ace.Mask & FILE_ALL_ACCESS, FILE_ALL_ACCESS);
            if unsafe { EqualSid(sid, system.as_mut_ptr().cast()) } != 0 {
                found_system = true;
            }
        } else {
            assert_ne!(unsafe { EqualSid(sid, system.as_mut_ptr().cast()) }, 0);
            found_system = true;
            assert_eq!(ace.Mask, FILE_GENERIC_READ);
        }
    }
    assert!(found_user && found_system);
}

#[test]
fn shared_directory_acl_rejects_untrusted_write_access() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Security::WinWorldSid;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    let directory = tempfile::tempdir().unwrap();
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .access_mode(READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory.path())
        .unwrap();
    validate_directory(&handle).unwrap();
    let mut everyone = well_known_sid(WinWorldSid).unwrap();
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: everyone.as_mut_ptr().cast(),
            ..Default::default()
        },
    };
    let mut acl = null_mut();
    assert_eq!(unsafe { SetEntriesInAclW(1, &entry, null(), &mut acl) }, 0);
    let _allocation = LocalAllocation(acl.cast());
    assert_eq!(
        unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
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
    assert!(validate_directory(&handle).is_err());
}

#[test]
fn wireguard_system_read_exception_does_not_relax_credentials_or_allow_system_write() {
    let user = current_user().unwrap();
    let mut system = well_known_sid(WinLocalSystemSid).unwrap();
    // LocalSystem is the owner itself in this unusual execution context.
    if unsafe { EqualSid(user_sid(&user), system.as_mut_ptr().cast()) } != 0 {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let file = File::create(directory.path().join("configuration")).unwrap();
    restrict(&file, true).unwrap();
    validate_wireguard(&file).unwrap();
    assert!(validate(&file).is_err());
    let raw = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    assert_ne!(raw, INVALID_HANDLE_VALUE);
    let acl_file = unsafe { File::from_raw_handle(raw) };
    let entry = |sid: PSID, rights| EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: SET_ACCESS,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid.cast(),
            ..Default::default()
        },
    };
    for forbidden in [FILE_GENERIC_READ | 2, FILE_ALL_ACCESS] {
        let entries = [
            entry(user_sid(&user), FILE_ALL_ACCESS),
            entry(system.as_mut_ptr().cast(), forbidden),
        ];
        let mut acl = null_mut();
        assert_eq!(
            unsafe { SetEntriesInAclW(2, entries.as_ptr(), null(), &mut acl) },
            0
        );
        let _allocation = LocalAllocation(acl.cast());
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    acl_file.as_raw_handle(),
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
        assert!(validate_wireguard(&file).is_err());
        assert!(validate(&file).is_err());
    }
}
