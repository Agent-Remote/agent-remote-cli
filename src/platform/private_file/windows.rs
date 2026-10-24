use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::{null, null_mut};

use anyhow::{bail, ensure, Result};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, SET_ACCESS,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetAce, GetTokenInformation, IsValidAcl, IsValidSid, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSID, TOKEN_QUERY, TOKEN_USER, WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx, ReOpenFile,
    BY_HANDLE_FILE_INFORMATION, FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct LocalAllocation(*mut core::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

// usize storage gives TOKEN_USER and SID their required alignment.
fn current_user() -> Result<Vec<usize>> {
    let mut handle = null_mut();
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } != 0,
        "cannot query current process identity"
    );
    let token = Token(handle);
    let mut size = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size) };
    ensure!(
        (std::mem::size_of::<TOKEN_USER>()..=65536).contains(&(size as usize)),
        "invalid process identity size"
    );
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } != 0,
        "cannot read current process identity"
    );
    ensure!(
        unsafe { IsValidSid(user_sid(&buffer)) } != 0,
        "invalid process identity"
    );
    Ok(buffer)
}

fn user_sid(buffer: &[usize]) -> PSID {
    unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid }
}

pub(super) fn restrict(file: &File, system_read: bool) -> Result<()> {
    // Request ACL rights on the same kernel file object, never a mutable path.
    let raw = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    ensure!(raw != INVALID_HANDLE_VALUE, "cannot obtain file ACL rights");
    let acl_file = unsafe { File::from_raw_handle(raw) };
    let user = current_user()?;
    let mut system = [0usize; 16];
    let mut system_size = std::mem::size_of_val(&system) as u32;
    ensure!(
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                null_mut(),
                system.as_mut_ptr().cast(),
                &mut system_size,
            )
        } != 0,
        "cannot obtain LocalSystem identity"
    );
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
    let entries = [
        entry(user_sid(&user), FILE_ALL_ACCESS),
        entry(system.as_mut_ptr().cast(), FILE_GENERIC_READ),
    ];
    let mut acl: *mut ACL = null_mut();
    ensure!(
        unsafe {
            SetEntriesInAclW(
                if system_read { 2 } else { 1 },
                entries.as_ptr(),
                null(),
                &mut acl,
            )
        } == 0,
        "cannot create private file ACL"
    );
    let _allocation = LocalAllocation(acl.cast());
    ensure!(
        unsafe {
            SetSecurityInfo(
                acl_file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION
                    | OWNER_SECURITY_INFORMATION,
                user_sid(&user),
                null_mut(),
                acl,
                null(),
            )
        } == 0,
        "cannot apply private file ACL"
    );
    Ok(())
}

pub(super) fn identity(file: &File) -> Result<String> {
    let mut info = FILE_ID_INFO::default();
    ensure!(
        unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        } != 0,
        "cannot obtain native file identity"
    );
    let id: String = info
        .FileId
        .Identifier
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("{}:{id}", info.VolumeSerialNumber))
}

pub(super) fn validate_kind(file: &File) -> Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    ensure!(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
        "cannot inspect credential handle"
    );
    ensure!(
        info.nNumberOfLinks == 1 && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "credential links are unsafe"
    );
    Ok(())
}

pub(super) fn validate(file: &File) -> Result<()> {
    validate_acl(file, false, false)
}

pub(super) fn validate_wireguard(file: &File) -> Result<()> {
    validate_acl(file, false, true)
}

pub(super) fn validate_directory(file: &File) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    ensure!(
        file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "directory is a reparse point"
    );
    validate_acl(file, true, false)
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<[usize; 16]> {
    let mut buffer = [0usize; 16];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    ensure!(
        unsafe { CreateWellKnownSid(kind, null_mut(), buffer.as_mut_ptr().cast(), &mut size) } != 0,
        "cannot obtain trusted identity"
    );
    Ok(buffer)
}

fn validate_acl(file: &File, directory: bool, system_read: bool) -> Result<()> {
    let user = current_user()?;
    let system = well_known_sid(WinLocalSystemSid)?;
    let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
    let trusted = |sid| unsafe {
        EqualSid(sid, user_sid(&user)) != 0
            || (directory
                && (EqualSid(sid, system.as_ptr().cast_mut().cast()) != 0
                    || EqualSid(sid, administrators.as_ptr().cast_mut().cast()) != 0))
    };
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    ensure!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        } == 0,
        "cannot inspect credential ACL"
    );
    let _allocation = LocalAllocation(descriptor);
    ensure!(
        !owner.is_null() && unsafe { IsValidSid(owner) } != 0 && trusted(owner),
        "credential ownership is unsafe"
    );
    ensure!(
        !acl.is_null() && unsafe { IsValidAcl(acl) } != 0,
        "credential ACL is unsafe"
    );
    for index in 0..unsafe { (*acl).AceCount } {
        let mut raw = null_mut();
        ensure!(
            unsafe { GetAce(acl, u32::from(index), &mut raw) } != 0 && !raw.is_null(),
            "credential ACL entry is unreadable"
        );
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        // Inherit-only directory entries grant no access to this directory.
        // Strictly created secret/lock files get their own protected DACL.
        if directory && header.AceFlags & 0x08 != 0 {
            continue;
        }
        // Only a direct allow ACE for the process user is accepted. Unknown,
        // inherited broad grants and callback/object ACEs fail closed.
        if header.AceType != 0
            || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            bail!("credential ACL entry is unsafe")
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&ace.SidStart as *const u32).cast_mut().cast();
        ensure!(unsafe { IsValidSid(sid) } != 0, "invalid ACL identity");
        if !trusted(sid) {
            if system_read && unsafe { EqualSid(sid, system.as_ptr().cast_mut().cast()) } != 0 {
                ensure!(
                    ace.Mask & !FILE_GENERIC_READ == 0,
                    "tunnel configuration grants System more than read access"
                );
                continue;
            }
            // Generic write/all, delete, owner/DACL changes, data/child writes,
            // delete-child, and write attributes/EA can replace lock authority.
            const MUTATING_RIGHTS: u32 =
                0x4000_0000 | 0x1000_0000 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x0000_0156;
            ensure!(
                directory && ace.Mask & MUTATING_RIGHTS == 0,
                "ACL permits an untrusted identity to change protected data"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/src/private_file_windows.rs"]
mod tests;
