//! Native ACLs and handle-relative creation with a protected descriptor at birth.

use std::fs::File;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};

use anyhow::{ensure, Result};
use cap_std::fs::Dir;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    LocalFree, RtlNtStatusToDosError, GENERIC_READ, GENERIC_WRITE, UNICODE_STRING,
};
#[cfg(test)]
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, SetSecurityInfo};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetAce, GetLengthSid, GetTokenInformation, IsValidAcl,
    IsValidSid, TokenElevation, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
    ACE_HEADER, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID, TOKEN_ELEVATION,
    TOKEN_QUERY, WELL_KNOWN_SID_TYPE,
};
#[cfg(test)]
use windows_sys::Win32::Security::{TokenUser, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_USER};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::{Authority, DirectorySync};

struct Local(*mut core::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn token() -> Result<OwnedHandle> {
    let mut raw = null_mut();
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } != 0
            && !raw.is_null(),
        "cannot inspect process token"
    );
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
pub(super) fn require_privileged() -> Result<()> {
    let token = token()?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    ensure!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenElevation,
                std::ptr::from_mut(&mut elevation).cast(),
                std::mem::size_of_val(&elevation) as u32,
                &mut length,
            )
        } != 0
            && length as usize == std::mem::size_of_val(&elevation)
            && elevation.TokenIsElevated != 0,
        "protected storage requires elevated process"
    );
    Ok(())
}

pub(super) fn normalize(path: &Path) -> Result<PathBuf> {
    ensure!(
        matches!(path.components().next(),Some(Component::Prefix(prefix)) if matches!(prefix.kind(),Prefix::Disk(_)|Prefix::VerbatimDisk(_))),
        "protected root requires a local drive"
    );
    Ok(path.components().collect())
}

pub(super) fn open_root(path: &Path) -> Result<Dir> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        // Test roots are narrowed in `prepare_test_root` immediately after
        // opening.  Request WRITE_DAC on that original handle instead of
        // reopening it: Windows runners can reject `ReOpenFile` for a
        // temporary directory even when the current user owns the object.
        .access_mode(GENERIC_READ | READ_CONTROL | TEST_ROOT_ACCESS)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    reject_reparse(&file)?;
    ensure!(
        file.metadata()?.is_dir(),
        "protected root is not a directory"
    );
    Ok(Dir::from_std_file(file))
}

#[cfg(test)]
const TEST_ROOT_ACCESS: u32 = WRITE_DAC | WRITE_OWNER;
#[cfg(not(test))]
const TEST_ROOT_ACCESS: u32 = 0;

fn reject_reparse(file: &File) -> Result<()> {
    ensure!(
        file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "reparse points are forbidden"
    );
    Ok(())
}

fn sid(kind: WELL_KNOWN_SID_TYPE) -> Result<[usize; 16]> {
    let mut buffer = [0usize; 16];
    let mut length = std::mem::size_of_val(&buffer) as u32;
    ensure!(
        unsafe { CreateWellKnownSid(kind, null_mut(), buffer.as_mut_ptr().cast(), &mut length) }
            != 0,
        "cannot obtain privileged identity"
    );
    Ok(buffer)
}

struct Identities {
    system: [usize; 16],
    admins: [usize; 16],
    #[cfg(test)]
    user: Option<Vec<usize>>,
}
impl Identities {
    fn new(authority: &Authority) -> Result<Self> {
        let _ = authority;
        Ok(Self {
            system: sid(WinLocalSystemSid)?,
            admins: sid(WinBuiltinAdministratorsSid)?,
            #[cfg(test)]
            user: if authority.production() {
                None
            } else {
                Some(current_user()?)
            },
        })
    }
    fn trusts(&self, value: PSID) -> bool {
        #[cfg(test)]
        if let Some(user) = &self.user {
            return unsafe { EqualSid(value, user_sid(user)) } != 0;
        }
        unsafe {
            EqualSid(value, self.system.as_ptr().cast_mut().cast()) != 0
                || EqualSid(value, self.admins.as_ptr().cast_mut().cast()) != 0
        }
    }
}

pub(super) fn validate_directory(file: &File, private: bool, authority: &Authority) -> Result<()> {
    reject_reparse(file)?;
    ensure!(
        file.metadata()?.is_dir(),
        "protected entry is not a directory"
    );
    validate_acl(file, private, authority)
}
pub(super) fn validate_file(file: &File, authority: &Authority) -> Result<()> {
    crate::platform::validate_single_regular_file(file)?;
    validate_acl(file, true, authority)
}

fn validate_acl(file: &File, private: bool, authority: &Authority) -> Result<()> {
    let identities = Identities::new(authority)?;
    let (mut owner, mut acl, mut descriptor) = (null_mut(), null_mut(), null_mut());
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
        "cannot inspect protected ACL"
    );
    let _allocation = Local(descriptor);
    ensure!(
        !owner.is_null() && unsafe { IsValidSid(owner) } != 0 && identities.trusts(owner),
        "protected ownership is unsafe"
    );
    ensure!(
        !acl.is_null() && unsafe { IsValidAcl(acl) } != 0,
        "protected DACL is unsafe"
    );
    for index in 0..unsafe { (*acl).AceCount } {
        let mut raw = null_mut();
        ensure!(
            unsafe { GetAce(acl, u32::from(index), &mut raw) } != 0 && !raw.is_null(),
            "unreadable protected ACE"
        );
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        // Inherit-only ancestor grants do not grant access to that ancestor.
        // At the private root we additionally reject unsafe future inheritance.
        if !private && header.AceFlags & 0x08 != 0 {
            continue;
        }
        ensure!(
            header.AceType == 0
                && usize::from(header.AceSize) >= std::mem::size_of::<ACCESS_ALLOWED_ACE>() + 4,
            "unsupported protected ACE"
        );
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = std::ptr::from_ref(&ace.SidStart).cast_mut().cast();
        ensure!(
            unsafe { IsValidSid(sid) } != 0,
            "invalid protected ACE identity"
        );
        ensure!(
            unsafe { GetLengthSid(sid) } as usize <= usize::from(header.AceSize) - 8,
            "protected ACE identity exceeds entry"
        );
        if !identities.trusts(sid) {
            const READ_ONLY: u32 =
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | 0x8000_0000 | 0x2000_0000;
            ensure!(
                !private && ace.Mask & !READ_ONLY == 0,
                "unprivileged access to protected storage"
            );
        }
    }
    Ok(())
}

fn descriptor(authority: &Authority) -> Result<Local> {
    let _ = authority;
    let value = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned();
    #[cfg(test)]
    let mut value = value;
    #[cfg(test)]
    if !authority.production() {
        let user = current_user()?;
        let mut raw = null_mut();
        ensure!(
            unsafe { ConvertSidToStringSidW(user_sid(&user), &mut raw) } != 0,
            "cannot encode test identity"
        );
        let _allocation = Local(raw.cast());
        let mut length = 0;
        while unsafe { *raw.add(length) } != 0 {
            length += 1;
        }
        let identity = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })?;
        value = format!("O:{identity}D:P(A;;FA;;;{identity})");
    }
    let wide: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let mut raw = null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut raw,
                null_mut(),
            )
        } != 0,
        "cannot create protected descriptor"
    );
    Ok(Local(raw))
}

fn relative(
    parent: &Dir,
    name: &str,
    directory: bool,
    create: bool,
    append: bool,
    authority: Option<&Authority>,
) -> std::io::Result<File> {
    let sd = authority
        .map(descriptor)
        .transpose()
        .map_err(std::io::Error::other)?;
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let bytes = u16::try_from(wide.len() * 2)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut string = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut string,
        Attributes: 0x40,
        SecurityDescriptor: sd.as_ref().map_or(null(), |sd| sd.0.cast()),
        SecurityQualityOfService: null_mut(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            GENERIC_READ
                | READ_CONTROL
                | SYNCHRONIZE
                | if create { GENERIC_WRITE | WRITE_DAC } else { 0 }
                | if append { FILE_APPEND_DATA } else { 0 },
            &attributes,
            &mut status,
            null_mut(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            if create { FILE_CREATE } else { FILE_OPEN },
            FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
                | if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                },
            null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    if handle.is_null() {
        return Err(std::io::Error::from(std::io::ErrorKind::Other));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(super) fn create_file(parent: &Dir, name: &str, authority: &Authority) -> Result<File> {
    Ok(relative(parent, name, false, true, false, Some(authority))?)
}
pub(super) fn open_file(parent: &Dir, name: &str) -> Result<Option<File>> {
    match relative(parent, name, false, false, false, None) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
pub(super) fn open_append_file(parent: &Dir, name: &str) -> Result<Option<File>> {
    match relative(parent, name, false, false, true, None) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
pub(super) fn create_child(parent: &Dir, name: &str, authority: &Authority) -> Result<Dir> {
    Ok(Dir::from_std_file(relative(
        parent,
        name,
        true,
        true,
        false,
        Some(authority),
    )?))
}
pub(super) fn open_child(parent: &Dir, name: &str) -> Result<Option<Dir>> {
    match relative(parent, name, true, false, false, None) {
        Ok(file) => Ok(Some(Dir::from_std_file(file))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
pub(super) fn sync(_directory: &Dir) -> Result<DirectorySync> {
    // FlushFileBuffers does not promise Unix parent-directory fsync semantics.
    // The caller must sync file handles and retain this explicit durability gap.
    Ok(DirectorySync::Unsupported)
}

#[cfg(test)]
fn current_user() -> Result<Vec<usize>> {
    let token = token()?;
    let mut size = 0;
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size) };
    ensure!(
        (std::mem::size_of::<TOKEN_USER>() as u32..=65536).contains(&size),
        "invalid test token size"
    );
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    ensure!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } != 0,
        "cannot read test token"
    );
    Ok(buffer)
}
#[cfg(test)]
fn user_sid(user: &[usize]) -> PSID {
    unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
}

#[cfg(test)]
pub(super) fn prepare_test_root(directory: &Dir) -> Result<()> {
    use windows_sys::Win32::Security::GetSecurityDescriptorDacl;
    let user = current_user()?;
    let file = directory.try_clone()?.into_std_file();
    let (mut owner, mut original) = (null_mut(), null_mut());
    ensure!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut original,
            )
        } == 0,
        "cannot inspect test root owner"
    );
    let _allocation = Local(original);
    // Hosted Windows runners may create TempDir roots with an inherited
    // Administrators owner even though the test process runs as that user.
    // Transfer ownership to the token user on the test-only handle before
    // installing the private descriptor. Production roots never use this
    // helper, so the production ownership checks remain unchanged.
    let current = user_sid(&user);
    if unsafe { EqualSid(owner, current) } == 0 {
        ensure!(
            unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    current,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null(),
                )
            } == 0,
            "cannot assign test root owner"
        );
    }
    let authority = Authority::Test {
        anchor: PathBuf::new(),
        identity: String::new(),
    };
    let sd = descriptor(&authority)?;
    let (mut present, mut defaulted, mut acl) = (0, 0, null_mut());
    ensure!(
        unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut acl, &mut defaulted) } != 0
            && present != 0,
        "invalid test descriptor"
    );
    ensure!(
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
        } == 0,
        "cannot protect test root"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/src/protected_directory_windows.rs"]
mod tests;
