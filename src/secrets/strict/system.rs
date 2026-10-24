use std::sync::atomic::AtomicBool;

use super::{check_cancel, SecretValue, StrictSecretError as Error};

#[cfg(target_os = "linux")]
mod linux;

pub(super) async fn read(key: &str, cancel: &AtomicBool) -> Result<Option<SecretValue>, Error> {
    check_cancel(cancel)?;
    #[cfg(target_os = "linux")]
    let result = linux::read(key, cancel).await;
    #[cfg(any(target_os = "macos", windows))]
    let result = { super::blocking_credential_operation(|| native_read(key)) };
    check_cancel(cancel)?;
    result
}

pub(super) async fn write(
    key: &str,
    value: &SecretValue,
    cancel: &AtomicBool,
) -> Result<(), Error> {
    check_cancel(cancel)?;
    #[cfg(target_os = "linux")]
    let result = linux::write(key, value, cancel).await;
    #[cfg(any(target_os = "macos", windows))]
    let result = { super::blocking_credential_operation(|| native_write(key, value)) };
    // Native Keychain/Credential APIs have no cancellable deadline. Keep the
    // caller's locks until they return; process termination is the outer bound.
    check_cancel(cancel)?;
    result
}

#[cfg(target_os = "macos")]
fn native_error(code: i32) -> Error {
    match code {
        -25293 | -25308 | -128 => Error::Denied,
        _ => Error::Unavailable,
    }
}

#[cfg(target_os = "macos")]
fn native_read(key: &str) -> Result<Option<SecretValue>, Error> {
    match security_framework::passwords::get_generic_password(crate::secrets::SERVICE, key) {
        Ok(bytes) => {
            SecretValue::new(String::from_utf8(bytes).map_err(|_| Error::Invalid)?).map(Some)
        }
        Err(error) if error.code() == -25300 => Ok(None),
        Err(error) => Err(native_error(error.code())),
    }
}

#[cfg(target_os = "macos")]
fn native_write(key: &str, value: &SecretValue) -> Result<(), Error> {
    security_framework::passwords::set_generic_password(
        crate::secrets::SERVICE,
        key,
        value.as_str().as_bytes(),
    )
    .map_err(|error| native_error(error.code()))
}

#[cfg(windows)]
fn native_read(key: &str) -> Result<Option<SecretValue>, Error> {
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };
    let target = crate::secrets::windows_target(key);
    let mut raw: *mut CREDENTIALW = std::ptr::null_mut();
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(1168) {
            Ok(None)
        } else {
            Err(error.into())
        };
    }
    if raw.is_null() {
        return Err(Error::Invalid);
    }
    let result = (|| {
        let credential = unsafe { &*raw };
        let size = credential.CredentialBlobSize as usize;
        if size == 0 || size > super::MAX_SECRET_BYTES || credential.CredentialBlob.is_null() {
            return Err(Error::Invalid);
        }
        let bytes = unsafe { std::slice::from_raw_parts(credential.CredentialBlob, size) }.to_vec();
        SecretValue::new(String::from_utf8(bytes).map_err(|_| Error::Invalid)?).map(Some)
    })();
    unsafe { CredFree(raw.cast()) };
    result
}

#[cfg(windows)]
fn native_write(key: &str, value: &SecretValue) -> Result<(), Error> {
    use windows_sys::Win32::Security::Credentials::{
        CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };
    let mut target = crate::secrets::windows_target(key);
    let mut bytes = value.as_str().as_bytes().to_vec();
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: bytes.len() as u32,
        CredentialBlob: bytes.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..Default::default()
    };
    if unsafe { CredWriteW(&credential, 0) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
