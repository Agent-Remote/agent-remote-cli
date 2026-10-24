//! Local SCM observation only. No service mutation, shell, installer or elevation.

use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::AtomicBool;

use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_DOES_NOT_EXIST,
};
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

use super::{TargetIdentity, TargetObservation, TargetReason, TargetState};
use crate::wireguard::publication;
use sha2::{Digest, Sha256};

struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}
struct Local(*mut core::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

pub(super) fn observe(name: &str, cancel: &AtomicBool) -> TargetObservation {
    if super::canceled(cancel).is_err() {
        return TargetObservation::unknown(name, TargetReason::NativeQueryFailed);
    }
    match query(name) {
        Ok(Some(identity)) => TargetObservation::present(name, identity),
        Ok(None) => TargetObservation::empty(name, TargetState::Absent, None),
        Err(TargetReason::ServiceInvalid) => TargetObservation::empty(
            name,
            TargetState::Conflict,
            Some(TargetReason::ServiceInvalid),
        ),
        Err(reason) => TargetObservation::unknown(name, reason),
    }
}

/// Return the broker-owned target fence for a logical WireGuard service.
///
/// The privileged service recomputes this value immediately before invoking
/// WireGuard. It binds the requested logical name to the complete SCM
/// observation (including service/config identity when present), so a service
/// created, removed, or replaced after the desktop plan cannot be silently
/// adopted by an old request.
pub(super) fn scope_digest(name: &str) -> Result<String, TargetReason> {
    let cancel = AtomicBool::new(false);
    let observation = observe(name, &cancel);
    let bytes = serde_json::to_vec(&observation).map_err(|_| TargetReason::NativeQueryFailed)?;
    let mut digest = Sha256::new();
    digest.update(b"agent-remote:wireguard:scope:v1\0");
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

fn query(name: &str) -> Result<Option<TargetIdentity>, TargetReason> {
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(TargetReason::NativeQueryFailed);
    }
    let manager = Service(manager);
    let service_name = format!("WireGuardTunnel${name}");
    let wide: Vec<u16> = service_name.encode_utf16().chain(Some(0)).collect();
    let raw = unsafe {
        OpenServiceW(
            manager.0,
            wide.as_ptr(),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    };
    if raw.is_null() {
        return if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
            Ok(None)
        } else {
            Err(TargetReason::NativeQueryFailed)
        };
    }
    let service = Service(raw);
    let mut size = 0u32;
    if unsafe { QueryServiceConfigW(service.0, null_mut(), 0, &mut size) } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || !(std::mem::size_of::<QUERY_SERVICE_CONFIGW>() as u32..=65536).contains(&size)
    {
        return Err(TargetReason::NativeQueryFailed);
    }
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    let allocated = buffer.len() * std::mem::size_of::<usize>();
    if unsafe {
        QueryServiceConfigW(
            service.0,
            buffer.as_mut_ptr().cast(),
            allocated as u32,
            &mut size,
        )
    } == 0
    {
        return Err(TargetReason::NativeQueryFailed);
    }
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    if config.dwServiceType != SERVICE_WIN32_OWN_PROCESS || config.dwStartType > 4 {
        return Err(TargetReason::ServiceInvalid);
    }
    let command = buffer_string(config.lpBinaryPathName, &buffer, 32768)?;
    let account = buffer_string(config.lpServiceStartName, &buffer, 512)?;
    if account.is_empty() || account.len() > 512 || account.chars().any(char::is_control) {
        return Err(TargetReason::ServiceInvalid);
    }
    let (binary_path, config_path) = command_paths(&command)?;
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut length = 0u32;
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            std::ptr::from_mut(&mut status).cast(),
            std::mem::size_of_val(&status) as u32,
            &mut length,
        )
    } == 0
    {
        return Err(TargetReason::NativeQueryFailed);
    }
    if !(1..=7).contains(&status.dwCurrentState)
        || status.dwServiceType != SERVICE_WIN32_OWN_PROCESS
    {
        return Err(TargetReason::ServiceInvalid);
    }
    let config_identity = config_identity(&config_path);
    Ok(Some(TargetIdentity::WindowsService {
        service_name,
        binary_path,
        config_path,
        config_identity,
        service_state: status.dwCurrentState,
        start_type: config.dwStartType,
        account,
        public_key: None,
    }))
}

fn buffer_string(
    pointer: *const u16,
    buffer: &[usize],
    limit: usize,
) -> Result<String, TargetReason> {
    let start = buffer.as_ptr() as usize;
    let end = start + std::mem::size_of_val(buffer);
    let address = pointer as usize;
    if pointer.is_null() || address < start || address >= end || !address.is_multiple_of(2) {
        return Err(TargetReason::ServiceInvalid);
    }
    let count = ((end - address) / 2).min(limit + 1);
    let slice = unsafe { std::slice::from_raw_parts(pointer, count) };
    let length = slice
        .iter()
        .position(|value| *value == 0)
        .ok_or(TargetReason::ServiceInvalid)?;
    if length > limit {
        return Err(TargetReason::ServiceInvalid);
    }
    String::from_utf16(&slice[..length]).map_err(|_| TargetReason::ServiceInvalid)
}

fn command_paths(command: &str) -> Result<(PathBuf, PathBuf), TargetReason> {
    if command.is_empty() || command.len() > 32768 || command.chars().any(char::is_control) {
        return Err(TargetReason::ServiceInvalid);
    }
    let wide: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();
    let mut count = 0;
    let raw = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    if raw.is_null() {
        return Err(TargetReason::ServiceInvalid);
    }
    let _allocation = Local(raw.cast());
    if count != 3 {
        return Err(TargetReason::ServiceInvalid);
    }
    let argv = unsafe { std::slice::from_raw_parts(raw, 3) };
    let strings: Vec<String> = argv
        .iter()
        .map(|pointer| {
            // CommandLineToArgvW guarantees terminated strings in its owned result.
            let mut len = 0;
            while len <= 32768 && unsafe { *(*pointer).add(len) } != 0 {
                len += 1;
            }
            if len > 32768 {
                return Err(TargetReason::ServiceInvalid);
            }
            String::from_utf16(unsafe { std::slice::from_raw_parts(*pointer, len) })
                .map_err(|_| TargetReason::ServiceInvalid)
        })
        .collect::<Result<_, _>>()?;
    if strings[1] != "/tunnelservice" {
        return Err(TargetReason::ServiceInvalid);
    }
    let parse = |text: &str| {
        let path = Path::new(text);
        if !path.is_absolute() {
            return Err(TargetReason::ServiceInvalid);
        }
        publication::absolute(path).map_err(|_| TargetReason::ServiceInvalid)
    };
    let binary = parse(&strings[0])?;
    if !binary
        .extension()
        .and_then(|v| v.to_str())
        .is_some_and(|v| v.eq_ignore_ascii_case("exe"))
    {
        return Err(TargetReason::ServiceInvalid);
    }
    Ok((binary, parse(&strings[2])?))
}

fn config_identity(path: &Path) -> Option<String> {
    let parent = path.parent()?;
    let name = path.file_name()?.to_str()?;
    let directory = publication::open_directory(parent).ok()?;
    let file = publication::open_regular(&directory, name).ok()??;
    publication::snapshot_identity(&file).ok()
}

#[cfg(test)]
#[path = "../../../tests/unit/src/wireguard_target_windows.rs"]
mod tests;
