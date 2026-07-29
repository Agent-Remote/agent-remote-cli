use std::env;
use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use std::path::Path;

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn tunnel_arguments(action: &str, config: &Path, dry_run: bool) -> Option<Vec<OsString>> {
    if dry_run || !matches!(action, "up" | "down") {
        return None;
    }
    Some(vec![
        OsString::from(action),
        OsString::from("--config"),
        config.as_os_str().to_owned(),
    ])
}

pub fn is_elevated() -> Result<bool> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect Windows privileges");
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned_length = 0;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned_length,
        )
    };
    let token_error = (result == 0).then(std::io::Error::last_os_error);
    unsafe { CloseHandle(token) };
    if let Some(error) = token_error {
        return Err(error).context("failed to inspect Windows privileges");
    }
    Ok(elevation.TokenIsElevated != 0)
}

pub fn relaunch(arguments: &[OsString]) -> Result<()> {
    let executable = env::current_exe().context("failed to locate WireGuard helper")?;
    let verb = wide_null(OsStr::new("runas"))?;
    let executable = wide_null(executable.as_os_str())?;
    let parameters = command_line(arguments)?;
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };

    // The process handle preserves synchronous CLI behavior across the UAC boundary.
    if unsafe { ShellExecuteExW(&mut execute) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("administrator approval was cancelled or failed");
    }
    if execute.hProcess.is_null() {
        bail!("Windows did not return the elevated WireGuard process handle");
    }

    let wait_result = unsafe { WaitForSingleObject(execute.hProcess, INFINITE) };
    if wait_result != WAIT_OBJECT_0 {
        unsafe { CloseHandle(execute.hProcess) };
        bail!("failed while waiting for the elevated WireGuard command");
    }
    let mut exit_code = 0_u32;
    let got_exit_code = unsafe { GetExitCodeProcess(execute.hProcess, &mut exit_code) };
    let exit_code_error = (got_exit_code == 0).then(std::io::Error::last_os_error);
    unsafe { CloseHandle(execute.hProcess) };
    if let Some(error) = exit_code_error {
        return Err(error).context("failed to read the elevated WireGuard command exit code");
    }
    if exit_code != 0 {
        bail!("elevated WireGuard command exited with code {exit_code}");
    }
    Ok(())
}

fn command_line(arguments: &[OsString]) -> Result<Vec<u16>> {
    let mut command_line = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 {
            command_line.push(b' ' as u16);
        }
        command_line.extend(quote_argument(argument.as_os_str())?);
    }
    command_line.push(0);
    Ok(command_line)
}

fn quote_argument(argument: &OsStr) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let units: Vec<u16> = argument.encode_wide().collect();
    if units.contains(&0) {
        bail!("WireGuard command arguments cannot contain NUL characters");
    }
    let mut quoted = vec![b'"' as u16];
    let mut backslashes = 0;
    for unit in units {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            quoted.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
        } else {
            quoted.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
        }
        backslashes = 0;
        quoted.push(unit);
    }
    quoted.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    quoted.push(b'"' as u16);
    Ok(quoted)
}

fn wide_null(value: &OsStr) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut units: Vec<u16> = value.encode_wide().collect();
    if units.contains(&0) {
        bail!("Windows executable paths cannot contain NUL characters");
    }
    units.push(0);
    Ok(units)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{command_line, tunnel_arguments};

    #[test]
    fn elevation_targets_tunnel_changes() {
        let config = PathBuf::from(r#"C:\Program Files\Agent Remote\tunnel.conf"#);
        assert!(tunnel_arguments("check", &config, false).is_none());
        assert!(tunnel_arguments("status", &config, false).is_none());
        assert!(tunnel_arguments("up", &config, true).is_none());
        assert_eq!(
            tunnel_arguments("down", &config, false),
            Some(vec![
                OsString::from("down"),
                OsString::from("--config"),
                config.into_os_string(),
            ])
        );
    }

    #[test]
    fn elevation_command_line_quotes_paths() {
        let command_line = command_line(&[
            OsString::from("up"),
            OsString::from("--config"),
            OsString::from(r#"C:\Program Files\Agent "Remote"\tunnel.conf"#),
        ])
        .unwrap();
        let rendered = String::from_utf16(&command_line[..command_line.len() - 1]).unwrap();
        assert_eq!(
            rendered,
            r#""up" "--config" "C:\Program Files\Agent \"Remote\"\tunnel.conf""#
        );
    }
}
