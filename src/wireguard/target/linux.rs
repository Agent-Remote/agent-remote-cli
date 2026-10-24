//! A named RTM_GETLINK query in this worker's network namespace; no shell or ip tool.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use super::{fingerprint, TargetIdentity, TargetObservation, TargetReason, TargetState};

type Failure = TargetReason;

pub(super) fn observe(name: &str, cancel: &AtomicBool) -> TargetObservation {
    match query(name, cancel) {
        Ok(Some((index, namespace))) => TargetObservation::present(
            name,
            TargetIdentity::LinuxInterface {
                name: name.into(),
                index,
                namespace,
                public_key: None,
            },
        ),
        Ok(None) => TargetObservation::empty(name, TargetState::Absent, None),
        Err(TargetReason::InterfaceNotWireguard) => TargetObservation::empty(
            name,
            TargetState::Conflict,
            Some(TargetReason::InterfaceNotWireguard),
        ),
        Err(reason) => TargetObservation::unknown(name, reason),
    }
}

fn namespace() -> Result<String, Failure> {
    let file =
        File::open("/proc/thread-self/ns/net").map_err(|_| TargetReason::NativeQueryFailed)?;
    let identity =
        crate::platform::file_identity(&file).map_err(|_| TargetReason::NativeQueryFailed)?;
    Ok(fingerprint(
        b"agent-remote:wireguard:netns:v1\0",
        identity.as_bytes(),
    ))
}

pub(super) fn scope_digest(name: &str) -> Result<String, Failure> {
    let namespace = namespace()?;
    let mut bytes = Vec::with_capacity(namespace.len() + name.len() + 1);
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(name.as_bytes());
    Ok(fingerprint(b"agent-remote:wireguard:scope:v1\0", &bytes))
}

fn query(name: &str, cancel: &AtomicBool) -> Result<Option<(u32, String)>, Failure> {
    let ns = namespace()?;
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(TargetReason::NativeQueryFailed);
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            std::mem::size_of_val(&address) as _,
        )
    } < 0
    {
        return Err(TargetReason::NativeQueryFailed);
    }
    let request = request(name);
    if unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            std::ptr::from_ref(&address).cast(),
            std::mem::size_of_val(&address) as _,
        )
    } != request.len() as isize
    {
        return Err(TargetReason::NativeQueryFailed);
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut total = 0usize;
    loop {
        if super::canceled(cancel).is_err() || Instant::now() >= deadline {
            return Err(TargetReason::NativeQueryFailed);
        }
        let mut event = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut event, 1, 20) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(TargetReason::NativeQueryFailed);
        }
        if ready == 0 {
            continue;
        }
        if event.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(TargetReason::NativeQueryFailed);
        }
        let mut bytes = vec![0u8; 65536];
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&source) as libc::socklen_t;
        let length = unsafe {
            libc::recvfrom(
                socket.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_TRUNC,
                std::ptr::from_mut(&mut source).cast(),
                &mut size,
            )
        };
        if length < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(TargetReason::NativeQueryFailed);
        }
        if length == 0
            || length as usize > bytes.len()
            || source.nl_pid != 0
            || source.nl_groups != 0
            || size as usize != std::mem::size_of_val(&source)
        {
            return Err(TargetReason::NativeQueryFailed);
        }
        total += length as usize;
        if total > 1024 * 1024 {
            return Err(TargetReason::NativeQueryFailed);
        }
        bytes.truncate(length as usize);
        if let Some(link) = response(&bytes, name)? {
            if namespace()? != ns {
                return Err(TargetReason::TargetChanged);
            }
            return Ok(link.map(|index| (index, ns)));
        }
    }
}

fn request(name: &str) -> Vec<u8> {
    let attr_length = 4 + name.len() + 1;
    let length = 32 + align(attr_length);
    let mut bytes = vec![0u8; length];
    bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
    bytes[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
    bytes[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_ne_bytes());
    bytes[16] = libc::AF_UNSPEC as u8;
    bytes[32..34].copy_from_slice(&(attr_length as u16).to_ne_bytes());
    bytes[34..36].copy_from_slice(&libc::IFLA_IFNAME.to_ne_bytes());
    bytes[36..36 + name.len()].copy_from_slice(name.as_bytes());
    bytes
}

fn align(length: usize) -> usize {
    (length + 3) & !3
}
fn u16_at(bytes: &[u8], index: usize) -> Result<u16, Failure> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(index..index + 2)
            .ok_or(TargetReason::NativeQueryFailed)?
            .try_into()
            .map_err(|_| TargetReason::NativeQueryFailed)?,
    ))
}
fn u32_at(bytes: &[u8], index: usize) -> Result<u32, Failure> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(index..index + 4)
            .ok_or(TargetReason::NativeQueryFailed)?
            .try_into()
            .map_err(|_| TargetReason::NativeQueryFailed)?,
    ))
}

// None means only control messages; Some(None) is an explicit kernel ENODEV.
fn response(mut bytes: &[u8], name: &str) -> Result<Option<Option<u32>>, Failure> {
    let mut found = None;
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(TargetReason::NativeQueryFailed);
        }
        let length = u32_at(bytes, 0)? as usize;
        if length < 16
            || length > bytes.len()
            || align(length) > bytes.len()
            || u32_at(bytes, 8)? != 1
        {
            return Err(TargetReason::NativeQueryFailed);
        }
        let message = &bytes[..length];
        let result = match u16_at(message, 4)? as i32 {
            libc::NLMSG_ERROR => {
                let code = u32_at(message, 16)? as i32;
                if code == -libc::ENODEV || code == -libc::ENXIO {
                    Some(None)
                } else if code == 0 {
                    None
                } else {
                    return Err(TargetReason::NativeQueryFailed);
                }
            }
            kind if kind == i32::from(libc::RTM_NEWLINK) => Some(Some(link(message, name)?)),
            libc::NLMSG_NOOP => None,
            _ => return Err(TargetReason::NativeQueryFailed),
        };
        if let Some(result) = result {
            if found.is_some() {
                return Err(TargetReason::NativeQueryFailed);
            }
            found = Some(result);
        }
        bytes = &bytes[align(length)..];
    }
    Ok(found)
}

fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, Failure> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let length = u16_at(bytes, 0)? as usize;
        if length < 4 || align(length) > bytes.len() {
            return Err(TargetReason::NativeQueryFailed);
        }
        result.push((u16_at(bytes, 2)? & 0x3fff, &bytes[4..length]));
        bytes = &bytes[align(length)..];
    }
    Ok(result)
}

fn text(bytes: &[u8]) -> Result<&str, Failure> {
    let bytes = bytes
        .strip_suffix(&[0])
        .ok_or(TargetReason::NativeQueryFailed)?;
    if bytes.contains(&0) {
        return Err(TargetReason::NativeQueryFailed);
    }
    std::str::from_utf8(bytes).map_err(|_| TargetReason::NativeQueryFailed)
}

fn link(bytes: &[u8], name: &str) -> Result<u32, Failure> {
    if bytes.len() < 32 {
        return Err(TargetReason::NativeQueryFailed);
    }
    let index = u32_at(bytes, 20)?;
    if index == 0 || index > i32::MAX as u32 {
        return Err(TargetReason::NativeQueryFailed);
    }
    let (mut found_name, mut found_kind) = (None, None);
    for (kind, value) in attributes(&bytes[32..])? {
        if kind == libc::IFLA_IFNAME {
            if found_name.replace(text(value)?).is_some() {
                return Err(TargetReason::NativeQueryFailed);
            }
        } else if kind == libc::IFLA_LINKINFO {
            for (kind, value) in attributes(value)? {
                if kind == libc::IFLA_INFO_KIND && found_kind.replace(text(value)?).is_some() {
                    return Err(TargetReason::NativeQueryFailed);
                }
            }
        }
    }
    if found_name != Some(name) {
        return Err(TargetReason::NativeQueryFailed);
    }
    if found_kind != Some("wireguard") {
        return Err(TargetReason::InterfaceNotWireguard);
    }
    Ok(index)
}

#[cfg(test)]
#[path = "../../../tests/unit/src/wireguard_target_linux.rs"]
mod tests;
