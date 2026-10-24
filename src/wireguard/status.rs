//! Read-only local observations. Only strictly parsed public fields leave Rust.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;

use super::configuration::ConfigError;
use super::{probe, tools};
use crate::config::AppPaths;

#[derive(Serialize)]
pub struct StatusResult {
    pub home: PathBuf,
    pub platform: String,
    pub elevation: &'static str,
    pub tool: tools::ToolInfo,
    pub state: &'static str,
    pub interfaces: Vec<Interface>,
}

#[derive(Serialize)]
pub struct Interface {
    pub name: String,
    pub public_key: Option<String>,
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: Vec<Peer>,
}

#[derive(Serialize)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub persistent_keepalive: u16,
}

pub async fn inspect(
    paths: &AppPaths,
    cancel: Arc<AtomicBool>,
) -> Result<StatusResult, ConfigError> {
    if cancel.load(Ordering::Acquire) {
        return Err(ConfigError("canceled"));
    }
    let home =
        crate::setup::absolute_home(paths).map_err(|_| ConfigError("configuration_unavailable"))?;
    let platform =
        crate::platform::current_platform().map_err(|_| ConfigError("unsupported_platform"))?;
    let tool = tools::find_wg(paths);
    let mut result = StatusResult {
        home,
        platform,
        elevation: tools::elevation(),
        tool,
        state: "query_failed",
        interfaces: Vec::new(),
    };
    match result.tool.state {
        "missing" => result.state = "tool_missing",
        "not_executable" => result.state = "tool_not_executable",
        "available" => {
            let path = result
                .tool
                .path
                .as_ref()
                .ok_or(ConfigError("wireguard_status_invalid"))?;
            match probe::run(path, &cancel).await {
                Ok(bytes) => match parse(&bytes.0) {
                    Ok(interfaces) => {
                        result.state = "observed";
                        result.interfaces = interfaces;
                    }
                    Err(()) => result.state = "invalid_output",
                },
                Err(probe::ProbeError::Failed) => result.state = "query_failed",
                Err(probe::ProbeError::TimedOut) => result.state = "timed_out",
                Err(probe::ProbeError::OutputTooLarge) => result.state = "output_too_large",
                Err(probe::ProbeError::Canceled) => return Err(ConfigError("canceled")),
            }
        }
        _ => return Err(ConfigError("wireguard_status_invalid")),
    }
    if cancel.load(Ordering::Acquire) {
        return Err(ConfigError("canceled"));
    }
    Ok(result)
}

fn parse(bytes: &[u8]) -> Result<Vec<Interface>, ()> {
    if bytes.len() > probe::MAX_OUTPUT || (!bytes.is_empty() && !bytes.ends_with(b"\n")) {
        return Err(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut indices = HashMap::new();
    let mut peer_keys = HashSet::new();
    let (mut total_peers, mut total_cidrs) = (0usize, 0usize);
    for line in text.split_terminator('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let fields: Vec<_> = line.split('\t').take(10).collect();
        match fields.as_slice() {
            [name, private_key, public_key, listen_port, fwmark] => {
                if name.is_empty()
                    || name.len() > 255
                    || name.chars().any(char::is_control)
                    || interfaces.len() >= 64
                    || indices.contains_key(*name)
                    || !key_or_none(private_key)
                {
                    return Err(());
                }
                let public_key = optional_key(public_key)?;
                let listen_port = number(listen_port)?.try_into().map_err(|_| ())?;
                let fwmark = if *fwmark == "off" {
                    0
                } else if let Some(hex) = fwmark.strip_prefix("0x") {
                    if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return Err(());
                    }
                    u32::from_str_radix(hex, 16).map_err(|_| ())?
                } else {
                    number(fwmark)?.try_into().map_err(|_| ())?
                };
                indices.insert(*name, interfaces.len());
                interfaces.push(Interface {
                    name: name.to_string(),
                    public_key,
                    listen_port,
                    fwmark,
                    peers: Vec::new(),
                });
            }
            [name, public_key, psk, endpoint, allowed_ips, handshake, received, sent, keepalive] => {
                let index = *indices.get(*name).ok_or(())?;
                if !valid_public_key(public_key)
                    || !key_or_none(psk)
                    || total_peers >= 1024
                    || !peer_keys.insert((index, *public_key))
                {
                    return Err(());
                }
                let endpoint = if *endpoint == "(none)" {
                    None
                } else {
                    if !valid_endpoint(endpoint) {
                        return Err(());
                    }
                    Some(endpoint.to_string())
                };
                let allowed_ips = if *allowed_ips == "(none)" {
                    Vec::new()
                } else {
                    let values: Vec<_> = allowed_ips.split(',').take(257).collect();
                    if values.len() > 256 || values.iter().any(|value| !cidr(value)) {
                        return Err(());
                    }
                    values.into_iter().map(str::to_owned).collect::<Vec<_>>()
                };
                total_cidrs += allowed_ips.len();
                if total_cidrs > 4096 {
                    return Err(());
                }
                let latest_handshake = number(handshake)?;
                if latest_handshake > 253_402_300_799 {
                    return Err(());
                }
                let persistent_keepalive = if *keepalive == "off" {
                    0
                } else {
                    number(keepalive)?.try_into().map_err(|_| ())?
                };
                interfaces[index].peers.push(Peer {
                    public_key: public_key.to_string(),
                    endpoint,
                    allowed_ips,
                    latest_handshake,
                    received_bytes: number(received)?,
                    sent_bytes: number(sent)?,
                    persistent_keepalive,
                });
                total_peers += 1;
            }
            _ => return Err(()),
        }
    }
    Ok(interfaces)
}

fn number(value: &str) -> Result<u64, ()> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    value.parse().map_err(|_| ())
}

fn key(value: &str) -> bool {
    if value.len() != 44 {
        return false;
    }
    STANDARD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && STANDARD.encode(&bytes) == value)
}

fn valid_public_key(value: &str) -> bool {
    key(value)
        && STANDARD
            .decode(value)
            .is_ok_and(|bytes| bytes.iter().any(|byte| *byte != 0))
}

fn key_or_none(value: &str) -> bool {
    value == "(none)" || key(value)
}

fn optional_key(value: &str) -> Result<Option<String>, ()> {
    if value == "(none)" {
        Ok(None)
    } else if valid_public_key(value) {
        Ok(Some(value.to_owned()))
    } else {
        Err(())
    }
}

fn cidr(value: &str) -> bool {
    let Some((ip, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    number(prefix).is_ok_and(|prefix| prefix <= if ip.is_ipv4() { 32 } else { 128 })
}

fn valid_endpoint(value: &str) -> bool {
    if value.len() > 320 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if !number(port).is_ok_and(|port| (1..=u64::from(u16::MAX)).contains(&port)) {
        return false;
    }
    if let Some(ip) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        let (ip, scope) = ip
            .split_once('%')
            .map_or((ip, None), |(ip, scope)| (ip, Some(scope)));
        return ip.parse::<Ipv6Addr>().is_ok()
            && scope.is_none_or(|scope| {
                !scope.is_empty()
                    && scope.len() <= 64
                    && scope
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            });
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_status.rs"]
mod tests;
