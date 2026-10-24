//! Bounded, non-executing parser for the documented WireGuard configuration subset.

use std::collections::HashSet;
use std::net::IpAddr;

use base64::{engine::general_purpose::STANDARD, Engine};

use super::validation;

pub(super) struct Summary {
    pub public_key: String,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: Option<u16>,
    pub peer_count: usize,
    pub unsupported_directives: Vec<&'static str>,
}

#[derive(Default)]
struct Section {
    fields: HashSet<String>,
    public_key: Option<String>,
    allowed_ips: usize,
}

const UNSUPPORTED: [&str; 6] = [
    "PreUp",
    "PostUp",
    "PreDown",
    "PostDown",
    "SaveConfig",
    "Table",
];

pub(super) fn parse(bytes: &[u8]) -> Result<Summary, ()> {
    let input = std::str::from_utf8(bytes).map_err(|_| ())?;
    if input
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(());
    }
    if bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
    {
        return Err(());
    }
    let mut summary = Summary {
        public_key: String::new(),
        addresses: vec![],
        dns: vec![],
        mtu: None,
        peer_count: 0,
        unsupported_directives: vec![],
    };
    let mut interface_seen = false;
    let mut interface = Section::default();
    let mut peer: Option<Section> = None;
    let mut public_keys = HashSet::new();
    for raw in input.lines() {
        if raw.len() > 64 * 1024 {
            return Err(());
        }
        let line = raw.split_once('#').map_or(raw, |(before, _)| before).trim();
        if line.is_empty() {
            continue;
        }
        match line {
            "[Interface]" if !interface_seen => {
                interface_seen = true;
                continue;
            }
            "[Peer]" if interface_seen => {
                if let Some(previous) = peer.take() {
                    finish_peer(previous, &mut public_keys)?;
                }
                summary.peer_count += 1;
                if summary.peer_count > validation::MAX_PEERS {
                    return Err(());
                }
                peer = Some(Section::default());
                continue;
            }
            _ if line.starts_with('[') || !interface_seen => return Err(()),
            _ => {}
        }
        let (name, value) = line.split_once('=').ok_or(())?;
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() || value.is_empty() {
            return Err(());
        }
        if let Some(peer) = &mut peer {
            let repeatable = name == "AllowedIPs";
            if !repeatable && !peer.fields.insert(name.to_owned()) {
                return Err(());
            }
            match name {
                "PublicKey" if validation::public_key(value) => {
                    peer.public_key = Some(value.to_owned())
                }
                "PresharedKey" if key(value) => {}
                "Endpoint" if validation::endpoint(value) => {}
                "PersistentKeepalive" if decimal(value) && value.parse::<u16>().is_ok() => {}
                "AllowedIPs" => {
                    let addresses = ip_list(value, 256)?;
                    peer.allowed_ips += addresses.len();
                    if peer.allowed_ips > 256 {
                        return Err(());
                    }
                }
                _ => return Err(()),
            }
        } else {
            if let Some(directive) = UNSUPPORTED.iter().copied().find(|item| *item == name) {
                if matches!(directive, "SaveConfig" | "Table")
                    && !interface.fields.insert(name.to_owned())
                {
                    return Err(());
                }
                if !summary.unsupported_directives.contains(&directive) {
                    summary.unsupported_directives.push(directive);
                }
                continue;
            }
            let repeatable = matches!(name, "Address" | "DNS");
            if !repeatable && !interface.fields.insert(name.to_owned()) {
                return Err(());
            }
            match name {
                "PrivateKey" if key(value) => {
                    summary.public_key = super::public_key_from_private(value).map_err(|_| ())?;
                }
                "Address" => {
                    summary.addresses.extend(ip_list(value, 64)?);
                    if summary.addresses.len() > 64 {
                        return Err(());
                    }
                }
                "DNS" => {
                    for value in value.split(',') {
                        summary
                            .dns
                            .push(value.trim().parse::<IpAddr>().map_err(|_| ())?.to_string());
                        if summary.dns.len() > 16 {
                            return Err(());
                        }
                    }
                }
                "MTU" => {
                    if !decimal(value) {
                        return Err(());
                    }
                    let mtu = value.parse::<u16>().map_err(|_| ())?;
                    if mtu < 576 {
                        return Err(());
                    }
                    summary.mtu = Some(mtu);
                }
                "ListenPort" if decimal(value) && value.parse::<u16>().is_ok() => {}
                "FwMark" if fwmark(value) => {}
                _ => return Err(()),
            }
        }
    }
    if let Some(peer) = peer {
        finish_peer(peer, &mut public_keys)?;
    }
    if !interface_seen || !interface.fields.contains("PrivateKey") || summary.addresses.is_empty() {
        return Err(());
    }
    summary
        .unsupported_directives
        .sort_unstable_by_key(|name| UNSUPPORTED.iter().position(|candidate| candidate == name));
    Ok(summary)
}

fn finish_peer(peer: Section, keys: &mut HashSet<String>) -> Result<(), ()> {
    let public = peer.public_key.ok_or(())?;
    if peer.allowed_ips == 0 || !keys.insert(public) {
        return Err(());
    }
    Ok(())
}

fn key(value: &str) -> bool {
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    if STANDARD.decode_slice(value, &mut *bytes).ok() != Some(32) {
        return false;
    }
    let canonical = zeroize::Zeroizing::new(STANDARD.encode(bytes.as_slice()));
    canonical.as_str() == value
}

fn fwmark(value: &str) -> bool {
    value == "off"
        || value.strip_prefix("0x").map_or_else(
            || decimal(value) && value.parse::<u32>().is_ok(),
            |hex| {
                !hex.is_empty()
                    && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && u32::from_str_radix(hex, 16).is_ok()
            },
        )
}

fn decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn ip_list(value: &str, maximum: usize) -> Result<Vec<String>, ()> {
    let mut addresses = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        let normalized = if let Some((ip, prefix)) = item.split_once('/') {
            if !decimal(prefix) {
                return Err(());
            }
            let ip = ip.parse::<IpAddr>().map_err(|_| ())?;
            let prefix = prefix.parse::<u8>().map_err(|_| ())?;
            if prefix > if ip.is_ipv4() { 32 } else { 128 } {
                return Err(());
            }
            format!("{ip}/{prefix}")
        } else {
            item.parse::<IpAddr>().map_err(|_| ())?.to_string()
        };
        addresses.push(normalized);
        if addresses.len() > maximum {
            return Err(());
        }
    }
    Ok(addresses)
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_inspection_parser.rs"]
mod tests;
