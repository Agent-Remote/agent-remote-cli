//! Only typed, bounded WireGuard values may reach the configuration renderer.

use std::net::IpAddr;

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

use crate::api::WireGuardConfigData;

pub(super) const MAX_PEERS: usize = 1024;

pub(super) fn validate(config: &WireGuardConfigData, device: &str) -> Result<()> {
    if config.device_id != device
        || !text(&config.device_id, 128)
        || !ip_or_network(&config.interface_address)
        || config.dns.len() > 16
        || config.dns.iter().any(|ip| ip.parse::<IpAddr>().is_err())
        || config.peers.len() > MAX_PEERS
    {
        bail!("wireguard_config_invalid")
    }
    for peer in &config.peers {
        if !text(&peer.node_id, 128)
            || !text(&peer.name, 256)
            || !text(&peer.region_code, 64)
            || !public_key(&peer.public_key)
            || !endpoint(&peer.endpoint)
            || peer.allowed_ips.is_empty()
            || peer.allowed_ips.len() > 256
            || peer.allowed_ips.iter().any(|ip| !ip_or_network(ip))
        {
            bail!("wireguard_config_invalid")
        }
    }
    Ok(())
}

pub(crate) fn public_key(value: &str) -> bool {
    let Ok(bytes) = STANDARD.decode(value) else {
        return false;
    };
    if STANDARD.encode(&bytes) != value {
        return false;
    }
    let Ok(bytes): Result<[u8; 32], _> = bytes.try_into() else {
        return false;
    };
    let public = x25519_dalek::PublicKey::from(bytes);
    let scalar = x25519_dalek::StaticSecret::from([0x42; 32]);
    scalar
        .diffie_hellman(&public)
        .as_bytes()
        .iter()
        .any(|&byte| byte != 0)
}

fn text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

pub(super) fn ip_or_network(value: &str) -> bool {
    let (ip, prefix) = value
        .split_once('/')
        .map_or((value, None), |(ip, prefix)| (ip, Some(prefix)));
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    prefix.is_none_or(|prefix| {
        prefix
            .parse::<u8>()
            .is_ok_and(|bits| bits <= if ip.is_ipv4() { 32 } else { 128 })
    })
}

pub(super) fn endpoint(value: &str) -> bool {
    if value.len() > 300 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if port.parse::<u16>().ok().is_none_or(|port| port == 0) {
        return false;
    }
    if let Some(ip) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return ip.parse::<std::net::Ipv6Addr>().is_ok();
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
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
