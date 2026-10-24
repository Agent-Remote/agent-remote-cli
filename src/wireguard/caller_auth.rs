//! Strict caller-authentication handshake for the future protected WireGuard broker.
//!
//! This module deliberately stops at authentication.  A valid proof establishes
//! that a holder of the broker credential answered the broker challenge for the
//! authenticated caller and request context; it does not authorize execution,
//! prove a target observation, or grant privilege.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::configuration::ConfigError;

const PROTOCOL_VERSION: u32 = 1;
const CHALLENGE_TTL_SECONDS: u64 = 30;
const DIGEST_BYTES: usize = 64;
const MAC_BYTES: usize = 32;
const HMAC_BLOCK_BYTES: usize = 64;
const MAX_USED_CHALLENGES: usize = 4096;

/// Broker-created challenge.  All fields are public protocol metadata; no
/// credential or private configuration is included.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthChallenge {
    pub protocol_version: u32,
    pub challenge_id: String,
    pub nonce: String,
    pub expires_at_unix: u64,
    pub broker_instance_sha256: String,
}

/// Caller response.  The OS transport supplies the caller identity separately;
/// the response repeats it only so the broker can bind the proof transcript and
/// reject a response copied between authenticated transports.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthResponse {
    pub protocol_version: u32,
    pub challenge_id: String,
    pub caller_sha256: String,
    pub request_sha256: String,
    pub proof_sha256: String,
}

/// In-memory replay protection owned by one broker process.  Expired entries
/// are pruned before each check; the bounded map fails closed when full rather
/// than evicting a still-valid challenge.
#[derive(Default)]
pub(crate) struct ChallengeReplayGuard {
    pending: HashMap<String, AuthChallenge>,
    used: HashMap<String, u64>,
}

impl ChallengeReplayGuard {
    pub(crate) fn register(
        &mut self,
        challenge: &AuthChallenge,
        now_unix: u64,
    ) -> Result<(), ConfigError> {
        self.prune(now_unix);
        validate_challenge(challenge, now_unix)?;
        if self.pending.contains_key(&challenge.challenge_id)
            || self.used.contains_key(&challenge.challenge_id)
        {
            return Err(ConfigError("wireguard_authentication_replayed"));
        }
        if self.pending.len() + self.used.len() >= MAX_USED_CHALLENGES {
            return Err(ConfigError("wireguard_authentication_unavailable"));
        }
        self.pending
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(())
    }

    pub(crate) fn consume(
        &mut self,
        challenge: &AuthChallenge,
        response: &AuthResponse,
        expected_caller_sha256: &str,
        expected_request_sha256: &str,
        credential: &[u8],
        now_unix: u64,
    ) -> Result<(), ConfigError> {
        self.prune(now_unix);
        validate_challenge_shape(challenge)?;
        validate_response(response)?;
        if self.used.contains_key(&challenge.challenge_id) {
            return Err(ConfigError("wireguard_authentication_replayed"));
        }
        let Some(registered) = self.pending.get(&challenge.challenge_id) else {
            return Err(ConfigError("wireguard_authentication_unknown_challenge"));
        };
        if registered != challenge {
            return Err(ConfigError("wireguard_authentication_mismatch"));
        }
        verify_response(
            challenge,
            response,
            expected_caller_sha256,
            expected_request_sha256,
            credential,
            now_unix,
        )?;
        self.pending.remove(&challenge.challenge_id);
        self.used
            .insert(challenge.challenge_id.clone(), challenge.expires_at_unix);
        Ok(())
    }

    fn prune(&mut self, now_unix: u64) {
        self.pending
            .retain(|_, challenge| challenge.expires_at_unix >= now_unix);
        self.used.retain(|_, expires| *expires >= now_unix);
    }
}

/// The successful result is intentionally content-free.  Callers must perform
/// authorization and target checks after this function returns `Ok(())`.
fn verify_response(
    challenge: &AuthChallenge,
    response: &AuthResponse,
    expected_caller_sha256: &str,
    expected_request_sha256: &str,
    credential: &[u8],
    now_unix: u64,
) -> Result<(), ConfigError> {
    validate_challenge(challenge, now_unix)?;
    validate_response(response)?;
    validate_digest(expected_caller_sha256)?;
    validate_digest(expected_request_sha256)?;
    if response.challenge_id != challenge.challenge_id
        || response.caller_sha256 != expected_caller_sha256
        || response.request_sha256 != expected_request_sha256
    {
        return Err(ConfigError("wireguard_authentication_mismatch"));
    }
    if credential.is_empty() || credential.len() > 4096 {
        return Err(ConfigError("wireguard_authentication_invalid"));
    }
    let expected = proof(
        challenge,
        expected_caller_sha256,
        expected_request_sha256,
        credential,
    );
    let supplied = decode_hex::<MAC_BYTES>(&response.proof_sha256)
        .ok_or(ConfigError("wireguard_authentication_invalid"))?;
    if !constant_time_equal(&expected, &supplied) {
        return Err(ConfigError("wireguard_authentication_failed"));
    }
    Ok(())
}

/// Build a response for the authenticated caller.  The caller identity and
/// request digest must come from independently reviewed context; this helper
/// does not derive or validate either against an OS transport.
pub(crate) fn make_response(
    challenge: &AuthChallenge,
    caller_sha256: &str,
    request_sha256: &str,
    credential: &[u8],
) -> Result<AuthResponse, ConfigError> {
    validate_challenge_shape(challenge)?;
    validate_digest(caller_sha256)?;
    validate_digest(request_sha256)?;
    if credential.is_empty() || credential.len() > 4096 {
        return Err(ConfigError("wireguard_authentication_invalid"));
    }
    let mac = proof(challenge, caller_sha256, request_sha256, credential);
    Ok(AuthResponse {
        protocol_version: PROTOCOL_VERSION,
        challenge_id: challenge.challenge_id.clone(),
        caller_sha256: caller_sha256.to_string(),
        request_sha256: request_sha256.to_string(),
        proof_sha256: encode_hex(&mac),
    })
}

/// Create a broker challenge with a bounded lifetime.  `broker_instance_sha256`
/// is an installation identity observed by the broker, never a caller-supplied
/// trust root.
pub(crate) fn new_challenge(
    broker_instance_sha256: &str,
    now_unix: u64,
) -> Result<AuthChallenge, ConfigError> {
    validate_digest(broker_instance_sha256)?;
    let expires_at_unix = now_unix
        .checked_add(CHALLENGE_TTL_SECONDS)
        .ok_or(ConfigError("wireguard_authentication_invalid"))?;
    let mut challenge_id = [0u8; 32];
    let mut nonce = [0u8; 32];
    rand_core::OsRng
        .try_fill_bytes(&mut challenge_id)
        .map_err(|_| ConfigError("wireguard_authentication_unavailable"))?;
    rand_core::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| ConfigError("wireguard_authentication_unavailable"))?;
    Ok(AuthChallenge {
        protocol_version: PROTOCOL_VERSION,
        challenge_id: encode_hex(&challenge_id),
        nonce: encode_hex(&nonce),
        expires_at_unix,
        broker_instance_sha256: broker_instance_sha256.to_string(),
    })
}

pub(crate) fn unix_time_seconds() -> Result<u64, ConfigError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| ConfigError("wireguard_authentication_unavailable"))
}

fn validate_challenge(challenge: &AuthChallenge, now_unix: u64) -> Result<(), ConfigError> {
    validate_challenge_shape(challenge)?;
    if challenge.expires_at_unix < now_unix
        || challenge.expires_at_unix - now_unix > CHALLENGE_TTL_SECONDS
    {
        return Err(ConfigError("wireguard_authentication_expired"));
    }
    Ok(())
}

fn validate_challenge_shape(challenge: &AuthChallenge) -> Result<(), ConfigError> {
    if challenge.protocol_version != PROTOCOL_VERSION
        || !is_hex_digest(&challenge.challenge_id)
        || !is_hex_digest(&challenge.nonce)
        || !is_hex_digest(&challenge.broker_instance_sha256)
    {
        return Err(ConfigError("wireguard_authentication_invalid"));
    }
    Ok(())
}

fn validate_response(response: &AuthResponse) -> Result<(), ConfigError> {
    if response.protocol_version != PROTOCOL_VERSION
        || !is_hex_digest(&response.challenge_id)
        || !is_hex_digest(&response.caller_sha256)
        || !is_hex_digest(&response.request_sha256)
        || !is_hex_digest(&response.proof_sha256)
    {
        return Err(ConfigError("wireguard_authentication_invalid"));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ConfigError> {
    if is_hex_digest(value) {
        Ok(())
    } else {
        Err(ConfigError("wireguard_authentication_invalid"))
    }
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == DIGEST_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn proof(
    challenge: &AuthChallenge,
    caller_sha256: &str,
    request_sha256: &str,
    credential: &[u8],
) -> [u8; MAC_BYTES] {
    let mut transcript = Vec::with_capacity(128 + challenge.nonce.len());
    transcript.extend_from_slice(b"agent-remote:wireguard:caller-auth:v1\0");
    transcript.extend_from_slice(challenge.challenge_id.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(challenge.nonce.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(&challenge.expires_at_unix.to_be_bytes());
    transcript.extend_from_slice(challenge.broker_instance_sha256.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(caller_sha256.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(request_sha256.as_bytes());
    hmac_sha256(credential, &transcript)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; MAC_BYTES] {
    let mut key_block = [0u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        key_block[..MAC_BYTES].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0u8; HMAC_BLOCK_BYTES];
    let mut outer = [0u8; HMAC_BLOCK_BYTES];
    for index in 0..HMAC_BLOCK_BYTES {
        inner[index] = key_block[index] ^ 0x36;
        outer[index] = key_block[index] ^ 0x5c;
    }
    let mut inner_input = Vec::with_capacity(HMAC_BLOCK_BYTES + message.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(message);
    let inner_hash = Sha256::digest(inner_input);
    let mut outer_input = Vec::with_capacity(HMAC_BLOCK_BYTES + MAC_BYTES);
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_hash);
    Sha256::digest(outer_input).into()
}

fn constant_time_equal(left: &[u8; MAC_BYTES], right: &[u8; MAC_BYTES]) -> bool {
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut output = [0u8; N];
    for (index, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex_digit(chunk[0])? << 4) | hex_digit(chunk[1])?;
    }
    Some(output)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_caller_auth.rs"]
mod tests;
