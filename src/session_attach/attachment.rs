//! Identity-bound transfer frames for exact Claude session attachments.
//!
//! This module only validates the wire contract.  The transfer channel is not
//! enabled by exact session attach until Server and Node advertise and enforce
//! the same contract.  In particular, callers must never reuse the legacy
//! receiver: it authenticates the SSH account but does not prove the expected
//! device and the actual SSH key for this session.

use serde::Deserialize;

pub const VERSION: u32 = 1;
pub const MAX_BATCH_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_NAME_BYTES: usize = 255;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenFrame {
    pub version: u32,
    pub operation: OpenOperation,
    pub session_id: String,
    pub expected_device_id: String,
    pub lease_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenOperation {
    Open,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UploadFrame {
    pub version: u32,
    pub operation: UploadOperation,
    pub session_id: String,
    pub expected_device_id: String,
    pub lease_id: String,
    pub batch_id: String,
    pub kind: PayloadKind,
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UploadOperation {
    Upload,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    File,
    Image,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CleanupFrame {
    pub version: u32,
    pub operation: CleanupOperation,
    pub session_id: String,
    pub expected_device_id: String,
    pub lease_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CleanupOperation {
    Cleanup,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CleanupReceipt {
    pub version: u32,
    pub operation: ReceiptOperation,
    pub session_id: String,
    pub expected_device_id: String,
    pub lease_id: String,
    pub status: CleanupStatus,
    pub removed_batches: u32,
    pub receipt_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOperation {
    CleanupReceipt,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Cleaned,
    Pending,
    Unknown,
    Rejected,
}

pub fn validate_open(frame: &OpenFrame, session_id: &str, device_id: &str, lease_id: &str) -> bool {
    frame.version == VERSION
        && frame.session_id == session_id
        && frame.expected_device_id == device_id
        && frame.lease_id == lease_id
        && canonical_uuid(session_id)
        && canonical_uuid(device_id)
        && canonical_uuid(&frame.lease_id)
}

pub fn validate_upload(
    frame: &UploadFrame,
    session_id: &str,
    device_id: &str,
    lease_id: &str,
) -> bool {
    frame.version == VERSION
        && frame.session_id == session_id
        && frame.expected_device_id == device_id
        && frame.lease_id == lease_id
        && canonical_uuid(session_id)
        && canonical_uuid(device_id)
        && canonical_uuid(&frame.lease_id)
        && canonical_uuid(&frame.batch_id)
        && !frame.name.is_empty()
        && frame.name.len() <= MAX_NAME_BYTES
        && !frame.name.contains('/')
        && !frame.name.contains('\\')
        && frame.name != "."
        && frame.name != ".."
        && !frame.name.chars().any(char::is_control)
        && frame.size > 0
        && frame.size <= MAX_BATCH_BYTES
        && frame.sha256.len() == 64
        && frame.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn validate_cleanup(
    frame: &CleanupFrame,
    session_id: &str,
    device_id: &str,
    lease_id: &str,
) -> bool {
    frame.version == VERSION
        && frame.session_id == session_id
        && frame.expected_device_id == device_id
        && frame.lease_id == lease_id
        && canonical_uuid(session_id)
        && canonical_uuid(device_id)
        && canonical_uuid(&frame.lease_id)
}

pub fn validate_receipt(
    receipt: &CleanupReceipt,
    session_id: &str,
    device_id: &str,
    lease_id: &str,
) -> bool {
    receipt.version == VERSION
        && receipt.session_id == session_id
        && receipt.expected_device_id == device_id
        && receipt.lease_id == lease_id
        && canonical_uuid(session_id)
        && canonical_uuid(device_id)
        && canonical_uuid(&receipt.lease_id)
        && canonical_uuid(&receipt.receipt_id)
        && receipt.removed_batches <= 32
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|uuid| uuid.to_string() == value && uuid != uuid::Uuid::nil())
}

#[cfg(test)]
#[path = "../../tests/unit/src/session_attach/attachment.rs"]
mod tests;
