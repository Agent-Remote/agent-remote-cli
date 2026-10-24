use crate::account_defaults::Context;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub tool: String,
    pub include_resume_history: bool,
    pub exclude_skills: bool,
}
impl Selection {
    pub fn valid(&self) -> bool {
        self.tool == "claude"
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub mode: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct Discovery {
    pub source_home: PathBuf,
    pub selection: Selection,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub context: Context,
    pub account_id: String,
    pub selection: Selection,
    pub source_home: PathBuf,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub manifest: Vec<ManifestEntry>,
    pub total_bytes: u64,
    pub source_fingerprint: String,
    pub intent_fingerprint: String,
    pub digest: String,
}
#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    pub http_status: Option<u16>,
}
impl Error {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            http_status: None,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn source_error(_: impl std::fmt::Display) -> Error {
    Error::new("account_import_source_invalid")
}
pub(crate) fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
pub fn valid_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| !id.is_nil() && id.hyphenated().to_string() == value)
}
