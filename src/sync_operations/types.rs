use crate::{account_defaults::Context, api::SyncSessionData};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub local_path: String,
    pub project_key: String,
    #[serde(deserialize_with = "required_option")]
    pub workspace_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub sync_session_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub fingerprint: Option<String>,
}
#[derive(Clone, Serialize)]
pub struct Sync {
    pub id: String,
    pub workspace_id: String,
    pub node_id: Option<String>,
    pub local_path: String,
    pub remote_path: String,
    pub status: String,
    pub conflict_status: String,
    pub sync_mode: String,
    pub sync_git: bool,
    pub exclude: Vec<String>,
    pub mutagen_session_id: Option<String>,
    pub remote_endpoint: Option<String>,
}
impl From<&SyncSessionData> for Sync {
    fn from(s: &SyncSessionData) -> Self {
        Self {
            id: s.id.clone(),
            workspace_id: s.workspace_id.clone(),
            node_id: s.node_id.clone(),
            local_path: s.local_path.clone(),
            remote_path: s.remote_path.clone(),
            status: s.status.clone(),
            conflict_status: s.conflict_status.clone(),
            sync_mode: s.sync_mode.clone(),
            sync_git: s.sync_git,
            exclude: s.exclude.clone(),
            mutagen_session_id: s.mutagen_session_id.clone(),
            remote_endpoint: s.remote_endpoint.clone(),
        }
    }
}
pub fn fingerprint(s: &SyncSessionData) -> String {
    let fields = serde_json::json!([
        s.id,
        s.workspace_id,
        s.node_id,
        s.local_path,
        s.remote_path,
        s.sync_mode,
        s.sync_git,
        s.exclude,
        s.mutagen_session_id,
        s.remote_endpoint
    ]);
    format!("sha256:{:x}", Sha256::digest(fields.to_string().as_bytes()))
}
#[derive(Clone, Serialize)]
pub struct Observation {
    pub state: &'static str,
    pub conflicts: &'static str,
    pub paused: Option<bool>,
    pub status: Option<&'static str>,
    pub conflict_count: Option<u64>,
}
impl Observation {
    pub fn unavailable() -> Self {
        Self {
            state: "unavailable",
            conflicts: "unknown",
            paused: None,
            status: None,
            conflict_count: None,
        }
    }
}
#[derive(Serialize)]
pub struct Status {
    pub context: Context,
    pub target: Target,
    pub sync: Option<Sync>,
    pub mutagen: Observation,
}
#[derive(Serialize)]
pub struct Stage {
    pub name: &'static str,
    pub state: &'static str,
}
#[derive(Serialize)]
pub struct Receipt {
    pub context: Context,
    pub method: String,
    pub target: Target,
    pub result_target: Target,
    pub dry_run: bool,
    pub outcome: &'static str,
    pub stages: Vec<Stage>,
    pub sync: Option<Sync>,
    pub mutagen: Option<Observation>,
    pub error_code: Option<&'static str>,
}
#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    #[allow(dead_code)] // Used by desktop wire errors; the human binary prints only the safe code.
    pub http_status: Option<u16>,
}
impl Error {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            http_status: None,
        }
    }
    pub fn read(error: crate::api::ApiError) -> Self {
        let http_status = error.status_code();
        Self {
            code: match http_status {
                Some(401) => "authentication_required",
                Some(403) => "permission_denied",
                Some(404) => "sync_not_found",
                Some(429) => "rate_limited",
                Some(200..=299) => "sync_response_invalid",
                _ => "server_unavailable",
            },
            http_status,
        }
    }
    pub fn write(error: crate::api::ApiError) -> Self {
        let http_status = error.status_code();
        Self {
            code: if http_status.is_some_and(|s| (400..500).contains(&s)) {
                "sync_rejected"
            } else {
                "sync_outcome_unknown"
            },
            http_status,
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

pub(super) fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
