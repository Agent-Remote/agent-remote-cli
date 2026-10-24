//! Reviewed daemon-wide environment repair. Project operations never imply this consent.
mod inventory;
mod native_lock;
mod snapshot;

use super::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub protocol: String,
    pub user: String,
    pub host: String,
    pub port: u32,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub kind: String,
    pub identifier: String,
    pub name: String,
    pub paused: bool,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub configuration_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub home: String,
    pub ssh_directory: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub path: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub home: String,
    pub data_directory: String,
    pub namespace_fingerprint: Option<String>,
    pub daemon_state: String,
    pub running_fingerprint: Option<String>,
    pub registration: String,
    pub previous: Option<Binding>,
    pub desired: Binding,
    pub tools: Vec<Tool>,
    pub sessions: Vec<Session>,
    pub inventory_fingerprint: String,
    pub marker_fingerprint: Option<String>,
    pub fingerprint: String,
    pub repairable: bool,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Stage {
    pub name: String,
    pub state: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub plan: Plan,
    pub outcome: String,
    pub stages: Vec<Stage>,
    pub environment: Option<Plan>,
    pub error_code: Option<String>,
}

mod guard;
mod lifecycle;
pub(crate) use guard::ExistingEnvironmentGuard;
pub(crate) use guard::{legacy_guard, lock_only, prepare_guard};
pub(crate) use lifecycle::NamespaceGuard;
pub use lifecycle::{apply, preview};
