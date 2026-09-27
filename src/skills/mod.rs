//! User-owned remote skill sources, manifests, and command workflows.

pub mod discovery;
pub mod export;
pub mod git_catalog;
pub mod git_objects;
pub mod git_process;
pub mod git_refs;
pub mod git_source;
pub mod manifest;
mod metadata;
pub mod recovery_export;
pub mod snapshot;
mod snapshot_capture;
mod source_fs;
pub mod state_snapshot;
