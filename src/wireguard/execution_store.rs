//! Protected snapshots and non-replayable operation records for a future broker.
//! No entry point here authenticates a caller, authorizes or executes a command.

use std::fs::File;
use std::io::Write;
use std::sync::atomic::AtomicBool;

use crate::platform::protected_directory::{DirectorySync, ProtectedDirectory};

use super::configuration::ConfigError;
use super::execution_config::ExecutionConfig;
use super::execution_request::{
    ExecutionFailure, ExecutionRequest, OperationPhase, OperationRecord,
};
use super::target::TargetObservation;

mod files;

pub(crate) struct ExecutionStore {
    root: ProtectedDirectory,
}

pub(crate) enum BeginOperation<'a> {
    Created(Box<Operation<'a>>),
    /// Existing IDs never produce a lease, including a leftover Prepared record.
    Existing(Box<OperationRecord>),
}

/// Holds both locks until the caller finishes observing the submitted operation.
/// Dropping this lease preserves all files, including long-lived service config.
pub(crate) struct Operation<'a> {
    root: &'a ProtectedDirectory,
    directory: ProtectedDirectory,
    record: OperationRecord,
    directory_sync: DirectorySync,
    _request_lock: File,
    _target_lock: File,
}

impl ExecutionStore {
    pub(crate) fn new(root: ProtectedDirectory) -> Self {
        Self { root }
    }

    pub(crate) fn begin(
        &self,
        request: ExecutionRequest,
        config: &ExecutionConfig,
        canceled: &AtomicBool,
    ) -> Result<BeginOperation<'_>, ConfigError> {
        request.validate()?;
        if request.config != *config.binding() {
            return Err(ConfigError("wireguard_execution_config_changed"));
        }
        self.root.verify().map_err(files::unavailable)?;
        // Always request then target; the ID lock also excludes a concurrent
        // attempt to reuse one ID for a different target or authenticated user.
        let request_lock = files::lock(
            &self.root,
            &format!("request-{}.lock", request.request_id),
            canceled,
        )?;
        let target_lock = files::lock(&self.root, &files::target_lock_name(&request), canceled)?;
        files::check_canceled(canceled)?;
        if let Some(directory) = self
            .root
            .open_child(&request.request_id)
            .map_err(files::unavailable)?
        {
            let record = files::load(&directory, &request.request_id)?;
            if record.request != request {
                return Err(ConfigError("wireguard_execution_request_conflict"));
            }
            files::verify_snapshot(&directory, &record)?;
            files::verify_journal(&directory, &record)?;
            return Ok(BeginOperation::Existing(Box::new(record)));
        }
        let directory = self
            .root
            .create_child(&request.request_id)
            .map_err(files::unavailable)?;
        // Never remove this directory on failure. An incomplete reservation is
        // a tombstone, not permission to recreate and replay the same ID.
        let root_sync = self.root.sync().map_err(files::unavailable)?;
        files::check_canceled(canceled)?;
        let mut file = directory
            .create_file(&format!("{}.conf", request.logical_name))
            .map_err(files::unavailable)?;
        file.write_all(config.as_bytes())
            .map_err(files::unavailable)?;
        file.sync_all().map_err(files::unavailable)?;
        directory.verify_file(&file).map_err(files::unavailable)?;
        let snapshot_identity = super::publication::snapshot_identity(&file)?;
        let record = OperationRecord {
            version: 1,
            request,
            snapshot_identity,
            phase: OperationPhase::Prepared,
            observation: None,
            failure: None,
        };
        files::check_canceled(canceled)?;
        let record_sync = files::persist(&directory, &record)?;
        let journal_sync = files::append_journal(&directory, &record)?;
        let directory_sync =
            files::combine_sync(root_sync, files::combine_sync(record_sync, journal_sync));
        Ok(BeginOperation::Created(Box::new(Operation {
            root: &self.root,
            directory,
            record,
            directory_sync,
            _request_lock: request_lock,
            _target_lock: target_lock,
        })))
    }

    /// Querying an incomplete or corrupt reservation fails closed. It never
    /// repairs state or creates a new execution lease.
    pub(crate) fn read(
        &self,
        request_id: &str,
        canceled: &AtomicBool,
    ) -> Result<Option<OperationRecord>, ConfigError> {
        if !super::execution_request::digest(request_id) {
            return Err(ConfigError("wireguard_execution_invalid"));
        }
        let _lock = files::lock(&self.root, &format!("request-{request_id}.lock"), canceled)?;
        let Some(directory) = self
            .root
            .open_child(request_id)
            .map_err(files::unavailable)?
        else {
            return Ok(None);
        };
        let record = files::load(&directory, request_id)?;
        files::verify_snapshot(&directory, &record)?;
        files::verify_journal(&directory, &record)?;
        Ok(Some(record))
    }

    /// Recover durable submission boundaries after a process restart. This
    /// query is deliberately read-only: it never creates a lease, invokes a
    /// helper, or resubmits an operation. A submitted record means the target
    /// may already have changed; a future authenticated broker must observe
    /// the target before deciding what to do.
    pub(crate) fn submitted_records(
        &self,
        canceled: &AtomicBool,
    ) -> Result<Vec<OperationRecord>, ConfigError> {
        let request_ids = files::request_ids(&self.root)?;
        let mut records = Vec::new();
        for request_id in request_ids {
            files::check_canceled(canceled)?;
            let Some(record) = self.read(&request_id, canceled)? else {
                return Err(ConfigError("wireguard_execution_changed"));
            };
            if record.phase == OperationPhase::Submitted {
                records.push(record);
            }
        }
        Ok(records)
    }
}

impl Operation<'_> {
    pub(crate) fn record(&self) -> &OperationRecord {
        &self.record
    }

    pub(crate) fn directory_sync(&self) -> DirectorySync {
        self.directory_sync
    }

    /// Records intent before any future dispatcher runs. Unsupported directory
    /// durability is explicit and must not be interpreted as an execution permit.
    pub(crate) fn mark_submitted(
        &mut self,
        canceled: &AtomicBool,
    ) -> Result<DirectorySync, ConfigError> {
        if self.record.phase != OperationPhase::Prepared {
            return Err(ConfigError("wireguard_execution_transition_invalid"));
        }
        files::check_canceled(canceled)?;
        let mut next = self.record.clone();
        next.phase = OperationPhase::Submitted;
        self.transition(next)
    }

    /// An observation is a fact, not an inferred successful requested outcome.
    pub(crate) fn record_observation(
        &mut self,
        observation: TargetObservation,
    ) -> Result<DirectorySync, ConfigError> {
        let mut next = self.completion()?;
        next.phase = OperationPhase::Observed;
        next.observation = Some(observation);
        self.transition(next)
    }

    /// Failure after submission does not prove that no OS change occurred.
    pub(crate) fn record_failure(
        &mut self,
        failure: ExecutionFailure,
    ) -> Result<DirectorySync, ConfigError> {
        let mut next = self.completion()?;
        next.phase = OperationPhase::Failed;
        next.failure = Some(failure);
        self.transition(next)
    }

    fn completion(&self) -> Result<OperationRecord, ConfigError> {
        if self.record.phase != OperationPhase::Submitted {
            return Err(ConfigError("wireguard_execution_transition_invalid"));
        }
        Ok(self.record.clone())
    }

    fn transition(&mut self, next: OperationRecord) -> Result<DirectorySync, ConfigError> {
        next.validate()?;
        self.root.verify().map_err(files::unavailable)?;
        if files::load(&self.directory, &self.record.request.request_id)? != self.record {
            return Err(ConfigError("wireguard_execution_changed"));
        }
        files::verify_snapshot(&self.directory, &self.record)?;
        let record_sync = files::persist(&self.directory, &next)?;
        let journal_sync = files::append_journal(&self.directory, &next)?;
        let sync = files::combine_sync(record_sync, journal_sync);
        self.directory_sync = files::combine_sync(self.directory_sync, sync);
        self.record = next;
        Ok(self.directory_sync)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_execution_store.rs"]
mod tests;
