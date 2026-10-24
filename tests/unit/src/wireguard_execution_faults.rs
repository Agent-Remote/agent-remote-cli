//! Thread-local one-shot failures; absent from production builds.
use std::cell::Cell;

use crate::wireguard::configuration::ConfigError;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Write,
    FileSync,
    Rename,
    DirectorySync,
}
thread_local! { static NEXT: Cell<Option<Stage>> = const { Cell::new(None) }; }
pub(crate) struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        NEXT.set(None);
    }
}
pub(crate) fn arm(stage: Stage) -> Reset {
    NEXT.set(Some(stage));
    Reset
}
pub(crate) fn check(stage: Stage) -> Result<(), ConfigError> {
    if NEXT.get() == Some(stage) {
        NEXT.set(None);
        return Err(ConfigError("wireguard_execution_unavailable"));
    }
    Ok(())
}
