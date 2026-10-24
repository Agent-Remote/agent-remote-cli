//! Local-only environment recovery shared by human and desktop entry points.
//!
//! Selecting a home does not require Server configuration, credentials or SQLite.
use crate::{config::AppPaths, mutagen::desktop::environment};

#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn failure(code: &'static str) -> Error {
    Error { code }
}

fn selected_home(paths: &AppPaths, expected: &str) -> Result<AppPaths> {
    if expected.is_empty()
        || expected.len() > 32768
        || expected.chars().any(char::is_control)
        || !std::path::Path::new(expected).is_absolute()
    {
        return Err(failure("invalid_params"));
    }
    let actual =
        crate::setup::absolute_home(paths).map_err(|_| failure("configuration_unavailable"))?;
    if actual.to_str() != Some(expected) {
        return Err(failure("configuration_changed"));
    }
    AppPaths::new(Some(actual)).map_err(|_| failure("configuration_unavailable"))
}

/// Read the full namespace impact without acquiring a creating lock or loading login state.
pub async fn preview(paths: &AppPaths, expected_home: &str) -> Result<environment::Plan> {
    let paths = selected_home(paths, expected_home)?;
    environment::preview(&paths)
        .await
        .map_err(|e| failure(e.code()))
}

/// Confirmation is bound to the complete backend plan digest. The configuration
/// lock prevents cooperating changes to this home; the backend owns the global
/// namespace lock and independently revalidates its complete plan before mutation.
pub async fn apply(
    paths: &AppPaths,
    expected_home: &str,
    expected_fingerprint: &str,
) -> Result<environment::Receipt> {
    if expected_fingerprint.len() != 71
        || !expected_fingerprint.starts_with("sha256:")
        || !expected_fingerprint[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(failure("invalid_params"));
    }
    let paths = selected_home(paths, expected_home)?;
    let current = environment::preview(&paths)
        .await
        .map_err(|e| failure(e.code()))?;
    if current.fingerprint != expected_fingerprint {
        return Err(failure("sync_mutagen_environment_changed"));
    }
    if !current.repairable {
        return Err(failure("sync_mutagen_environment_blocked"));
    }
    let _guard = crate::config::write_lock_existing(&paths)
        .map_err(|_| failure("configuration_unavailable"))?;
    environment::apply(&paths, expected_fingerprint)
        .await
        .map_err(|e| failure(e.code()))
}
