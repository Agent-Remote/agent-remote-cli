use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

pub const DEFAULT_EXCLUDES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    ".venv",
    "__pycache__",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceIdentity {
    pub local_path: PathBuf,
    pub project_key: String,
    pub display_name: String,
}

pub fn identify_workspace(path: Option<&Path>) -> Result<WorkspaceIdentity> {
    let raw_path = match path {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().context("failed to read current directory")?,
    };
    let local_path = raw_path
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", raw_path.display()))?;
    if !local_path.is_dir() {
        bail!(
            "workspace path must be a directory: {}",
            local_path.display()
        );
    }
    let normalized = local_path.to_string_lossy().to_string();
    let project_key = format!("sha256:{}", sha256_hex(normalized.as_bytes()));
    let display_name = local_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("workspace")
        .to_string();
    Ok(WorkspaceIdentity {
        local_path,
        project_key,
        display_name,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + value - 10),
        _ => unreachable!("nibble is always <= 15"),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::identify_workspace;

    #[test]
    fn computes_stable_project_key() {
        let dir = tempdir().unwrap();
        let first = identify_workspace(Some(dir.path())).unwrap();
        let second = identify_workspace(Some(dir.path())).unwrap();
        assert_eq!(first.project_key, second.project_key);
        assert!(first.project_key.starts_with("sha256:"));
    }
}
