use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::redirect::Policy;
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};

use crate::managed_releases::{MANAGED_BRIDGE_BOOTSTRAP_COMMIT, MANAGED_BRIDGE_BOOTSTRAP_SHA256};
pub use crate::managed_releases::{
    MANAGED_BRIDGE_PROTOCOL_VERSION, MANAGED_BRIDGE_REPOSITORY, MANAGED_BRIDGE_VERSION,
    MANAGED_CREDENTIAL_PROFILE, MANAGED_PROFILE_ID, MANAGED_SIGNER_CERTIFICATE_SHA256,
};

const MAX_BOOTSTRAP_BYTES: u64 = 2 * 1024 * 1024;

pub struct VerifiedBridgeBootstrap {
    _directory: TempDir,
    path: PathBuf,
}

impl VerifiedBridgeBootstrap {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub async fn obtain_bootstrap() -> Result<VerifiedBridgeBootstrap> {
    let directory = Builder::new()
        .prefix("agent-remote-bridge-bootstrap.")
        .tempdir()
        .context("failed to create the private Bridge bootstrap directory")?;
    set_directory_owner_only(directory.path())?;
    let destination = directory.path().join("install.sh");
    if let Some(source) = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_BOOTSTRAP") {
        copy_verified_source(
            Path::new(&source),
            &destination,
            MANAGED_BRIDGE_BOOTSTRAP_SHA256,
            MAX_BOOTSTRAP_BYTES,
        )?;
    } else {
        let url = bootstrap_url();
        let client = reqwest::Client::builder()
            .redirect(Policy::limited(5))
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(120))
            .build()
            .context("failed to create the Bridge bootstrap download client")?;
        download(&client, &url, &destination, MAX_BOOTSTRAP_BYTES).await?;
        verify_file_digest(
            &destination,
            MANAGED_BRIDGE_BOOTSTRAP_SHA256,
            MAX_BOOTSTRAP_BYTES,
        )?;
    }
    make_executable_owner_only(&destination)?;
    validate_private_executable(&destination, MAX_BOOTSTRAP_BYTES)?;
    Ok(VerifiedBridgeBootstrap {
        _directory: directory,
        path: destination,
    })
}

pub fn managed_bootstrap_arguments() -> Vec<&'static OsStr> {
    [
        "--version",
        MANAGED_BRIDGE_VERSION,
        "--repo",
        MANAGED_BRIDGE_REPOSITORY,
        "--certificate-sha256",
        MANAGED_SIGNER_CERTIFICATE_SHA256,
        "--confirm-local-trust",
        "--non-interactive",
        "--agent-remote",
        "/usr/bin/false",
    ]
    .into_iter()
    .map(OsStr::new)
    .collect()
}

fn bootstrap_url() -> String {
    format!(
        "https://raw.githubusercontent.com/{MANAGED_BRIDGE_REPOSITORY}/{MANAGED_BRIDGE_BOOTSTRAP_COMMIT}/scripts/install.sh"
    )
}

async fn download(client: &reqwest::Client, url: &str, path: &Path, limit: u64) -> Result<()> {
    let mut response = client
        .get(url)
        .send()
        .await
        .context("failed to download the pinned Bridge bootstrap")?
        .error_for_status()
        .context("the pinned Bridge bootstrap is unavailable")?;
    if response.content_length().is_some_and(|size| size > limit) {
        bail!("the pinned Bridge bootstrap exceeds its size limit")
    }
    let mut output = create_private_file(path)?;
    let mut written = 0_u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed while downloading the pinned Bridge bootstrap")?
    {
        written = written.saturating_add(chunk.len() as u64);
        if written > limit {
            bail!("the pinned Bridge bootstrap exceeds its size limit")
        }
        output.write_all(&chunk)?;
    }
    output.sync_all()?;
    Ok(())
}

fn copy_verified_source(
    source: &Path,
    destination: &Path,
    expected: &str,
    limit: u64,
) -> Result<()> {
    let before = fs::symlink_metadata(source)
        .with_context(|| format!("pinned Bridge bootstrap is missing: {}", source.display()))?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > limit {
        bail!("pinned Bridge bootstrap input is not a bounded regular file")
    }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::nlink(&before) != 1 {
        bail!("pinned Bridge bootstrap input has an unsafe hard link")
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut input = options.open(source)?;
    let after = input.metadata()?;
    if !after.is_file() || after.len() > limit {
        bail!("pinned Bridge bootstrap input is not a bounded regular file")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.nlink() != 1 || before.dev() != after.dev() || before.ino() != after.ino() {
            bail!("pinned Bridge bootstrap input changed while opening")
        }
    }
    let mut output = create_private_file(destination)?;
    let copied = std::io::copy(
        &mut Read::by_ref(&mut input).take(limit.saturating_add(1)),
        &mut output,
    )?;
    if copied > limit {
        bail!("the pinned Bridge bootstrap exceeds its size limit")
    }
    output.sync_all()?;
    verify_file_digest(destination, expected, limit)
}

fn verify_file_digest(path: &Path, expected: &str, limit: u64) -> Result<()> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("embedded Bridge bootstrap digest is invalid")
    }
    let mut input = File::open(path)?;
    let mut digest = Sha256::new();
    let copied = std::io::copy(
        &mut Read::by_ref(&mut input).take(limit.saturating_add(1)),
        &mut digest,
    )?;
    if copied > limit || format!("{:x}", digest.finalize()) != expected {
        bail!("pinned Bridge bootstrap SHA-256 verification failed")
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn set_directory_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn make_executable_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn validate_private_executable(path: &Path, limit: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        bail!("pinned Bridge bootstrap staging file is unsafe")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o500
        {
            bail!("pinned Bridge bootstrap staging file is not owner-only")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        bootstrap_url, copy_verified_source, managed_bootstrap_arguments,
        MANAGED_BRIDGE_REPOSITORY, MANAGED_BRIDGE_VERSION, MANAGED_PROFILE_ID,
        MANAGED_SIGNER_CERTIFICATE_SHA256,
    };
    use crate::managed_releases::MANAGED_BRIDGE_BOOTSTRAP_COMMIT;
    use sha2::{Digest, Sha256};
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    #[test]
    fn managed_profile_and_bootstrap_are_exactly_pinned() {
        let dependencies: serde_json::Value =
            serde_json::from_str(include_str!("../release-dependencies.json")).unwrap();
        let bridge = &dependencies["ego_browser_bridge"];
        assert_eq!(bridge["version"], MANAGED_BRIDGE_VERSION);
        assert_eq!(bridge["profile_id"], MANAGED_PROFILE_ID);
        assert_eq!(
            bridge["signer_certificate_sha256"],
            MANAGED_SIGNER_CERTIFICATE_SHA256
        );
        assert_eq!(
            bootstrap_url(),
            format!(
                "https://raw.githubusercontent.com/{MANAGED_BRIDGE_REPOSITORY}/{MANAGED_BRIDGE_BOOTSTRAP_COMMIT}/scripts/install.sh"
            )
        );
        let arguments: Vec<_> = managed_bootstrap_arguments()
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            arguments,
            [
                "--version",
                MANAGED_BRIDGE_VERSION,
                "--repo",
                MANAGED_BRIDGE_REPOSITORY,
                "--certificate-sha256",
                MANAGED_SIGNER_CERTIFICATE_SHA256,
                "--confirm-local-trust",
                "--non-interactive",
                "--agent-remote",
                "/usr/bin/false",
            ]
        );
        assert!(!arguments.iter().any(|value| {
            matches!(
                value.as_str(),
                "--token" | "--server" | "--session-id" | "--confirm-full-trust"
            )
        }));
    }

    #[test]
    fn bootstrap_copy_requires_the_exact_digest() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source.sh");
        let payload = b"#!/bin/sh\nexit 0\n";
        fs::write(&source, payload).unwrap();
        let digest = format!("{:x}", Sha256::digest(payload));
        let destination = temporary.path().join("verified.sh");
        copy_verified_source(&source, &destination, &digest, 1024).unwrap();
        assert_eq!(fs::read(destination).unwrap(), payload);
        assert!(copy_verified_source(
            &source,
            &temporary.path().join("rejected.sh"),
            &"0".repeat(64),
            1024,
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_copy_rejects_links_and_oversize_inputs() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source.sh");
        fs::write(&source, b"safe").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"safe"));
        let alias = temporary.path().join("alias.sh");
        fs::hard_link(&source, &alias).unwrap();
        assert!(copy_verified_source(
            &source,
            &temporary.path().join("hardlink-output"),
            &digest,
            1024,
        )
        .is_err());
        fs::remove_file(alias).unwrap();
        let source_link = temporary.path().join("source-link.sh");
        symlink(&source, &source_link).unwrap();
        assert!(copy_verified_source(
            &source_link,
            &temporary.path().join("symlink-output"),
            &digest,
            1024,
        )
        .is_err());
        let oversized = temporary.path().join("oversized.sh");
        fs::File::create(&oversized).unwrap().set_len(1025).unwrap();
        assert!(copy_verified_source(
            &oversized,
            &temporary.path().join("oversized-output"),
            &digest,
            1024,
        )
        .is_err());
    }
}
