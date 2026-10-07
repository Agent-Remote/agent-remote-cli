// Tests for src/bridge_release.rs.

use super::{
    bootstrap_url, copy_verified_source, managed_bootstrap_arguments, MANAGED_BRIDGE_REPOSITORY,
    MANAGED_BRIDGE_VERSION, MANAGED_PROFILE_ID, MANAGED_SIGNER_CERTIFICATE_SHA256,
};
use crate::managed_releases::MANAGED_BRIDGE_BOOTSTRAP_COMMIT;
use sha2::{Digest, Sha256};
use std::fs;

#[cfg(unix)]
use std::os::unix::fs::symlink;

#[test]
fn managed_profile_and_bootstrap_are_exactly_pinned() {
    let dependencies: serde_json::Value =
        serde_json::from_str(include_str!("../../../release-dependencies.json")).unwrap();
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
