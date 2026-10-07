// Tests for src/node_release.rs.

#[cfg(unix)]
use super::{
    append_suffix, copy_regular_file, obtain_with, MANAGED_NODE_RELEASE_WORKFLOW,
    MANAGED_NODE_REPOSITORY, MAX_ARCHIVE_BYTES,
};
use super::{validate_target, verify_checksum_file, MANAGED_NODE_VERSION};
#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::fs::File;

#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

#[test]
fn release_targets_are_strictly_allowlisted() {
    for target in [
        "linux-amd64-glibc",
        "linux-amd64-musl",
        "linux-arm64-glibc",
        "linux-arm64-musl",
    ] {
        assert_eq!(validate_target(target).unwrap(), target);
    }
    for target in [
        "",
        "linux-x86_64-glibc",
        "linux-amd64-gnu",
        "../linux-amd64-glibc",
        "linux-amd64-glibc\nother",
    ] {
        assert!(validate_target(target).is_err(), "accepted {target:?}");
    }
}

#[test]
fn checksum_requires_one_exact_lowercase_digest_and_filename() {
    let temporary = tempfile::tempdir().unwrap();
    let checksum = temporary.path().join("release.sha256");
    let name = format!("agent-remote-node-{MANAGED_NODE_VERSION}-linux-amd64-glibc.tar.gz");
    let digest = "a".repeat(64);

    fs::write(&checksum, format!("{digest}  {name}\n")).unwrap();
    verify_checksum_file(&checksum, &name, &digest).unwrap();
    fs::write(&checksum, format!("{}  {name}\n", "A".repeat(64))).unwrap();
    assert!(verify_checksum_file(&checksum, &name, &digest).is_err());
    fs::write(&checksum, format!("{digest}  other.tar.gz\n")).unwrap();
    assert!(verify_checksum_file(&checksum, &name, &digest).is_err());
    fs::write(&checksum, format!("{digest}  {name}\nextra\n")).unwrap();
    assert!(verify_checksum_file(&checksum, &name, &digest).is_err());
}

#[cfg(unix)]
#[test]
fn local_release_inputs_reject_symlinks_hard_links_and_oversize_files() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    fs::write(&source, b"release").unwrap();
    let source_alias = temporary.path().join("source-alias");
    fs::hard_link(&source, &source_alias).unwrap();
    assert!(copy_regular_file(&source, &temporary.path().join("hard-link-copy"), 1024).is_err());
    fs::remove_file(&source_alias).unwrap();

    let source_link = temporary.path().join("source-link");
    symlink(&source, &source_link).unwrap();
    assert!(copy_regular_file(&source_link, &temporary.path().join("symlink-copy"), 1024).is_err());

    let oversized = temporary.path().join("oversized");
    File::create(&oversized)
        .unwrap()
        .set_len(MAX_ARCHIVE_BYTES + 1)
        .unwrap();
    assert!(copy_regular_file(
        &oversized,
        &temporary.path().join("oversized-copy"),
        MAX_ARCHIVE_BYTES
    )
    .is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn local_release_is_private_and_cosign_identity_is_exact() {
    let temporary = tempfile::tempdir().unwrap();
    let target = "linux-arm64-musl";
    let archive_name = format!("agent-remote-node-{MANAGED_NODE_VERSION}-{target}.tar.gz");
    let source = temporary.path().join("candidate.tar.gz");
    let payload = b"authenticated release fixture";
    fs::write(&source, payload).unwrap();
    let digest = format!("{:x}", Sha256::digest(payload));
    fs::write(
        append_suffix(&source, ".sha256"),
        format!("{digest}  {archive_name}\n"),
    )
    .unwrap();
    fs::write(append_suffix(&source, ".sigstore.json"), b"bundle").unwrap();

    let cosign = temporary.path().join("cosign");
    fs::write(
        &cosign,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > \"$0.args\"\n",
    )
    .unwrap();
    fs::set_permissions(&cosign, fs::Permissions::from_mode(0o700)).unwrap();

    let release = obtain_with(target, Some(&source), cosign.as_os_str())
        .await
        .unwrap();
    assert_eq!(release.target(), target);
    assert_eq!(release.archive_name(), archive_name);
    assert_eq!(release.sha256(), digest);
    assert_eq!(fs::read(release.archive()).unwrap(), payload);
    let metadata = fs::metadata(release.archive()).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);

    let arguments = fs::read_to_string(append_suffix(&cosign, ".args")).unwrap();
    assert!(arguments.contains("verify-blob\n"));
    assert!(arguments.contains("--bundle\n"));
    assert!(arguments.contains("--certificate-identity\n"));
    assert!(arguments.contains(&format!(
        "https://github.com/{MANAGED_NODE_REPOSITORY}/.github/workflows/{MANAGED_NODE_RELEASE_WORKFLOW}@refs/tags/v{MANAGED_NODE_VERSION}\n"
    )));
    assert!(arguments.contains("--certificate-oidc-issuer\n"));
    assert!(arguments.contains("https://token.actions.githubusercontent.com\n"));
}
