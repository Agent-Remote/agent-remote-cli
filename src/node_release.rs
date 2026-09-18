use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::redirect::Policy;
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};
use tokio::process::Command;

pub use crate::managed_releases::MANAGED_NODE_VERSION;
use crate::managed_releases::{MANAGED_NODE_RELEASE_WORKFLOW, MANAGED_NODE_REPOSITORY};

const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 4 * 1024;
const MAX_SIGSTORE_BYTES: u64 = 16 * 1024 * 1024;

pub struct VerifiedNodeRelease {
    _directory: TempDir,
    archive: PathBuf,
    archive_name: String,
    sha256: String,
    target: String,
}

impl VerifiedNodeRelease {
    pub fn archive(&self) -> &Path {
        &self.archive
    }

    pub fn archive_name(&self) -> &str {
        &self.archive_name
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}

pub fn validate_target(value: &str) -> Result<&str> {
    if matches!(
        value,
        "linux-amd64-glibc" | "linux-amd64-musl" | "linux-arm64-glibc" | "linux-arm64-musl"
    ) {
        Ok(value)
    } else {
        bail!("remote Node reported an unsupported release target")
    }
}

pub async fn obtain(target: &str) -> Result<VerifiedNodeRelease> {
    let source = std::env::var_os("AGENT_REMOTE_NODE_RELEASE_ARCHIVE").map(PathBuf::from);
    obtain_with(target, source.as_deref(), OsStr::new("cosign")).await
}

async fn obtain_with(
    target: &str,
    source: Option<&Path>,
    cosign: &OsStr,
) -> Result<VerifiedNodeRelease> {
    let target = validate_target(target)?.to_owned();
    let archive_name = format!("agent-remote-node-{MANAGED_NODE_VERSION}-{target}.tar.gz");
    let directory = Builder::new()
        .prefix("agent-remote-node-release.")
        .tempdir()
        .context("failed to create the private Node release staging directory")?;
    set_directory_owner_only(directory.path())?;
    let archive = directory.path().join(&archive_name);
    let checksum = directory.path().join(format!("{archive_name}.sha256"));
    let sigstore = directory
        .path()
        .join(format!("{archive_name}.sigstore.json"));

    if let Some(source) = source {
        let checksum_source = append_suffix(source, ".sha256");
        let sigstore_source = append_suffix(source, ".sigstore.json");
        copy_regular_file(source, &archive, MAX_ARCHIVE_BYTES)?;
        copy_regular_file(&checksum_source, &checksum, MAX_CHECKSUM_BYTES)?;
        copy_regular_file(&sigstore_source, &sigstore, MAX_SIGSTORE_BYTES)?;
    } else {
        let base = format!(
            "https://github.com/{MANAGED_NODE_REPOSITORY}/releases/download/v{MANAGED_NODE_VERSION}"
        );
        let client = reqwest::Client::builder()
            .redirect(Policy::limited(5))
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(20 * 60))
            .build()
            .context("failed to create the Node release download client")?;
        download(
            &client,
            &format!("{base}/{archive_name}"),
            &archive,
            MAX_ARCHIVE_BYTES,
        )
        .await?;
        download(
            &client,
            &format!("{base}/{archive_name}.sha256"),
            &checksum,
            MAX_CHECKSUM_BYTES,
        )
        .await?;
        download(
            &client,
            &format!("{base}/{archive_name}.sigstore.json"),
            &sigstore,
            MAX_SIGSTORE_BYTES,
        )
        .await?;
    }

    let sha256 = sha256_file(&archive)?;
    verify_checksum_file(&checksum, &archive_name, &sha256)?;
    verify_sigstore_with_program(cosign, &archive, &sigstore).await?;
    validate_private_file(&archive, MAX_ARCHIVE_BYTES)?;
    validate_private_file(&checksum, MAX_CHECKSUM_BYTES)?;
    validate_private_file(&sigstore, MAX_SIGSTORE_BYTES)?;

    Ok(VerifiedNodeRelease {
        _directory: directory,
        archive,
        archive_name,
        sha256,
        target,
    })
}

async fn download(client: &reqwest::Client, url: &str, path: &Path, limit: u64) -> Result<()> {
    let mut response = client
        .get(url)
        .send()
        .await
        .with_context(|| {
            format!(
                "failed to download managed Node release evidence from {MANAGED_NODE_REPOSITORY}"
            )
        })?
        .error_for_status()
        .with_context(|| {
            format!("managed Node release evidence is unavailable in {MANAGED_NODE_REPOSITORY}")
        })?;
    if response.content_length().is_some_and(|size| size > limit) {
        bail!("managed Node release evidence exceeds its size limit")
    }
    let mut file = create_private_file(path)?;
    let mut written = 0_u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed while downloading managed Node release evidence")?
    {
        written = written.saturating_add(chunk.len() as u64);
        if written > limit {
            bail!("managed Node release evidence exceeds its size limit")
        }
        file.write_all(&chunk)?;
    }
    file.sync_all()?;
    Ok(())
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn copy_regular_file(source: &Path, destination: &Path, limit: u64) -> Result<()> {
    let before = fs::symlink_metadata(source).with_context(|| {
        format!(
            "managed Node release input is missing: {}",
            source.display()
        )
    })?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > limit {
        bail!("managed Node release input is not a bounded regular file")
    }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::nlink(&before) != 1 {
        bail!("managed Node release input has an unsafe hard link")
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
        bail!("managed Node release input is not a bounded regular file")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.nlink() != 1 || before.dev() != after.dev() || before.ino() != after.ino() {
            bail!("managed Node release input changed while opening")
        }
    }
    let mut output = create_private_file(destination)?;
    let copied = std::io::copy(
        &mut Read::by_ref(&mut input).take(limit.saturating_add(1)),
        &mut output,
    )?;
    if copied > limit {
        bail!("managed Node release input exceeds its size limit")
    }
    output.sync_all()?;
    Ok(())
}

fn verify_checksum_file(path: &Path, archive_name: &str, actual: &str) -> Result<()> {
    let bytes = read_bounded(path, MAX_CHECKSUM_BYTES)?;
    let text = std::str::from_utf8(&bytes).context("Node release checksum is not UTF-8")?;
    let mut fields = text.split_whitespace();
    let expected = fields.next().unwrap_or_default();
    let name = fields.next().unwrap_or_default().trim_start_matches('*');
    if fields.next().is_some()
        || expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || name != archive_name
        || expected != actual
    {
        bail!("managed Node release checksum does not match the signed archive")
    }
    Ok(())
}

async fn verify_sigstore_with_program(
    program: &OsStr,
    archive: &Path,
    bundle: &Path,
) -> Result<()> {
    let identity = format!(
        "https://github.com/{MANAGED_NODE_REPOSITORY}/.github/workflows/{MANAGED_NODE_RELEASE_WORKFLOW}@refs/tags/v{MANAGED_NODE_VERSION}"
    );
    let status = Command::new(program)
        .arg("verify-blob")
        .arg("--bundle")
        .arg(bundle)
        .arg("--certificate-identity")
        .arg(identity)
        .arg("--certificate-oidc-issuer")
        .arg("https://token.actions.githubusercontent.com")
        .arg(archive)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("cosign is required to authenticate the managed Node release")?;
    if !status.success() {
        bail!("managed Node release Sigstore verification failed")
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("managed Node release evidence exceeds its size limit")
    }
    Ok(bytes)
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn set_directory_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn validate_private_file(path: &Path, limit: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        bail!("managed Node release staging file is unsafe")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            bail!("managed Node release staging file is not owner-only")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        append_suffix, copy_regular_file, obtain_with, validate_target, verify_checksum_file,
        MANAGED_NODE_RELEASE_WORKFLOW, MANAGED_NODE_REPOSITORY, MANAGED_NODE_VERSION,
        MAX_ARCHIVE_BYTES,
    };
    use sha2::{Digest, Sha256};
    use std::fs::{self, File};

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
        assert!(
            copy_regular_file(&source, &temporary.path().join("hard-link-copy"), 1024).is_err()
        );
        fs::remove_file(&source_alias).unwrap();

        let source_link = temporary.path().join("source-link");
        symlink(&source, &source_link).unwrap();
        assert!(
            copy_regular_file(&source_link, &temporary.path().join("symlink-copy"), 1024).is_err()
        );

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
}
