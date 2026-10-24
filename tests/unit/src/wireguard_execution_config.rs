use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};

use super::*;

fn contents() -> Vec<u8> {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.77.0.2/24\n",
        STANDARD.encode([7; 32])
    )
    .into_bytes()
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    crate::platform::set_private_wireguard_file_permissions(&file).unwrap();
}

fn fixture() -> (tempfile::TempDir, PathBuf, ConfigBinding) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("client.conf");
    private_file(&path, &contents());
    let (inspection, binding) = inspection::inspect_snapshot(&path).unwrap();
    assert_eq!(inspection.state, "ready");
    (temp, path, binding.unwrap())
}

fn succeeds(result: Result<ExecutionConfig, ConfigError>) -> ExecutionConfig {
    result.unwrap_or_else(|error| panic!("safe fixture rejected: {error}"))
}

fn fails(result: Result<ExecutionConfig, ConfigError>, code: &str) {
    let error = match result {
        Ok(_) => panic!("unsafe execution input accepted"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), code);
    assert!(!error.to_string().contains(&STANDARD.encode([7; 32])));
    assert!(!format!("{error:?}").contains("SECRET_HOOK"));
}

#[test]
fn source_and_transfer_preserve_exact_bytes_and_matching_public_binding() {
    let (_temp, path, binding) = fixture();
    let source = succeeds(ExecutionConfig::from_source(&path, &binding));
    assert_eq!(source.as_bytes(), contents());
    assert!(source.binding() == &binding);
    let transferred = succeeds(ExecutionConfig::from_transfer(
        source.as_bytes().to_vec(),
        &binding,
    ));
    assert_eq!(transferred.as_bytes(), source.as_bytes());
    assert!(transferred.binding() == source.binding());
    assert_eq!(fs::read(path).unwrap(), contents());
}

#[test]
fn changed_content_and_replaced_objects_cannot_reuse_source_binding() {
    let (temp, path, binding) = fixture();
    let mut changed = contents();
    changed.extend_from_slice(b"# changed exact bytes\n");
    private_file(&path, &changed);
    fails(
        ExecutionConfig::from_source(&path, &binding),
        "wireguard_config_changed",
    );
    fails(
        ExecutionConfig::from_transfer(changed, &binding),
        "wireguard_config_changed",
    );
    let replacement = temp.path().join("replacement.conf");
    private_file(&replacement, &contents());
    fs::remove_file(&path).unwrap();
    fs::rename(&replacement, &path).unwrap();
    fails(
        ExecutionConfig::from_source(&path, &binding),
        "wireguard_config_changed",
    );
    // Transfer deliberately does not reopen or inspect the source path.
    fs::remove_file(path).unwrap();
    let transferred = succeeds(ExecutionConfig::from_transfer(contents(), &binding));
    assert_eq!(transferred.as_bytes(), contents());
}

#[test]
fn all_unsupported_directives_are_refused_even_with_matching_snapshot() {
    let (_temp, path, _) = fixture();
    for directive in [
        "PreUp",
        "PostUp",
        "PreDown",
        "PostDown",
        "SaveConfig",
        "Table",
    ] {
        let mut bytes = contents();
        bytes.extend_from_slice(format!("{directive} = SECRET_HOOK\n").as_bytes());
        private_file(&path, &bytes);
        let (inspection, binding) = inspection::inspect_snapshot(&path).unwrap();
        assert_eq!(inspection.state, "unsupported");
        let binding = binding.unwrap();
        fails(
            ExecutionConfig::from_source(&path, &binding),
            "wireguard_config_unsupported",
        );
        fails(
            ExecutionConfig::from_transfer(bytes, &binding),
            "wireguard_config_unsupported",
        );
    }
}

#[test]
fn transfer_rejects_invalid_oversize_and_mismatched_public_data_without_raw_errors() {
    let (_temp, _path, binding) = fixture();
    for bytes in [
        vec![],
        vec![0xff],
        b"PrivateKey = SECRET_HOOK".to_vec(),
        vec![b' '; MAX_CONFIG_BYTES as usize + 1],
    ] {
        fails(
            ExecutionConfig::from_transfer(bytes, &binding),
            "wireguard_config_invalid",
        );
    }
    let mut wrong = binding.clone();
    wrong.public_key =
        crate::wireguard::public_key_from_private(&STANDARD.encode([9; 32])).unwrap();
    fails(
        ExecutionConfig::from_transfer(contents(), &wrong),
        "wireguard_config_changed",
    );
    wrong = binding.clone();
    wrong.content_sha256 = "a".repeat(64);
    fails(
        ExecutionConfig::from_transfer(contents(), &wrong),
        "wireguard_config_changed",
    );
    for field in ["file_identity", "content_sha256", "public_key"] {
        let mut wrong = binding.clone();
        match field {
            "file_identity" => wrong.file_identity = "SECRET_HOOK".into(),
            "content_sha256" => wrong.content_sha256 = "A".repeat(64),
            _ => wrong.public_key = STANDARD.encode([0; 32]),
        }
        fails(
            ExecutionConfig::from_transfer(contents(), &wrong),
            "wireguard_config_invalid",
        );
    }
}

#[test]
fn unreadable_and_invalid_source_never_yield_execution_bytes() {
    let (_temp, path, binding) = fixture();
    private_file(&path, b"SECRET_HOOK");
    fails(
        ExecutionConfig::from_source(&path, &binding),
        "wireguard_config_invalid",
    );
    private_file(&path, &vec![b' '; MAX_CONFIG_BYTES as usize + 1]);
    fails(
        ExecutionConfig::from_source(&path, &binding),
        "wireguard_config_invalid",
    );
    fs::remove_file(&path).unwrap();
    fails(
        ExecutionConfig::from_source(&path, &binding),
        "wireguard_config_unavailable",
    );
}

#[cfg(unix)]
#[test]
fn linked_special_and_public_sources_cannot_be_transferred_under_stale_binding() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (temp, path, binding) = fixture();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fails(
        ExecutionConfig::from_source(&path, &binding),
        "wireguard_config_unavailable",
    );
    let outside = temp.path().join("outside.conf");
    private_file(&outside, &contents());
    fs::remove_file(&path).unwrap();
    symlink(&outside, &path).unwrap();
    fails(
        ExecutionConfig::from_source(&path, &binding),
        "wireguard_config_unavailable",
    );
    fs::remove_file(&path).unwrap();
    fs::hard_link(&outside, &path).unwrap();
    fails(
        ExecutionConfig::from_source(&path, &binding),
        "wireguard_config_unavailable",
    );
    fs::remove_file(&path).unwrap();
    let fifo = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    fails(
        ExecutionConfig::from_source(&path, &binding),
        "wireguard_config_unavailable",
    );
}
