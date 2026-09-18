use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use semver::Version;
use serde::Deserialize;

const MANIFEST_NAME: &str = "release-dependencies.json";
const MAX_MANIFEST_BYTES: u64 = 32 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseDependencies {
    schema_version: u32,
    node: NodeRelease,
    ego_browser_bridge: BridgeRelease,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeRelease {
    repository: String,
    release_workflow: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeRelease {
    repository: String,
    version: String,
    protocol_version: String,
    profile_id: String,
    credential_profile: String,
    signer_certificate_sha256: String,
    bootstrap: BridgeBootstrap,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeBootstrap {
    commit: String,
    sha256: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={MANIFEST_NAME}");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or("Cargo did not provide CARGO_MANIFEST_DIR while resolving managed releases")?,
    );
    let manifest_path = manifest_dir.join(MANIFEST_NAME);
    let metadata = fs::symlink_metadata(&manifest_path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err("release dependency manifest must be a bounded regular file".into());
    }
    let source = fs::read(&manifest_path)?;
    let generated = parse_and_render(&source)?;
    let output = PathBuf::from(
        env::var_os("OUT_DIR").ok_or("Cargo did not provide OUT_DIR for managed releases")?,
    );
    fs::write(output.join("managed_releases.rs"), generated)?;
    Ok(())
}

pub fn parse_and_render(source: &[u8]) -> Result<String, Box<dyn Error>> {
    let dependencies: ReleaseDependencies = serde_json::from_slice(source)?;
    validate(&dependencies)?;
    Ok(render(&dependencies))
}

fn validate(dependencies: &ReleaseDependencies) -> Result<(), Box<dyn Error>> {
    if dependencies.schema_version != 1 {
        return Err("unsupported release dependency manifest schema".into());
    }
    validate_repository(&dependencies.node.repository)?;
    validate_workflow(&dependencies.node.release_workflow)?;
    validate_version(&dependencies.node.version, "Node")?;
    validate_repository(&dependencies.ego_browser_bridge.repository)?;
    validate_version(&dependencies.ego_browser_bridge.version, "Bridge")?;
    validate_policy_value(
        &dependencies.ego_browser_bridge.protocol_version,
        "Bridge protocol version",
    )?;
    if dependencies.ego_browser_bridge.profile_id != "community-local-trust" {
        return Err("managed Bridge profile is unsupported".into());
    }
    validate_policy_value(
        &dependencies.ego_browser_bridge.credential_profile,
        "Bridge credential profile",
    )?;
    validate_lower_hex(
        &dependencies.ego_browser_bridge.signer_certificate_sha256,
        64,
        "Bridge signer certificate SHA-256",
    )?;
    validate_lower_hex(
        &dependencies.ego_browser_bridge.bootstrap.commit,
        40,
        "Bridge bootstrap commit",
    )?;
    validate_lower_hex(
        &dependencies.ego_browser_bridge.bootstrap.sha256,
        64,
        "Bridge bootstrap SHA-256",
    )?;
    Ok(())
}

fn validate_version(value: &str, component: &str) -> Result<(), Box<dyn Error>> {
    let parsed =
        Version::parse(value).map_err(|_| format!("managed {component} version is invalid"))?;
    if parsed.to_string() != value {
        return Err(format!("managed {component} version is not canonical").into());
    }
    Ok(())
}

fn validate_repository(value: &str) -> Result<(), Box<dyn Error>> {
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repository = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || !valid_github_name(owner)
        || !valid_github_name(repository)
        || value.len() > 200
    {
        return Err("managed release repository must be an owner/name GitHub slug".into());
    }
    Ok(())
}

fn valid_github_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_workflow(value: &str) -> Result<(), Box<dyn Error>> {
    if value.is_empty()
        || value.len() > 128
        || value.contains('/')
        || !(value.ends_with(".yml") || value.ends_with(".yaml"))
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("managed release workflow must be a YAML filename".into());
    }
    Ok(())
}

fn validate_policy_value(value: &str, label: &str) -> Result<(), Box<dyn Error>> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!("{label} is invalid").into());
    }
    Ok(())
}

fn validate_lower_hex(value: &str, length: usize, label: &str) -> Result<(), Box<dyn Error>> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is invalid").into());
    }
    Ok(())
}

fn render(dependencies: &ReleaseDependencies) -> String {
    let node = &dependencies.node;
    let bridge = &dependencies.ego_browser_bridge;
    let mut output = String::new();
    write_constant(&mut output, "MANAGED_NODE_REPOSITORY", &node.repository);
    write_constant(
        &mut output,
        "MANAGED_NODE_RELEASE_WORKFLOW",
        &node.release_workflow,
    );
    write_constant(&mut output, "MANAGED_NODE_VERSION", &node.version);
    write_constant(&mut output, "MANAGED_BRIDGE_REPOSITORY", &bridge.repository);
    write_constant(&mut output, "MANAGED_BRIDGE_VERSION", &bridge.version);
    write_constant(
        &mut output,
        "MANAGED_BRIDGE_PROTOCOL_VERSION",
        &bridge.protocol_version,
    );
    write_constant(&mut output, "MANAGED_PROFILE_ID", &bridge.profile_id);
    write_constant(
        &mut output,
        "MANAGED_CREDENTIAL_PROFILE",
        &bridge.credential_profile,
    );
    write_constant(
        &mut output,
        "MANAGED_SIGNER_CERTIFICATE_SHA256",
        &bridge.signer_certificate_sha256,
    );
    write_constant(
        &mut output,
        "MANAGED_BRIDGE_BOOTSTRAP_COMMIT",
        &bridge.bootstrap.commit,
    );
    write_constant(
        &mut output,
        "MANAGED_BRIDGE_BOOTSTRAP_SHA256",
        &bridge.bootstrap.sha256,
    );
    output
}

fn write_constant(output: &mut String, name: &str, value: &str) {
    output.push_str(&format!("pub const {name}: &str = {value:?};\n"));
}
