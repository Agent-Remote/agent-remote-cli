#[allow(dead_code)]
#[path = "../build.rs"]
mod release_build;

fn source_manifest() -> serde_json::Value {
    serde_json::from_str(include_str!("../release-dependencies.json")).unwrap()
}

#[test]
fn release_manifest_generates_one_bridge_version_source() {
    let manifest = source_manifest();
    let source = serde_json::to_vec(&manifest).unwrap();
    let generated = release_build::parse_and_render(&source).unwrap();
    let version = manifest["ego_browser_bridge"]["version"].as_str().unwrap();

    assert!(generated.contains(&format!(
        "pub const MANAGED_BRIDGE_VERSION: &str = {version:?};"
    )));
    assert!(!generated.contains("MANAGED_PROFILE_VERSION"));
}

#[test]
fn release_manifest_rejects_unreviewable_identity_values() {
    let cases = [
        ("unknown field", "unexpected", "value"),
        ("version", "node.version", "latest"),
        (
            "repository",
            "node.repository",
            "https://example.test/release",
        ),
        ("commit", "ego_browser_bridge.bootstrap.commit", "main"),
        ("digest", "ego_browser_bridge.bootstrap.sha256", "ABCDEF"),
        (
            "protocol",
            "ego_browser_bridge.protocol_version",
            "invalid protocol",
        ),
        (
            "credential profile",
            "ego_browser_bridge.credential_profile",
            "invalid/profile",
        ),
    ];

    for (name, path, replacement) in cases {
        let mut manifest = source_manifest();
        match path {
            "unexpected" => manifest["unexpected"] = replacement.into(),
            "node.version" => manifest["node"]["version"] = replacement.into(),
            "node.repository" => manifest["node"]["repository"] = replacement.into(),
            "ego_browser_bridge.bootstrap.commit" => {
                manifest["ego_browser_bridge"]["bootstrap"]["commit"] = replacement.into();
            }
            "ego_browser_bridge.bootstrap.sha256" => {
                manifest["ego_browser_bridge"]["bootstrap"]["sha256"] = replacement.into();
            }
            "ego_browser_bridge.protocol_version" => {
                manifest["ego_browser_bridge"]["protocol_version"] = replacement.into();
            }
            "ego_browser_bridge.credential_profile" => {
                manifest["ego_browser_bridge"]["credential_profile"] = replacement.into();
            }
            _ => unreachable!(),
        }
        let source = serde_json::to_vec(&manifest).unwrap();
        assert!(
            release_build::parse_and_render(&source).is_err(),
            "accepted invalid {name}"
        );
    }
}
