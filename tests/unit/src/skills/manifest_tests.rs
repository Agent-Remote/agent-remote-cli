use super::Manifest;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    manifest_json: String,
    #[serde(default)]
    tree_sha256: String,
}

#[derive(Deserialize)]
struct Vectors {
    valid: Vec<Vector>,
    invalid: Vec<Vector>,
}

#[test]
fn canonical_manifest_matches_shared_vectors() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../../fixtures/skills/manifest-v1.json")).unwrap();
    for case in vectors.valid {
        let manifest = Manifest::decode(case.manifest_json.as_bytes()).unwrap();
        assert_eq!(
            manifest.digest().unwrap(),
            case.tree_sha256,
            "{}",
            case.name
        );
    }
    for case in vectors.invalid {
        assert!(
            Manifest::decode(case.manifest_json.as_bytes()).is_err(),
            "{}",
            case.name
        );
    }
}
