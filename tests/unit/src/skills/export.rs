// Tests for src/skills/export.rs.

use super::*;
use crate::skills::manifest::ContentKind;

fn file(path: &str, size: u64) -> Entry {
    Entry {
        path: path.into(),
        kind: EntryKind::File,
        mode: 0o600,
        size,
        sha256: "a".repeat(64),
        target: String::new(),
        content_kind: ContentKind::Binary,
        dependency: String::new(),
    }
}

#[test]
fn export_stages_metadata_above_runtime_default_without_allocating_content() {
    let parent = tempfile::tempdir().unwrap();
    let output = parent.path().join("bundle");
    let size = (10 << 30) + 1;
    let manifest = Manifest {
        version: 1,
        entries: vec![file("large.db", size)],
    };
    let bundle = ExportBundle::prepare(&output, &manifest, &serde_json::json!({})).unwrap();
    assert_eq!(bundle.objects().len(), 1);
    assert_eq!(bundle.objects()[0].size, size);
    assert!(!output.exists());
    let objects = bundle.staging.path().join("bundle/objects");
    assert_eq!(std::fs::read_dir(objects).unwrap().count(), 0);
    drop(bundle);
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn overflowing_export_metadata_never_creates_staging() {
    let parent = tempfile::tempdir().unwrap();
    let output = parent.path().join("bundle");
    let manifest = Manifest {
        version: 1,
        entries: vec![file("a", i64::MAX as u64), file("b", 1)],
    };
    assert!(ExportBundle::prepare(&output, &manifest, &serde_json::json!({})).is_err());
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}
