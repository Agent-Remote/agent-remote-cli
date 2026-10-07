// Tests for src/skills/git_objects.rs.

use super::*;
#[test]
fn tree_parser_preserves_modes_and_rejects_paths_or_parents() {
    let oid = "a".repeat(40);
    let entries = parse_tree(format!("100755 blob {oid} 4\trun.sh\0").as_bytes()).unwrap();
    assert_eq!(entries[0].mode, 0o100755);
    for path in ["../escape", "dir/missing", "/absolute", "bad\\path"] {
        assert!(parse_tree(format!("100644 blob {oid} 4\t{path}\0").as_bytes()).is_err());
    }
}
#[test]
fn blob_parser_does_not_interpret_binary_payload() {
    let oid = "a".repeat(40);
    let mut output = format!("{oid} blob 4\n").into_bytes();
    output.extend_from_slice(b"\0\xff\nX\n");
    let expected = BTreeMap::from([(oid.clone(), 4)]);
    assert_eq!(
        parse_blobs(&output, expected.clone()).unwrap()[&oid],
        b"\0\xff\nX"
    );
    output.pop();
    assert!(parse_blobs(&output, expected).is_err());
}
