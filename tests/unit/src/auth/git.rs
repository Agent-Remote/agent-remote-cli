// Tests for src/auth/git.rs.

use super::*;
#[test]
fn helper_material_is_validated_without_echoing_secrets() {
    assert!(parse(b"username=test\npassword=secret\n\n")
        .unwrap()
        .is_some());
    assert!(parse(b"username=test\npassword=secret\npassword=secret\n")
        .err()
        .unwrap()
        .to_string()
        .contains("repeated"));
    assert!(parse(b"username=bad:user\npassword=secret\n").is_err());
}
