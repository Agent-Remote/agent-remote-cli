// Tests for src/platform.rs.

use super::{executable_name, ssh_binary};

#[test]
fn executable_names_follow_the_host_platform() {
    let expected = if cfg!(windows) {
        "mutagen.exe"
    } else {
        "mutagen"
    };
    assert_eq!(executable_name("mutagen"), expected);
}

#[test]
fn ssh_binary_follows_the_host_platform() {
    let expected = if cfg!(windows) { "ssh.exe" } else { "ssh" };
    assert_eq!(
        ssh_binary().file_name().and_then(|value| value.to_str()),
        Some(expected)
    );
}
