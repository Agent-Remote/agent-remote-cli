// Tests for src/bin/agent-remote-ssh.rs.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use super::proxy_args;

#[test]
fn proxy_uses_managed_known_hosts_and_accepts_only_new_keys() {
    let arguments = proxy_args(
        Path::new("C:/Agent Remote/ssh/known_hosts"),
        [OsString::from("example.test")],
    );
    let expected = [
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "UserKnownHostsFile=C:/Agent Remote/ssh/known_hosts",
        "example.test",
    ];
    assert_eq!(
        arguments
            .iter()
            .map(OsString::as_os_str)
            .collect::<Vec<_>>(),
        expected.iter().map(OsStr::new).collect::<Vec<_>>()
    );
}
