// Tests for src/bin/agent-remote-scp.rs.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use super::proxy_args;

#[test]
fn proxy_uses_legacy_scp_and_managed_known_hosts() {
    let arguments = proxy_args(
        Path::new("C:/Agent Remote/ssh/known_hosts"),
        [OsString::from("source"), OsString::from("destination")],
    );
    let expected = [
        "-O",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "UserKnownHostsFile=C:/Agent Remote/ssh/known_hosts",
        "source",
        "destination",
    ];
    assert_eq!(
        arguments
            .iter()
            .map(OsString::as_os_str)
            .collect::<Vec<_>>(),
        expected.iter().map(OsStr::new).collect::<Vec<_>>()
    );
}
