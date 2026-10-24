use anyhow::{bail, Result};

use crate::api::session_attach::SessionAttachData;

use super::ExactSessionAttach;

pub(super) fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| !id.is_nil() && id.hyphenated().to_string() == value)
}

pub(super) fn input(input: &ExactSessionAttach<'_>) -> Result<()> {
    let server = reqwest::Url::parse(input.expected_server);
    if !uuid(input.session_id)
        || !uuid(input.expected_device)
        || input.expected_server.len() > 2048
        || input.expected_server.chars().any(char::is_whitespace)
        || input.expected_server.chars().any(char::is_control)
        || !server.is_ok_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
    {
        bail!("Exact session attachment requires canonical nonzero session/device UUIDs and a valid expected server URL.");
    }
    Ok(())
}

fn safe_word(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

fn host(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
        || (!value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && !part.starts_with('-')
                    && !part.ends_with('-')
                    && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
}

pub(super) fn response(value: &SessionAttachData, input: &ExactSessionAttach<'_>) -> Result<()> {
    if value.version != 1
        || value.session_id != input.session_id
        || value.device_id != input.expected_device
        || value.tool_type != "claude"
        || !uuid(&value.node_id)
        || !uuid(&value.authorization_task_record_id)
        || !host(&value.ssh_host)
        || value.ssh_port == 0
        || !safe_word(&value.ssh_user, 64)
        || value.ssh_user.starts_with('-')
        || value.ssh_user.contains(':')
        || !safe_word(&value.tmux_session_name, 128)
        || !safe_word(&value.authorization_task_id, 256)
        || !(1..=300).contains(&value.expires_in)
    {
        bail!("Session authorization response does not match the confirmed target.");
    }
    Ok(())
}

pub(super) fn same_target(a: &SessionAttachData, b: &SessionAttachData) -> bool {
    let mut normalized = b.clone();
    normalized.authorization_task_status = a.authorization_task_status;
    normalized.expires_in = a.expires_in;
    a == &normalized
}
