use anyhow::{bail, Result};

use crate::{api::binding_attach::BindingAttachData, cli::AccountAttachArgs};

pub(super) fn account(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}

pub(super) fn binding(value: &str, account_id: &str) -> bool {
    let compact = account_id.replace('-', "");
    compact.len() == 32
        && compact.bytes().all(|b| b.is_ascii_hexdigit())
        && value
            .strip_prefix(&format!("bind-{}-", &compact[..12]))
            .is_some_and(|attempt| {
                attempt.len() == 12
                    && attempt
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
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

pub(super) fn response(
    value: &BindingAttachData,
    input: &AccountAttachArgs,
    device: &str,
) -> Result<()> {
    if value.version != 1
        || value.tool_account_id != input.account_id
        || value.binding_session_id != input.binding_session
        || value.device_id != device
        || !account(&value.node_id)
        || !host(&value.ssh_host)
        || value.ssh_port == 0
        || !safe_word(&value.ssh_user, 64)
        || value.ssh_user.starts_with('-')
        || value.ssh_user.contains(':')
        || !safe_word(&value.tmux_session_name, 128)
        || !safe_word(&value.authorization_task_id, 256)
        || !(1..=300).contains(&value.expires_in)
        || !matches!(
            value.authorization_task_status.as_str(),
            "pending" | "leased" | "running" | "succeeded" | "failed" | "cancelled" | "expired"
        )
    {
        bail!("Binding authorization response does not match the confirmed target.");
    }
    Ok(())
}

pub(super) fn same_target(a: &BindingAttachData, b: &BindingAttachData) -> bool {
    a.version == b.version
        && a.tool_account_id == b.tool_account_id
        && a.binding_session_id == b.binding_session_id
        && a.node_id == b.node_id
        && a.device_id == b.device_id
        && a.ssh_host == b.ssh_host
        && a.ssh_port == b.ssh_port
        && a.ssh_user == b.ssh_user
        && a.tmux_session_name == b.tmux_session_name
        && a.authorization_task_id == b.authorization_task_id
}
