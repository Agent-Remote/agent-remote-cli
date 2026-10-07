// Tests for src/ssh.rs.

use super::*;

#[test]
fn clipboard_proxy_only_observes_managed_session_and_binding_attach() {
    for target in ["--session", "--binding"] {
        let args = [
            "-tt",
            "user@host",
            "agent-remote-attach",
            target,
            "account-123",
        ]
        .map(Into::into);
        assert!(is_managed_attach(&args));
        assert!(is_managed_attach(&[format!(
            "agent-remote-attach {target} account-123"
        )
        .into()]));
    }
    for args in [
        vec!["user@host", "mutagen-agent", "synchronizer"],
        vec!["user@host", "agent-remote-tunnel", "--forward", "id"],
        vec!["user@host", "agent-remote-attach", "--session", "id;sh"],
        vec![
            "user@host",
            "agent-remote-attach",
            "--session",
            "id",
            "extra",
        ],
        vec!["-V"],
    ] {
        assert!(!is_managed_attach(
            &args.into_iter().map(Into::into).collect::<Vec<_>>()
        ));
    }
}

fn attach(forward_ssh_agent: bool) -> AttachSessionData {
    AttachSessionData {
        session_id: "session_1".to_string(),
        node_id: "node_1".to_string(),
        node_wireguard_ip: "10.77.0.1".to_string(),
        ssh_host: "10.77.0.1".to_string(),
        ssh_port: 22,
        ssh_user: "agent-remote".to_string(),
        tmux_session_name: "claude-test".to_string(),
        command_args: Vec::new(),
        ssh_command: String::new(),
        forward_ssh_agent,
        authorization_task_id: "task_1".to_string(),
        authorization_task_status: "succeeded".to_string(),
        expires_in: 300,
    }
}

#[test]
fn attach_args_forward_agent_only_when_authorized() {
    let remote_command = vec!["agent-remote-attach".to_string()];
    let known_hosts = std::path::Path::new("/tmp/agent-remote/ssh/known_hosts");
    let forwarded = attach_args(&attach(true), remote_command.clone(), known_hosts);
    assert_eq!(forwarded.first().map(String::as_str), Some("-A"));

    let restricted = attach_args(&attach(false), remote_command, known_hosts);
    assert!(!restricted.iter().any(|argument| argument == "-A"));
    for option in [
        "BatchMode=yes",
        "ConnectTimeout=10",
        "ServerAliveInterval=10",
        "ServerAliveCountMax=2",
        "StrictHostKeyChecking=accept-new",
        "UserKnownHostsFile=/tmp/agent-remote/ssh/known_hosts",
    ] {
        assert!(restricted.iter().any(|argument| argument == option));
    }
}

#[test]
fn tunnel_args_disable_standard_forwarding_and_use_fixed_command() {
    let args = tunnel_args(
        "10.77.0.2",
        2222,
        "agent-remote",
        "forward-1",
        std::path::Path::new("/tmp/known_hosts"),
    );
    for expected in [
        "-T",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "agent-remote-tunnel",
        "--forward",
        "forward-1",
        "--protocol",
        "1",
    ] {
        assert!(args.iter().any(|argument| argument == expected));
    }
    for forbidden in ["-L", "-R", "-D", "-W", "StrictHostKeyChecking=no"] {
        assert!(!args.iter().any(|argument| argument == forbidden));
    }
}
