// Tests for src/app/mod.rs.

#[test]
fn command_future_fits_small_platform_stacks() {
    fn future_size<F: std::future::Future>(_: impl FnOnce() -> F) -> usize {
        std::mem::size_of::<F>()
    }
    // Inspect the type without first placing an oversized future on this test's stack.
    let size = future_size(|| {
        super::run(<super::Cli as clap::Parser>::parse_from([
            "agent-remote",
            "skill",
            "list",
        ]))
    });
    assert!(
        size <= 128 * 1024,
        "command dispatch future uses {size} bytes"
    );
}

use super::{
    collect_claude_config_files_at, config_import_complete, config_import_exclusions,
    discover_claude_config_paths_at, json_error_value, normalize_server_url, parse_rfc3339_seconds,
    posix_shell_quote, valid_join_code, valid_join_code_expiry, valid_managed_ssh_host,
    valid_managed_ssh_user, valid_node_install_server_url,
};
use anyhow::anyhow;

#[test]
fn trims_trailing_slashes_from_server_url() {
    assert_eq!(
        normalize_server_url(" https://example.test/// "),
        "https://example.test"
    );
}

#[test]
fn config_import_default_keeps_skills_and_exclusion_is_explicit() {
    let home = tempfile::tempdir().unwrap();
    let claude = home.path().join(".claude");
    std::fs::create_dir_all(claude.join("skills/example")).unwrap();
    std::fs::write(claude.join("skills/example/SKILL.md"), "skill").unwrap();
    std::fs::write(claude.join("settings.json"), "{}").unwrap();
    let included = discover_claude_config_paths_at(home.path(), false, false).unwrap();
    let files = collect_claude_config_files_at(home.path(), &included).unwrap();
    assert_eq!(files.len(), 2);
    assert!(files
        .iter()
        .any(|file| file.path == "~/.claude/skills/example/SKILL.md"));
    assert!(!config_import_exclusions(false)
        .iter()
        .any(|path| path == "~/.claude/skills"));
    assert!(config_import_exclusions(true)
        .iter()
        .any(|path| path == "~/.claude/skills"));
}

#[test]
fn config_import_excludes_skills_before_reading_and_preserves_other_scopes() {
    let home = tempfile::tempdir().unwrap();
    let claude = home.path().join(".claude");
    for path in ["skills/example", "plugins/example/skills", "projects"] {
        std::fs::create_dir_all(claude.join(path)).unwrap();
    }
    std::fs::File::create(claude.join("skills/example/large.bin"))
        .unwrap()
        .set_len(super::CONFIG_IMPORT_MAX_FILE_BYTES + 1)
        .unwrap();
    std::fs::write(claude.join("settings.json"), "{}").unwrap();
    std::fs::write(claude.join("plugins/example/skills/SKILL.md"), "plugin").unwrap();
    std::fs::write(claude.join("projects/history.jsonl"), "history").unwrap();
    for history in [false, true] {
        let included = discover_claude_config_paths_at(home.path(), history, true).unwrap();
        assert!(!included.iter().any(|path| path == "~/.claude/skills"));
        let files = collect_claude_config_files_at(home.path(), &included).unwrap();
        assert_eq!(files.len(), if history { 3 } else { 2 });
        assert!(files
            .iter()
            .all(|file| !file.path.starts_with("~/.claude/skills/")));
        assert!(files
            .iter()
            .any(|file| file.path == "~/.claude/plugins/example/skills/SKILL.md"));
    }
    let all = discover_claude_config_paths_at(home.path(), false, false).unwrap();
    assert!(collect_claude_config_files_at(home.path(), &all).is_err());
}

#[test]
fn config_import_only_skills_becomes_empty_when_excluded() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".claude/skills")).unwrap();
    let included = discover_claude_config_paths_at(home.path(), true, true).unwrap();
    assert!(included.is_empty());
    assert!(collect_claude_config_files_at(home.path(), &included)
        .unwrap()
        .is_empty());
}

#[test]
fn config_import_completion_classifies_terminal_states() {
    assert!(!config_import_complete("pending", None, "task-1").unwrap());
    assert!(!config_import_complete("running", None, "task-1").unwrap());
    assert!(config_import_complete("succeeded", None, "task-1").unwrap());

    let failed = config_import_complete("failed", Some("write failed"), "task-1")
        .unwrap_err()
        .to_string();
    assert!(failed.contains("write failed"));
    assert!(failed.contains("task-1"));
    assert!(config_import_complete("unexpected", None, "task-1").is_err());
}

#[test]
fn node_join_code_metadata_is_strictly_validated() {
    assert!(valid_join_code("jcode_0123456789abcdef"));
    assert!(!valid_join_code("too short"));
    assert!(!valid_join_code("jcode_with\nnewline"));
    assert!(parse_rfc3339_seconds("2099-01-02T03:04:05Z").is_some());
    assert!(parse_rfc3339_seconds("2099-01-02T03:04:05+08:00").is_some());
    assert!(valid_join_code_expiry("2099-01-02T03:04:05Z"));
    assert!(!valid_join_code_expiry("not-a-timestamp"));
    assert!(!valid_join_code_expiry("2000-01-02T03:04:05Z"));
}

#[test]
fn node_install_transport_fields_are_strictly_validated_and_quoted() {
    assert!(valid_node_install_server_url(
        "https://control.example:8443"
    ));
    assert!(!valid_node_install_server_url(
        "https://control.example/path"
    ));
    assert!(!valid_node_install_server_url(
        "https://control.example?next=1"
    ));
    assert!(valid_managed_ssh_host("node-1.internal"));
    assert!(valid_managed_ssh_host("fe80::1%en0"));
    assert!(!valid_managed_ssh_host("-oProxyCommand=bad"));
    assert!(!valid_managed_ssh_host("node\nother"));
    assert!(valid_managed_ssh_user("agent-remote"));
    assert!(!valid_managed_ssh_user("-oProxyCommand=bad"));
    assert!(!valid_managed_ssh_user("agent remote"));
    assert_eq!(posix_shell_quote("a'b"), "'a'\\''b'");
}

#[test]
fn json_error_projection_is_stable_and_secret_free() {
    let error = anyhow!(
        "error_code=admission_disabled state=ready admission=server_execution_closed next_action=request_execution_admission next_command=agent-remote ego-browser connect stale=false token=do-not-leak"
    );
    let value = json_error_value(&error);
    assert_eq!(value["error_code"], "admission_disabled");
    assert!(value["state"]["installed"].is_null());
    assert!(value["state"]["enabled"].is_null());
    assert!(value["state"]["registered"].is_null());
    assert_eq!(value["state"]["available"], false);
    assert_eq!(value["state"]["connected"], false);
    assert!(value["capability"]["effective_enabled"].is_null());
    assert_eq!(value["admission"]["binding"], "unknown");
    assert_eq!(value["admission"]["server_execution"], "denied");
    assert_eq!(value["next_action"], "request_execution_admission");
    assert_eq!(value["next_command"], "agent-remote ego-browser connect");
    assert!(!serde_json::to_string(&value)
        .unwrap()
        .contains("do-not-leak"));
}
