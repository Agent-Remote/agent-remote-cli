use super::*;
use crate::api::session_stop::SessionStopReceipt;

const SESSION: &str = "44444444-4444-4444-8444-444444444444";
const NODE: &str = "33333333-3333-4333-8333-333333333333";
const REQUEST: &str = "11111111-1111-4111-8111-111111111111";

fn receipt(phase: &str, process_stopped: Option<bool>) -> SessionStopReceipt {
    SessionStopReceipt {
        schema_version: 1,
        request_id: REQUEST.into(),
        phase: phase.into(),
        session_id: SESSION.into(),
        node_id: NODE.into(),
        runtime_backend: "native".into(),
        runtime_resource_id: None,
        stop_task_id: Some(format!("stop_tool_session:{SESSION}")),
        stop_task_record_id: Some("22222222-2222-4222-8222-222222222222".into()),
        stop_task_status: Some("succeeded".into()),
        session_status: Some("stopped".into()),
        skill_finalization_operation_id: None,
        session_deleted: false,
        observed_at: None,
        error_code: None,
        intent_fingerprint:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        reason: "user_requested".into(),
        result_status: Some("succeeded".into()),
        process_stopped,
        save_status: None,
    }
}

#[test]
fn failed_or_unresolved_stop_never_proves_termination() {
    assert!(!is_terminal(&receipt("failed", Some(false))));
    assert!(!is_terminal(&receipt("unresolved", None)));
    assert!(!is_terminal(&receipt("settled", None)));
    assert!(is_terminal(&receipt("accepted", Some(true))));
    let mut deleted = receipt("deleted", None);
    deleted.session_deleted = true;
    assert!(is_terminal(&deleted));
}

#[test]
fn intent_fingerprint_is_stable_and_content_free() {
    let session = crate::api::SessionData {
        id: SESSION.into(),
        tool_type: "claude".into(),
        user_id: REQUEST.into(),
        tool_account_id: REQUEST.into(),
        workspace_id: REQUEST.into(),
        workspace_local_path: None,
        workspace_remote_path: None,
        node_id: NODE.into(),
        project_key: "project".into(),
        status: "running".into(),
        tmux_session_name: None,
        container_id: None,
        runtime_backend: "native".into(),
        runtime_resource_id: None,
        replaces_session_id: None,
        create_task_id: None,
        stop_task_id: None,
        skill_finalization_operation_id: None,
        created_at: "now".into(),
        updated_at: "now".into(),
    };
    let first = intent_fingerprint(&session, "user_requested");
    assert_eq!(first, intent_fingerprint(&session, "user_requested"));
    assert!(first.starts_with("sha256:") && first.len() == 71);
    assert_ne!(first, intent_fingerprint(&session, "other"));
}
