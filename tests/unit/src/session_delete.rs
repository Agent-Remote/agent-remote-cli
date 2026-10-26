use super::*;

fn session(id: &str, status: &str) -> SessionData {
    SessionData {
        id: id.to_string(),
        tool_type: "claude".into(),
        user_id: "00000000-0000-4000-8000-000000000010".into(),
        tool_account_id: "00000000-0000-4000-8000-000000000011".into(),
        workspace_id: "00000000-0000-4000-8000-000000000012".into(),
        workspace_local_path: None,
        workspace_remote_path: None,
        node_id: "00000000-0000-4000-8000-000000000013".into(),
        project_key: "project".into(),
        status: status.into(),
        tmux_session_name: None,
        container_id: None,
        runtime_backend: "native".into(),
        runtime_resource_id: None,
        replaces_session_id: None,
        create_task_id: None,
        stop_task_id: None,
        skill_finalization_operation_id: None,
        created_at: "2026-01-01T00:00:00Z".into(),
        updated_at: "2026-01-01T00:00:00Z".into(),
    }
}

#[test]
fn freeze_selection_sorts_and_deduplicates_the_reviewed_rows() {
    let rows = vec![
        session("00000000-0000-4000-8000-000000000002", "stopped"),
        session("00000000-0000-4000-8000-000000000001", "failed"),
    ];
    let selected = freeze_selection(rows, "claude", None).unwrap();
    assert_eq!(
        selected
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000002"
        ]
    );
}

#[test]
fn freeze_selection_rejects_running_rows_and_ambiguous_prefixes() {
    let running = vec![session("00000000-0000-4000-8000-000000000001", "running")];
    assert!(freeze_selection(running, "claude", None).is_err());

    let rows = vec![
        session("00000000-0000-4000-8000-000000000001", "stopped"),
        session("00000000-0000-4000-8000-000000000002", "stopped"),
    ];
    assert!(freeze_selection(rows, "claude", Some("00000000-0000-4000-8000-00000000000")).is_err());
}

#[test]
fn freeze_selection_accepts_the_short_id_shown_by_fclaude_list() {
    let rows = vec![session("d338e86e-0398-4d2f-8a7c-000000000001", "stopped")];

    let selected = freeze_selection(rows, "claude", Some("d338e86e0398")).unwrap();
    assert_eq!(selected[0].id, "d338e86e-0398-4d2f-8a7c-000000000001");
}

#[test]
fn digest_fixture_includes_schema_and_explicit_null_project_key() {
    let selection = SessionDeleteSelection {
        tool_type: "claude".into(),
        statuses: vec!["failed".into(), "interrupted".into(), "stopped".into()],
        project_key: None,
    };
    let ids = vec![
        "00000000-0000-4000-8000-000000000001".into(),
        "00000000-0000-4000-8000-000000000002".into(),
    ];
    assert_eq!(
        selection_digest("claude", &ids, &selection),
        "sha256:e2d736030969edc2946f564a1d355f411b67a2a044a36456426cfcd5421a5212"
    );
    assert_eq!(
        intent_fingerprint("claude", &ids, &selection, "user_requested"),
        "sha256:4f2a56adbe032af6b0a43bae4279a1fdbb2f2868966c98b21bcafa2886fcdb71"
    );
}

#[test]
fn receipt_decodes_server_reason_field() {
    let receipt: SessionDeleteReceipt = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "request_id": "00000000-0000-4000-8000-000000000020",
        "tool_type": "claude",
        "session_ids": ["00000000-0000-4000-8000-000000000021"],
        "selection": {
            "tool_type": "claude",
            "statuses": ["failed", "interrupted", "stopped"],
            "project_key": null
        },
        "selection_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "intent_fingerprint": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "reason": "user_requested",
        "phase": "deleted",
        "session_deleted": true
    }))
    .expect("Server deletion receipt should decode");

    assert_eq!(receipt.reason, "user_requested");
}
