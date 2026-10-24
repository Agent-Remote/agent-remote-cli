use super::fixture::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path};
const KEY: &str = "12345678-1234-4234-9234-123456789abc";
const TASK:&str="import_tool_account_config:12345678-1234-1234-1234-123456789abc:12345678-1234-4234-9234-123456789abe";
fn selection() -> Value {
    json!({"tool":"claude","include_resume_history":false,"exclude_skills":false})
}
fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn receipt() -> Value {
    let manifest = json!([{"path":"~/.claude/settings.json","size":12,"sha256":hash(b"private-body"),"mode":384}]);
    let excludes = json!([
        "~/.claude.json",
        "~/.claude/cache",
        "~/.claude/logs",
        "~/.claude/transcripts"
    ]);
    let intent = json!({"schema_version":1,"tool_account_id":ACCOUNT_ID,"tool_type":"claude","source":"local_cli","include":["~/.claude/settings.json"],"exclude":excludes,"include_resume_history":false,"dry_run":false,"files":manifest});
    json!({"schema_version":1,"request_id":KEY,"tool_account_id":ACCOUNT_ID,"tool_type":"claude","source":"local_cli","include":["~/.claude/settings.json"],"exclude":excludes,"include_resume_history":false,"dry_run":false,"manifest":manifest,"intent_fingerprint":hash(&serde_json::to_vec(&intent).unwrap()),"task_id":TASK,"accepted":["~/.claude/settings.json"],"rejected":[],"warnings":[],"account_remote_path":"/accounts/private","file_count":1})
}
fn source(f: &Fixture) -> std::path::PathBuf {
    let p = f._temp.path().join("source");
    std::fs::create_dir_all(p.join(".claude")).unwrap();
    std::fs::write(p.join(".claude/settings.json"), "private-body").unwrap();
    p.canonicalize().unwrap()
}
fn invoke(f: &Fixture, source: &Path, method: &str, params: Value) -> (bool, Value) {
    let mut child = command(&f.home)
        .env("HOME", source)
        .env("USERPROFILE", source)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request(method, params))
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    let text = value.to_string();
    assert!(!text.contains("private-body"));
    assert!(!text.contains("cHJpdmF0ZS1ib2R5"));
    redact(&value);
    (out.status.success(), value)
}
fn prepare(f: &Fixture, source: &Path) -> Value {
    let (ok, result) = invoke(
        f,
        source,
        "accounts.import.prepare",
        json!({"expected_context":f.context,"account_id":ACCOUNT_ID,"selection":selection(),"expected_source_home":source}),
    );
    assert!(ok, "{result}");
    result["result"].clone()
}
fn apply(f: &Fixture, source: &Path, plan: &Value) -> (bool, Value) {
    invoke(
        f,
        source,
        "accounts.import.apply",
        json!({"confirmed":true,"expected_context":f.context,"account_id":ACCOUNT_ID,"selection":selection(),"expected_source_home":source,"expected_digest":plan["digest"],"request_id":KEY}),
    )
}
fn status_input(f: &Fixture, plan: &Value) -> Value {
    json!({"expected_context":f.context,"account_id":ACCOUNT_ID,"request_id":KEY,"expected_digest":plan["digest"],"expected_task_id":null})
}
fn task(status: &str, count: u32) -> Reply {
    envelope(
        json!({"task_id":TASK,"status":status,"files_written":[],"file_count":count,"error":"secret-node-error"}),
    )
}
#[test]
fn local_review_and_pending_are_content_free_and_network_free() {
    let f = Fixture::new(vec![]);
    let source = source(&f);
    let (ok, d) = invoke(
        &f,
        &source,
        "accounts.import.discover",
        json!({"selection":selection()}),
    );
    assert!(ok, "{d}");
    let plan = prepare(&f, &source);
    assert_eq!(plan["manifest"].as_array().unwrap().len(), 1);
    assert_eq!(plan["intent_fingerprint"], receipt()["intent_fingerprint"]);
    let (ok, p) = invoke(
        &f,
        &source,
        "accounts.import.pending",
        json!({"expected_home":f.home}),
    );
    assert!(ok, "{p}");
    assert_eq!(p["result"]["items"], json!([]));
    assert!(f.wires().is_empty());
}
#[test]
fn source_change_and_unconfirmed_apply_never_post_or_reserve() {
    let f = Fixture::new(vec![]);
    let source = source(&f);
    let plan = prepare(&f, &source);
    std::fs::write(source.join(".claude/settings.json"), "changed").unwrap();
    let (ok, error) = apply(&f, &source, &plan);
    assert!(!ok);
    assert_eq!(error["error"]["code"], "account_import_source_changed");
    let (_, p) = invoke(
        &f,
        &source,
        "accounts.import.pending",
        json!({"expected_home":f.home}),
    );
    assert_eq!(p["result"]["items"], json!([]));
    assert!(f.wires().is_empty());
}
#[test]
fn apply_acceptance_is_not_completion_and_original_task_status_is_readonly() {
    let f = Fixture::new(vec![
        envelope(receipt()),
        envelope(receipt()),
        task("running", 0),
    ]);
    let source = source(&f);
    let plan = prepare(&f, &source);
    let (ok, r) = apply(&f, &source, &plan);
    assert!(ok, "{r}");
    assert_eq!(r["result"]["phase"], "accepted");
    assert_eq!(r["result"]["operation_id"], "account-operation");
    let db = agent_remote_cli::config::AppPaths::new(Some(f.home.clone()))
        .unwrap()
        .state_db_path();
    let before = std::fs::read(&db).ok();
    let (ok, s) = invoke(
        &f,
        &source,
        "accounts.import.status",
        status_input(&f, &plan),
    );
    assert!(ok, "{s}");
    assert_eq!(s["result"]["phase"], "running");
    assert!(!s.to_string().contains("secret-node-error"));
    assert_eq!(before, std::fs::read(db).ok());
    let (ok, e) = apply(&f, &source, &plan);
    assert!(!ok);
    assert_eq!(e["error"]["code"], "account_import_recovery_required");
    assert_eq!(f.wires().len(), 3);
    assert!(f.wires()[0].starts_with("POST /api/v1/tool-accounts/"));
    assert!(f.wires()[1].contains(&format!("/config-import-requests/{KEY} ")));
    assert!(f.wires()[2].contains(&format!("/config-imports/{TASK} ")));
}
#[test]
fn lost_response_survives_new_process_and_recovers_by_original_key_only() {
    let f = Fixture::new(vec![
        Reply {
            status: 200,
            body: None,
            advertised_length: None,
        },
        envelope(receipt()),
        task("succeeded", 1),
        envelope(receipt()),
        task("succeeded", 1),
    ]);
    let source = source(&f);
    let plan = prepare(&f, &source);
    let (ok, e) = apply(&f, &source, &plan);
    assert!(!ok);
    assert_eq!(e["error"]["code"], "account_import_outcome_unknown");
    let (ok, p) = invoke(
        &f,
        &source,
        "accounts.import.pending",
        json!({"expected_home":f.home}),
    );
    assert!(ok, "{p}");
    assert_eq!(p["result"]["items"][0]["phase"], "pending");
    assert!(p["result"]["items"][0]["task_id"].is_null());
    assert!(!p.to_string().contains("settings.json"));
    let (ok, s) = invoke(
        &f,
        &source,
        "accounts.import.status",
        status_input(&f, &plan),
    );
    assert!(ok, "{s}");
    assert_eq!(s["result"]["phase"], "succeeded");
    let mut forget = status_input(&f, &plan);
    forget["confirmed"] = json!(true);
    forget["expected_task_id"] = json!(TASK);
    let (ok, r) = invoke(&f, &source, "accounts.import.forget", forget);
    assert!(ok, "{r}");
    assert_eq!(r["result"]["forgotten"], true);
    let (_, p) = invoke(
        &f,
        &source,
        "accounts.import.pending",
        json!({"expected_home":f.home}),
    );
    assert_eq!(p["result"]["items"], json!([]));
    assert_eq!(
        f.wires().iter().filter(|w| w.starts_with("POST ")).count(),
        1
    );
}
#[test]
fn ambiguous_http_codes_remain_pending_and_404_status_never_clears() {
    for code in [408, 409, 429, 503] {
        let f = Fixture::new(vec![
            Reply::json(code, json!({"detail":"private-server-error"})),
            Reply::json(404, json!({"detail":"absent"})),
        ]);
        let source = source(&f);
        let plan = prepare(&f, &source);
        let (ok, e) = apply(&f, &source, &plan);
        assert!(!ok);
        assert_eq!(e["error"]["code"], "account_import_outcome_unknown");
        let (ok, s) = invoke(
            &f,
            &source,
            "accounts.import.status",
            status_input(&f, &plan),
        );
        assert!(!ok);
        assert_eq!(s["error"]["code"], "account_import_status_unknown");
        let (_, p) = invoke(
            &f,
            &source,
            "accounts.import.pending",
            json!({"expected_home":f.home}),
        );
        assert_eq!(p["result"]["items"][0]["phase"], "pending");
        assert_eq!(f.wires().len(), 2);
    }
}
#[test]
fn definite_single_rejection_can_be_forgotten_offline() {
    let f = Fixture::new(vec![Reply::json(
        403,
        json!({"detail":"private-server-error"}),
    )]);
    let source = source(&f);
    let plan = prepare(&f, &source);
    let (ok, e) = apply(&f, &source, &plan);
    assert!(!ok);
    assert_eq!(e["error"]["code"], "account_import_rejected");
    let mut mismatch = status_input(&f, &plan);
    mismatch["confirmed"] = json!(true);
    mismatch["expected_task_id"] = json!(TASK);
    let (ok, r) = invoke(&f, &source, "accounts.import.forget", mismatch);
    assert!(!ok);
    assert_eq!(r["error"]["code"], "account_import_request_mismatch");
    let mut input = status_input(&f, &plan);
    input["confirmed"] = json!(true);
    let (ok, r) = invoke(&f, &source, "accounts.import.forget", input);
    assert!(ok, "{r}");
    assert!(r["result"]["task_id"].is_null());
    assert_eq!(f.wires().len(), 1);
}
#[test]
fn forged_receipts_never_bind_or_trigger_task_queries() {
    for field in ["request_id", "intent_fingerprint", "task_id"] {
        let mut forged = receipt();
        forged[field] = json!("unexpected");
        let f = Fixture::new(vec![envelope(forged)]);
        let source = source(&f);
        let plan = prepare(&f, &source);
        let (ok, e) = apply(&f, &source, &plan);
        assert!(!ok);
        assert_eq!(e["error"]["code"], "account_import_outcome_unknown");
        let (_, p) = invoke(
            &f,
            &source,
            "accounts.import.pending",
            json!({"expected_home":f.home}),
        );
        assert_eq!(p["result"]["items"][0]["phase"], "pending");
        assert_eq!(f.wires().len(), 1);
    }
}
#[test]
fn validate_is_confirmed_metadata_only_audited_remote_action() {
    let f = Fixture::new(vec![envelope(
        json!({"tool_account_id":ACCOUNT_ID,"accepted":["~/.claude/settings.json"],"rejected":[],"warnings":["secret-verifier"],"task_id":null,"account_remote_path":null,"imported_file_count":null,"dry_run":true}),
    )]);
    let source = source(&f);
    std::fs::File::options()
        .write(true)
        .open(source.join(".claude/settings.json"))
        .unwrap()
        .set_len(2 * 1024 * 1024)
        .unwrap();
    let mut input = json!({"confirmed":false,"expected_context":f.context,"account_id":ACCOUNT_ID,"selection":selection(),"expected_source_home":source,"expected_include":["~/.claude/settings.json"]});
    let (ok, r) = invoke(&f, &source, "accounts.import.validate", input.clone());
    assert!(!ok);
    assert_eq!(r["error"]["code"], "confirmation_required");
    assert!(f.wires().is_empty());
    input["confirmed"] = json!(true);
    let (ok, r) = invoke(&f, &source, "accounts.import.validate", input);
    assert!(ok, "{r}");
    assert_eq!(r["result"]["audit_written"], true);
    let body = f.wires()[0].split("\r\n\r\n").nth(1).unwrap().to_owned();
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["files"], json!([]));
    assert_eq!(v["dry_run"], true);
}

#[test]
fn running_task_cannot_be_forgotten_and_context_switch_keeps_original_key() {
    let f = Fixture::new(vec![
        envelope(receipt()),
        envelope(receipt()),
        task("running", 0),
    ]);
    let source = source(&f);
    let plan = prepare(&f, &source);
    assert!(apply(&f, &source, &plan).0);
    let mut input = status_input(&f, &plan);
    input["confirmed"] = json!(true);
    let (ok, r) = invoke(&f, &source, "accounts.import.forget", input);
    assert!(!ok);
    assert_eq!(r["error"]["code"], "account_import_not_settled");
    let paths = agent_remote_cli::config::AppPaths::new(Some(f.home.clone())).unwrap();
    agent_remote_cli::config::Config {
        server_url: Some("https://changed.test".into()),
        active_device_id: Some("other-device".into()),
    }
    .save(&paths)
    .unwrap();
    let (ok, r) = invoke(
        &f,
        &source,
        "accounts.import.status",
        status_input(&f, &plan),
    );
    assert!(!ok);
    assert_eq!(r["error"]["code"], "configuration_changed");
    let (ok, p) = invoke(
        &f,
        &source,
        "accounts.import.pending",
        json!({"expected_home":f.home}),
    );
    assert!(ok, "{p}");
    assert_eq!(p["result"]["items"][0]["context"], f.context);
    assert_eq!(f.wires().len(), 3);
}
#[test]
fn lost_validation_response_never_claims_audit_absence_or_success() {
    let f = Fixture::new(vec![Reply {
        status: 200,
        body: None,
        advertised_length: None,
    }]);
    let source = source(&f);
    let input = json!({"confirmed":true,"expected_context":f.context,"account_id":ACCOUNT_ID,"selection":selection(),"expected_source_home":source,"expected_include":["~/.claude/settings.json"]});
    let (ok, r) = invoke(&f, &source, "accounts.import.validate", input);
    assert!(!ok);
    assert_eq!(r["error"]["code"], "account_import_outcome_unknown");
    assert!(r.get("result").is_none());
    assert_eq!(f.wires().len(), 1);
}
#[test]
fn apply_confirmation_precedes_source_capture_or_http() {
    let f = Fixture::new(vec![]);
    let source = source(&f);
    let input = json!({"confirmed":false,"expected_context":f.context,"account_id":ACCOUNT_ID,"selection":selection(),"expected_source_home":source,"expected_digest":hash(b"unreviewed"),"request_id":KEY});
    let (ok, r) = invoke(&f, &source, "accounts.import.apply", input);
    assert!(!ok);
    assert_eq!(r["error"]["code"], "confirmation_required");
    assert!(f.wires().is_empty());
}

#[test]
fn structured_skill_ownership_rejection_is_recoverable_without_changing_selection() {
    for (status, body, definite) in [
        (
            409,
            json!({"error":{"code":"SKILL_MANAGER_OWNS_PATH","message":"managed"}}),
            true,
        ),
        (
            409,
            json!({"error":{"code":"CONFIG_IMPORT_REQUEST_CONFLICT","message":"SKILL_MANAGER_OWNS_PATH"}}),
            false,
        ),
        (409, json!({"detail":"SKILL_MANAGER_OWNS_PATH"}), false),
        (
            503,
            json!({"error":{"code":"SKILL_MANAGER_OWNS_PATH","message":"managed"}}),
            false,
        ),
    ] {
        let f = Fixture::new(vec![Reply::json(status, body)]);
        let source = source(&f);
        let plan = prepare(&f, &source);
        let (ok, r) = apply(&f, &source, &plan);
        assert!(!ok);
        assert_eq!(
            r["error"]["code"],
            if definite {
                "account_import_skills_managed"
            } else {
                "account_import_outcome_unknown"
            }
        );
        let (_, p) = invoke(
            &f,
            &source,
            "accounts.import.pending",
            json!({"expected_home":f.home}),
        );
        assert_eq!(
            p["result"]["items"][0]["phase"],
            if definite { "rejected" } else { "pending" }
        );
        if definite {
            let mut input = status_input(&f, &plan);
            input["confirmed"] = json!(true);
            let (ok, r) = invoke(&f, &source, "accounts.import.forget", input);
            assert!(ok, "{r}");
        }
        assert_eq!(f.wires().len(), 1);
        assert_eq!(plan["selection"]["exclude_skills"], false);
    }
}
