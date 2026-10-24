use super::fixture::*;
use agent_remote_cli::{
    config::AppPaths,
    secrets::{user_token_key, SecretStore},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, process::Command};

const ACTOR: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const KEY: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const RECORD: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const ORIGINAL_RECORD: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const TOKEN: &str = "runtime-user-secret";

#[test]
fn seed_user() {
    let Ok(server) = std::env::var("RECOVERY_TEST_SERVER") else {
        return;
    };
    let paths = AppPaths::new(None).unwrap();
    let value=match std::env::var("RECOVERY_TEST_SESSION").as_deref(){
        Ok("fresh")=>json!({"version":1,"refresh_at":4102444800u64,"expires_at":4102444800u64,"session_expires_at":4102444800u64,"token":{"access_token":TOKEN,"expires_in":100,"refresh_token":"never-refresh-this","refresh_expires_in":1000}}).to_string(),
        Ok("valid")=>json!({"version":1,"refresh_at":1,"expires_at":4102444800u64,"session_expires_at":4102444800u64,"token":{"access_token":TOKEN,"token_type":"bearer","expires_in":100,"refresh_token":"never-refresh-this","refresh_expires_in":1000}}).to_string(),
        Ok("expired")=>json!({"version":1,"refresh_at":1,"expires_at":2,"session_expires_at":4102444800u64,"token":{"access_token":TOKEN,"token_type":"bearer","expires_in":100,"refresh_token":"never-refresh-this","refresh_expires_in":1000}}).to_string(),
        _=>TOKEN.into(),
    };
    SecretStore::new(paths)
        .set_secret(&user_token_key(&server), &value)
        .unwrap();
}
fn seed(f: &Fixture, mode: &str) {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "runtime_recovery::seed_user"])
        .env(
            "RECOVERY_TEST_SERVER",
            f.context["server_url"].as_str().unwrap(),
        )
        .env("RECOVERY_TEST_SESSION", mode)
        .env("AGENT_REMOTE_HOME", &f.home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
fn setup(replies: Vec<Reply>) -> Fixture {
    let f = Fixture::new(replies);
    seed(&f, "raw");
    f
}
fn auth() -> Reply {
    envelope(json!({"schema_version":1,"actor_user_id":ACTOR,"admin":true}))
}
fn context(f: &Fixture) -> Value {
    json!({"home":f.home,"server_url":f.context["server_url"],"actor_user_id":ACTOR})
}
fn original() -> Value {
    json!({"task_id":format!("migrate_tool_account_runtime:{ACCOUNT_ID}:{KEY}"),"task_record_id":ORIGINAL_RECORD,"user_id":OWNER,"tool_account_id":ACCOUNT_ID,"node_id":OWNER,"tool_type":"claude","source_runtime_backend":"docker_sandbox","target_runtime_backend":"native"})
}
fn binding(action: &str) -> Value {
    let mut b = json!({"version":1,"task_id":format!("recover_tool_account_runtime:{ACCOUNT_ID}:{KEY}"),"task_record_id":RECORD,"original_task_id":original()["task_id"],"original_task_record_id":ORIGINAL_RECORD,"user_id":OWNER,"tool_account_id":ACCOUNT_ID,"node_id":OWNER,"tool_type":"claude","source_runtime_backend":"docker_sandbox","target_runtime_backend":"native"});
    if action != "verify_target" {
        b["version"] = json!(if action == "verify_source" { 2 } else { 3 });
        b["action"] = json!(action);
    }
    b
}
fn response(action: &str, status: &str) -> Reply {
    envelope(
        json!({"schema_version":1,"request_id":KEY,"action":action,"binding":binding(action),"status":status}),
    )
}
fn inspection() -> Reply {
    envelope(
        json!({"schema_version":1,"original":original(),"original_status":"failed","account_status":"migrating"}),
    )
}
fn call(f: &Fixture, method: &str, params: Value) -> (bool, Value) {
    let result = f.invoke(&format!("accounts.runtime_recovery.{method}"), params);
    assert!(!result.1.to_string().contains(TOKEN));
    assert!(!result.1.to_string().contains("never-refresh-this"));
    result
}
fn authority_input(f: &Fixture) -> Value {
    json!({"expected_home":f.home,"expected_server_url":f.context["server_url"]})
}
fn plan(f: &Fixture, action: &str) -> Value {
    let (ok, v) = call(
        f,
        "inspect",
        json!({"expected_context":context(f),"account_id":ACCOUNT_ID,"original_task_id":original()["task_id"],"action":action}),
    );
    assert!(ok, "{v}");
    v["result"].clone()
}
fn apply_input(f: &Fixture, plan: &Value) -> Value {
    json!({"confirmed":true,"expected_context":context(f),"account_id":ACCOUNT_ID,"original":plan["original"],"action":plan["action"],"expected_digest":plan["digest"],"request_id":KEY})
}
fn status_input(f: &Fixture, digest: Value, binding: Value) -> Value {
    json!({"expected_context":context(f),"account_id":ACCOUNT_ID,"request_id":KEY,"expected_digest":digest,"expected_binding":binding})
}
fn pending(f: &Fixture) -> Value {
    let (ok, v) = call(f, "pending", json!({"expected_home":f.home}));
    assert!(ok, "{v}");
    assert_eq!(v["result"]["home"], json!(f.home));
    v["result"]["items"].clone()
}
fn snapshot(path: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for e in std::fs::read_dir(path).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            result.extend(snapshot(&p));
        } else {
            result.insert(p.clone(), std::fs::read(p).unwrap());
        }
    }
    result
}

#[test]
fn authority_is_user_only_readonly_and_never_refreshes_due_session() {
    let f = setup(vec![auth()]);
    seed(&f, "valid");
    let before = snapshot(&f.home);
    let (ok, v) = call(&f, "authority", authority_input(&f));
    assert!(ok, "{v}");
    assert_eq!(v["result"]["context"], context(&f));
    assert_eq!(before, snapshot(&f.home));
    assert_eq!(f.wires().len(), 1);
    assert!(f.wires()[0].starts_with("GET /api/v1/runtime-recovery/authority "));
    assert!(f.wires()[0]
        .to_lowercase()
        .contains(&format!("authorization: bearer {TOKEN}")));
}
#[test]
fn device_slot_and_expired_user_cannot_supply_authority() {
    for mode in ["missing", "expired"] {
        let f = Fixture::new(vec![]);
        if mode == "expired" {
            seed(&f, mode);
        }
        let before = snapshot(&f.home);
        let (ok, v) = call(&f, "authority", authority_input(&f));
        assert!(!ok, "{v}");
        assert_eq!(v["error"]["code"], "credential_unavailable");
        assert_eq!(before, snapshot(&f.home));
        assert!(f.wires().is_empty());
    }
}
#[test]
fn ordinary_user_is_observable_but_cannot_inspect() {
    let no_admin = || envelope(json!({"schema_version":1,"actor_user_id":ACTOR,"admin":false}));
    let f = setup(vec![no_admin(), no_admin()]);
    let (ok, v) = call(&f, "authority", authority_input(&f));
    assert!(ok, "{v}");
    assert_eq!(v["result"]["admin"], false);
    let (ok, v) = call(
        &f,
        "inspect",
        json!({"expected_context":context(&f),"account_id":ACCOUNT_ID,"original_task_id":original()["task_id"],"action":"verify_target"}),
    );
    assert!(!ok);
    assert_eq!(v["error"]["code"], "permission_denied");
    assert_eq!(f.wires().len(), 2);
}
#[test]
fn accepted_receipt_is_not_completion_and_known_binding_is_exact() {
    for action in ["verify_target", "verify_source", "repair_source"] {
        let f = setup(vec![
            auth(),
            inspection(),
            auth(),
            response(action, "pending"),
            auth(),
            response(action, "succeeded"),
            auth(),
            response(action, "succeeded"),
        ]);
        let p = plan(&f, action);
        assert_ne!(p["context"]["actor_user_id"], p["original"]["user_id"]);
        let (ok, v) = call(&f, "apply", apply_input(&f, &p));
        assert!(ok, "{v}");
        assert_eq!(v["result"]["target_completion_confirmed"], false);
        assert_eq!(v["result"]["source_restoration_confirmed"], false);
        let records = pending(&f);
        assert_eq!(records[0]["phase"], "accepted");
        assert_eq!(records[0]["binding"], binding(action));
        let before = snapshot(&f.home);
        let input = status_input(&f, p["digest"].clone(), binding(action));
        let (ok, v) = call(&f, "status", input.clone());
        assert!(ok, "{v}");
        assert_eq!(
            v["result"]["target_completion_confirmed"],
            action == "verify_target"
        );
        assert_eq!(
            v["result"]["source_restoration_confirmed"],
            action != "verify_target"
        );
        assert_eq!(before, snapshot(&f.home));
        let mut wrong = input.clone();
        wrong["expected_binding"]["task_record_id"] = json!(ACTOR);
        let (ok, v) = call(&f, "status", wrong);
        assert!(!ok);
        assert_eq!(v["error"]["code"], "runtime_recovery_receipt_changed");
        let mut forget = input;
        forget["confirmed"] = true.into();
        let (ok, v) = call(&f, "forget", forget);
        assert!(ok, "{v}");
        assert!(pending(&f).as_array().unwrap().is_empty());
        let wires = f.wires();
        assert_eq!(wires.iter().filter(|v| v.starts_with("POST ")).count(), 1);
        let body: Value = serde_json::from_str(wires[3].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            body,
            json!({"schema_version":1,"request_id":KEY,"action":action,"expected_original":original()})
        );
    }
}
#[test]
fn lost_response_keeps_key_and_fresh_terminal_binding_can_forget() {
    let f = setup(vec![
        auth(),
        inspection(),
        auth(),
        Reply {
            status: 200,
            body: None,
            advertised_length: None,
        },
        auth(),
        response("verify_target", "succeeded"),
        auth(),
        response("verify_target", "succeeded"),
    ]);
    let p = plan(&f, "verify_target");
    let (ok, v) = call(&f, "apply", apply_input(&f, &p));
    assert!(!ok);
    assert_eq!(v["error"]["code"], "runtime_recovery_outcome_unknown");
    let saved = pending(&f);
    assert_eq!(saved[0]["phase"], "unknown");
    assert!(saved[0]["binding"].is_null());
    let input = status_input(&f, p["digest"].clone(), Value::Null);
    let (ok, v) = call(&f, "status", input);
    assert!(ok, "{v}");
    assert_eq!(pending(&f), saved);
    let mut input = status_input(
        &f,
        p["digest"].clone(),
        v["result"]["recovery"]["binding"].clone(),
    );
    input["confirmed"] = true.into();
    let (ok, v) = call(&f, "forget", input);
    assert!(ok, "{v}");
    assert!(pending(&f).as_array().unwrap().is_empty());
}
#[test]
fn review_changed_is_definite_but_rejected_forget_rejects_forged_binding() {
    let f = setup(vec![
        auth(),
        inspection(),
        auth(),
        Reply::json(
            409,
            json!({"error":{"code":"RUNTIME_MIGRATION_RECOVERY_REVIEW_CHANGED","message":"private-server-detail"}}),
        ),
    ]);
    let p = plan(&f, "verify_target");
    let (ok, v) = call(&f, "apply", apply_input(&f, &p));
    assert!(!ok);
    assert_eq!(v["error"]["code"], "runtime_recovery_review_changed");
    let saved = pending(&f);
    assert_eq!(saved[0]["phase"], "rejected");
    let mut input = status_input(&f, p["digest"].clone(), binding("verify_target"));
    input["confirmed"] = true.into();
    let (ok, v) = call(&f, "forget", input.clone());
    assert!(!ok);
    assert_eq!(v["error"]["code"], "runtime_recovery_receipt_changed");
    input["expected_binding"] = Value::Null;
    let (ok, v) = call(&f, "forget", input);
    assert!(ok, "{v}");
    assert!(pending(&f).as_array().unwrap().is_empty());
    assert_eq!(f.wires().len(), 4);
}
#[test]
fn conflict_rate_limit_and_404_never_authorize_forget_or_new_post() {
    for http in [409, 429] {
        let f = setup(vec![
            auth(),
            inspection(),
            auth(),
            Reply::json(
                http,
                json!({"error":{"code":"RUNTIME_MIGRATION_RECOVERY_CONFLICT","message":"private-server-detail"}}),
            ),
            auth(),
            Reply::json(
                404,
                json!({"error":{"code":"COMMON_NOT_FOUND","message":"absent"}}),
            ),
            auth(),
        ]);
        let p = plan(&f, "verify_target");
        assert!(!call(&f, "apply", apply_input(&f, &p)).0);
        let saved = pending(&f);
        assert_eq!(saved[0]["phase"], "unknown");
        let mut input = status_input(&f, p["digest"].clone(), Value::Null);
        input["confirmed"] = true.into();
        let (ok, v) = call(&f, "forget", input);
        assert!(!ok, "{v}");
        assert_eq!(pending(&f), saved);
        let mut fresh = apply_input(&f, &p);
        fresh["request_id"] = json!(ACTOR);
        let (ok, v) = call(&f, "apply", fresh);
        assert!(!ok);
        assert_eq!(v["error"]["code"], "runtime_recovery_pending");
        assert_eq!(
            f.wires().iter().filter(|v| v.starts_with("POST ")).count(),
            1
        );
    }
}
#[test]
fn manual_old_key_is_query_only_and_prior_binding_remains_exact() {
    let mut changed = binding("verify_target");
    changed["task_record_id"] = json!(ACTOR);
    let f = setup(vec![
        auth(),
        response("verify_target", "running"),
        auth(),
        envelope(
            json!({"schema_version":1,"request_id":KEY,"action":"verify_target","binding":changed,"status":"succeeded"}),
        ),
    ]);
    let before = snapshot(&f.home);
    let (ok, v) = call(&f, "status", status_input(&f, Value::Null, Value::Null));
    assert!(ok, "{v}");
    assert!(v["result"]["digest"].is_null());
    let (ok, v) = call(
        &f,
        "status",
        status_input(&f, Value::Null, binding("verify_target")),
    );
    assert!(!ok);
    assert_eq!(v["error"]["code"], "runtime_recovery_response_invalid");
    assert!(pending(&f).as_array().unwrap().is_empty());
    assert_eq!(before, snapshot(&f.home));
    assert!(f.wires().iter().all(|v| v.starts_with("GET ")));
}
#[test]
fn presubmit_invalid_review_never_invents_pending() {
    let f = setup(vec![auth(), inspection()]);
    let p = plan(&f, "verify_target");
    let mut input = apply_input(&f, &p);
    input["expected_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    let (ok, v) = call(&f, "apply", input);
    assert!(!ok);
    assert_eq!(v["error"]["code"], "runtime_recovery_review_changed");
    assert!(pending(&f).as_array().unwrap().is_empty());
    assert_eq!(f.wires().len(), 2);
    let mut input = status_input(&f, Value::Null, Value::Null);
    input.as_object_mut().unwrap().remove("expected_binding");
    let (ok, v) = call(&f, "status", input);
    assert!(!ok);
    assert_eq!(v["error"]["code"], "invalid_params");
}

fn human(f: &Fixture, args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .args(["--json", "account"])
        .args(args)
        .env("AGENT_REMOTE_HOME", &f.home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn human_same_key_and_forget_share_desktop_receipt_without_reposting() {
    let f = setup(vec![
        auth(),
        inspection(),
        auth(),
        response("verify_target", "pending"),
        auth(),
        response("verify_target", "succeeded"),
        auth(),
        response("verify_target", "succeeded"),
    ]);
    seed(&f, "fresh");
    let p = plan(&f, "verify_target");
    assert!(call(&f, "apply", apply_input(&f, &p)).0);
    let original = original()["task_id"].as_str().unwrap().to_owned();
    let v = human(
        &f,
        &[
            "recover-runtime",
            ACCOUNT_ID,
            "--request-id",
            KEY,
            "--original-task",
            &original,
        ],
    );
    assert_eq!(v["target_completion_confirmed"], true);
    let v = human(
        &f,
        &[
            "recovery-status",
            ACCOUNT_ID,
            "--request-id",
            KEY,
            "--forget",
            "--yes",
        ],
    );
    assert_eq!(v["forgotten"], true);
    assert!(pending(&f).as_array().unwrap().is_empty());
    assert_eq!(
        f.wires().iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
}

#[test]
fn human_status_preserves_legacy_user_refresh_preparation() {
    let f = setup(vec![
        envelope(
            json!({"access_token":"renewed-user-token","expires_in":3600,"refresh_token":"renewed-refresh","refresh_expires_in":86400}),
        ),
        auth(),
        auth(),
        response("verify_target", "succeeded"),
    ]);
    seed(&f, "expired");
    let v = human(&f, &["recovery-status", ACCOUNT_ID, "--request-id", KEY]);
    assert_eq!(v["target_completion_confirmed"], true);
    let wires = f.wires();
    assert_eq!(wires.len(), 4);
    assert!(wires[0].starts_with("POST "));
    assert!(wires[0].contains("never-refresh-this"));
    assert!(wires[1..].iter().all(|r| r.starts_with("GET ")
        && r.to_lowercase()
            .contains("authorization: bearer renewed-user-token")));
    assert!(pending(&f).as_array().unwrap().is_empty());
}

#[test]
fn missing_home_pending_is_empty_without_initialization() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, v) = invoke(
        &home,
        "accounts.runtime_recovery.pending",
        json!({"expected_home":home}),
    );
    assert!(ok, "{v}");
    assert_eq!(v["result"], json!({"home":home,"items":[]}));
    assert!(!home.exists());
}
