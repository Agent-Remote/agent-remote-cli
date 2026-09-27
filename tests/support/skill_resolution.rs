#![allow(dead_code)]

use super::{conflicts, state::*, support::*};
use agent_remote_cli::skills::state_snapshot::StateSnapshot;
use serde_json::{json, Value};

pub fn user() -> (u16, Value) {
    (200, json!({"data":{"id":SECOND}}))
}
pub fn side(path: Option<&str>) -> Value {
    json!({"path":path,"unit":[],"use":"incoming","file_tree_digest":null,"directory_tree_digest":null})
}
pub fn custom(snapshot: &StateSnapshot, file: bool) -> Value {
    json!({"path":if file {Some("sample/memory")} else {None},"unit":[],"use":null,"file_tree_digest":if file {Some(snapshot.tree_digest())} else {None},"directory_tree_digest":if file {None} else {Some(snapshot.tree_digest())}})
}
pub fn active_migration() -> Value {
    let mut v = conflicts::migration();
    v["status"] = json!("conflicted");
    v["replacement_id"] = Value::Null;
    v["superseded_reason"] = Value::Null;
    v["live"]["source"]["checkpoint_id"] = json!(OP);
    v["live"]["target"]["checkpoint_id"] = json!(SECOND);
    v["live"]["directory_checkpoint_id"] = json!(SECOND);
    v["live"]["source_head_advanced"] = json!(false);
    v["live"]["recomputation_reasons"] = json!([]);
    v
}
pub fn plan() -> Value {
    let mut v = envelope(
        json!({"migration_id":OP,"current_status":"conflicted","revision":0,"choices":[]}),
    );
    v["status"] = json!("conflicted");
    v
}
pub fn changes() -> Value {
    json!([{"path":"sample/memory","base":file("sample/memory",b"before"),"current":file("sample/memory",b"after")}])
}
pub fn remaining() -> Value {
    json!([{"path":"sample/other","reason":"changed_both","unit":[]}])
}
pub fn resolution(migration: bool, choice: Value, preview: bool, complete: bool) -> Value {
    let status = if preview {
        "preview"
    } else if complete {
        "published"
    } else {
        "pending"
    };
    let mut v = json!({"operation_id":if preview {None} else {Some(REVISION)},"status":status,"plan_revision":if preview {0} else {1},
        "choices":[choice],"remaining":if complete {json!([])} else {remaining()},"result_tree_digest":if complete {Some("a".repeat(64))} else {None},
        "result_checkpoint_id":if !preview && complete {Some(SECOND)} else {None},"replacement_id":null});
    if migration {
        v["operation_kind"] = json!("migration_resolution");
        v["migration_id"] = json!(OP);
        v["candidate_complete"] = json!(complete);
        v["unit"] = json!(["sample"]);
        v["target_revision_id"] = json!(REVISION);
        v["target_modified"] = if complete { json!(true) } else { Value::Null };
        for field in ["target_changes", "original_changes", "directory_changes"] {
            v[field] = if complete { changes() } else { Value::Null };
        }
        v["other_changed_roots"] = json!([]);
        v["stale_reasons"] = json!([]);
        v["recomputation_possible"] = json!(false);
        v["result_directory_id"] = json!(if !preview && complete {
            Some(SKILL)
        } else {
            None
        });
        v["migration_sequence"] = json!(if !preview && complete { Some(1) } else { None });
        v["affected"] = if complete {
            json!([{"name":"sample","state_id":REVISION,"skill_id":SKILL,"origin":"user_library","revision_id":REVISION,
            "installation_epoch":9007199254740993_i64,"state_epoch":2,"checkpoint_id":SECOND,"result_checkpoint_id":if preview {None} else {Some(SECOND)},
            "changes":changes(),"original_changes":changes(),"modified":true}])
        } else {
            json!([])
        };
    } else {
        v["publication_id"] = json!(OP);
        v["ready"] = json!(complete);
        v["stale_reason"] = Value::Null;
    }
    let mut out = envelope(v);
    out["status"] = json!(status);
    out["committed"] = json!(!preview);
    out["operation_id"] = json!(if preview { None } else { Some(REVISION) });
    out
}
pub fn metadata(migration: bool, choice: Value, snapshot: &StateSnapshot, complete: bool) -> Value {
    let mut out = envelope(
        json!({"kind":if migration {"migration"} else {"publication"},"conflict_id":OP,"account_id":ACCOUNT,"plan_revision":0,
        "proposed_tree_digest":snapshot.tree_digest(),"choices":[choice],"metadata_only":true,"content_verified":false,"ready_to_publish":false,
        "candidate_complete":complete,"result_tree_digest":if complete {Some("a".repeat(64))} else {None},"remaining":if complete {json!([])} else {remaining()},
        "unit":if migration {json!(["sample"])} else {json!([])},"current_tree_digest":"b".repeat(64),"directory_tree_digest":if migration {"d".repeat(64)} else {"b".repeat(64)},
        "changes":if complete {changes()} else {Value::Null},"target_revision_id":if migration {Some(REVISION)} else {None},
        "target_modified":if migration && complete {Some(true)} else {None},"target_changes":if migration && complete {changes()} else {Value::Null},
        "original_changes":if migration && complete {changes()} else {Value::Null},"pending_checks":["custom_content","source_authorization","quota_admission","head_preconditions"]}),
    );
    out["status"] = json!("preview");
    out
}
pub fn upload(snapshot: &StateSnapshot) -> Value {
    let mut out = envelope(
        json!({"id":SKILL,"status":"staged","tree_digest":snapshot.tree_digest(),"reserved_bytes":snapshot.total_bytes(),"expires_at":"2026-09-23T14:00:00Z","manifest":snapshot.manifest()}),
    );
    out["status"] = json!("staged");
    out
}
pub fn stored(snapshot: &StateSnapshot) -> Value {
    let mut out =
        envelope(json!({"tree_digest":snapshot.tree_digest(),"manifest":snapshot.manifest()}));
    out["status"] = json!("stored");
    out["committed"] = json!(true);
    out
}
pub fn file_receipt(snapshot: &StateSnapshot) -> Value {
    let mut out = envelope(
        json!({"upload_id":SKILL,"digest":snapshot.manifest().entries[0].sha256,"created":true}),
    );
    out["status"] = json!("upload_pending");
    out
}
pub fn receipt(mut result: Value) -> Value {
    let view = result["data"].take();
    result["data"] = json!({"result":view,"current_status":"ready","replacement_id":null,"superseded_reason":null});
    result
}
pub fn reads(migration: bool) -> Vec<(u16, Value)> {
    let mut responses = vec![user()];
    if migration {
        responses.extend([
            (404, conflicts::rejection("CONFLICT_NOT_FOUND")),
            (200, conflicts::conflict_envelope(active_migration())),
            (200, plan()),
        ]);
    } else {
        responses.push((200, conflicts::conflict_envelope(conflicts::publication())));
    }
    responses
}
pub fn body(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}
