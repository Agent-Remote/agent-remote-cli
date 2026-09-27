#![allow(dead_code)]

use super::{state::*, support::*};
use serde_json::{json, Value};

pub fn user() -> (u16, Value) {
    (200, json!({"data":{"id":SECOND}}))
}
pub fn current() -> Value {
    json!({"account_id":ACCOUNT,"skill_id":SKILL,"name":"sample","installation_epoch":9007199254740993_i64,
        "library_generation":9007199254740994_i64,"directory_epoch":1,"directory_checkpoint_id":SECOND,
        "source":{"revision_id":OP,"state_id":ACCOUNT,"state_epoch":1,"checkpoint_id":OP,"expired":false},
        "target":{"revision_id":REVISION,"state_id":null,"state_epoch":null,"checkpoint_id":null,"expired":false},
        "last_migration_id":null,"last_migrated_checkpoint_id":null,"last_sequence":0,"source_has_unmigrated_checkpoint":true})
}
pub fn view(preview: bool, conflict: bool) -> Value {
    let mut v = envelope(
        json!({"mode":"incremental","operation_id":if preview {None} else {Some(SKILL)},
        "status":if conflict {"conflicted"} else {"ready"},"before":current(),
        "base_source":"old_original","current_source":"target_original","incoming_source":"source_published",
        "base_digest":"a".repeat(64),"current_digest":"b".repeat(64),"incoming_digest":"c".repeat(64),
        "result_tree_digest":if conflict {None} else {Some("d".repeat(64))},
        "result_checkpoint_id":if preview || conflict {None} else {Some(SECOND)},
        "result_directory_id":if preview || conflict {None} else {Some(ACCOUNT)},
        "migration_sequence":if preview || conflict {None} else {Some(1)},
        "conflicts":if conflict {json!([{"path":"sample/memory","reason":"changed_both","unit":[]}])} else {json!([])},
        "changes":if conflict {Value::Null} else {json!([{"path":"sample/memory","base":null,"current":file("sample/memory",b"learned")}])},
        "directory_changes":if conflict {Value::Null} else {json!([])}}),
    );
    v["status"] = v["data"]["status"].clone();
    v["committed"] = json!(!preview);
    v["operation_id"] = v["data"]["operation_id"].clone();
    v
}
pub fn receipt(conflict: bool, status: &str) -> Value {
    let mut v = view(false, conflict);
    let original = v["data"].take();
    v["status"] = json!(status);
    v["data"] = json!({"result":original,"current_status":status,
        "replacement_id":if status == "superseded" {Some(OP)} else {None},
        "superseded_reason":if status == "superseded" {Some("state_reset")} else {None}});
    v
}
pub fn rejected(code: &str) -> Value {
    json!({"schema_version":1,"status":"failed","committed":false,"retryable":false,"operation_id":null,"data":null,
        "errors":[{"code":code,"message":"request rejected","object_id":null,"details":{}}]})
}
pub fn reads(conflict: bool) -> Vec<(u16, Value)> {
    vec![
        user(),
        (200, envelope(current())),
        (200, view(true, conflict)),
    ]
}
pub fn body(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}
