#![allow(dead_code)]

use super::{state::*, support::*};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use serde_json::{json, Value};

pub fn publication_summary() -> Value {
    json!({"id":OP,"account_id":ACCOUNT,"finalization_id":SECOND,"attempt":2,
        "scope":"account-directory","status":"conflicted","reason":null})
}
pub fn publication() -> Value {
    let mut value = publication_summary();
    let extra = json!({"session_reference_id":REVISION,"replacement_id":null,
        "base":{"source":"session_snapshot","reference_id":SKILL,"tree_digest":"a".repeat(64)},
        "current":{"source":"publication_comparison","reference_id":OP,"tree_digest":"b".repeat(64)},
        "incoming":{"source":"finalization","reference_id":SECOND,"tree_digest":"c".repeat(64)},
        "branches":[{"state_id":SKILL,"entry_name":"sample","state_epoch":9007199254740993_i64,"checkpoint_id":SECOND,"revision_id":REVISION,"changed":true}],
        "conflicts":[{"path":"sample/memory","reason":"changed_both","unit":[]}],
        "plan_revision":0,"choices":[]});
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    value
}
pub fn migration_summary() -> Value {
    json!({"id":OP,"account_id":ACCOUNT,"skill_id":SKILL,"installation_epoch":9007199254740993_i64,
        "name":"sample","mode":"incremental","status":"superseded","source_state_id":SECOND,"source_epoch":1,
        "target_state_id":REVISION,"target_epoch":2,"directory_epoch":3,"created_at":"2026-09-22T12:00:00Z",
        "recomputed_from_id":null,"replacement_id":SKILL,"superseded_reason":"target_head_changed"})
}
pub fn migration() -> Value {
    let mut value = migration_summary();
    let extra = json!({"original":{"mode":"incremental","operation_id":OP,"status":"conflicted",
        "before":{"account_id":ACCOUNT,"skill_id":SKILL,"name":"sample","installation_epoch":9007199254740993_i64,
            "library_generation":4,"directory_epoch":3,"directory_checkpoint_id":SECOND,
            "source":{"revision_id":SKILL,"state_id":SECOND,"state_epoch":1,"checkpoint_id":OP,"expired":false},
            "target":{"revision_id":REVISION,"state_id":REVISION,"state_epoch":2,"checkpoint_id":SECOND,"expired":false},
            "last_migration_id":null,"last_migrated_checkpoint_id":null,"last_sequence":0,"source_has_unmigrated_checkpoint":true},
        "base_source":"old_original","current_source":"target_published","incoming_source":"source_published",
        "base_digest":"a".repeat(64),"current_digest":"b".repeat(64),"incoming_digest":"c".repeat(64),
        "result_tree_digest":null,"result_checkpoint_id":null,"result_directory_id":null,"migration_sequence":null,
        "conflicts":[{"path":"sample/memory","reason":"changed_both","unit":[]}],"changes":null,"directory_changes":null},
        "base":{"source":"old_original","revision_id":SKILL,"checkpoint_id":null,"tree_digest":"a".repeat(64)},
        "current":{"source":"target_published","revision_id":REVISION,"checkpoint_id":SECOND,"tree_digest":"b".repeat(64)},
        "incoming":{"source":"source_published","revision_id":SKILL,"checkpoint_id":OP,"tree_digest":"c".repeat(64)},
        "directory":{"source":"account_directory","revision_id":null,"checkpoint_id":SECOND,"tree_digest":"d".repeat(64)},
        "live":{"source":{"state_id":SECOND,"revision_id":SKILL,"epoch":1,"checkpoint_id":SECOND,"expired":false},
            "target":{"state_id":REVISION,"revision_id":REVISION,"epoch":2,"checkpoint_id":OP,"expired":false},
            "directory_mode":"managed_v1","directory_epoch":3,"directory_checkpoint_id":OP,"library_generation":4,
            "installation_epoch":9007199254740993_i64,"installation_removed":false,"last_migration_id":null,
            "source_head_advanced":true,"recomputation_reasons":["superseded","target_head_changed"]}});
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    value
}
pub fn migration_cursor(id: &str, path: &str) -> String {
    URL_SAFE.encode(json!([id, "a".repeat(64), "b".repeat(64), "c".repeat(64), path]).to_string())
}
pub fn conflict_envelope(value: Value) -> Value {
    let status = value["status"].clone();
    let mut result = envelope(value);
    result["status"] = status;
    result
}
pub fn conflict_diff(migration: bool) -> Value {
    let mut value = json!({"items":[{"path":"sample/memory","base":file("sample/memory",b"base"),
        "current":file("sample/memory",b"\xff\0current"),"incoming":null}],"next_cursor":null});
    if migration {
        value["migration_id"] = json!(OP);
        value["comparison"] = json!("saved_inputs");
    } else {
        value["publication_id"] = json!(OP);
    }
    value
}
pub fn rejection(code: &str) -> Value {
    json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,"retryable":false,"data":null,
        "errors":[{"code":code,"message":"test rejection","object_id":OP,"details":{}}]})
}
