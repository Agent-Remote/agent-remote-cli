//! One result envelope for read-only checks and independently committed batch updates.

use super::{print_json, remote_result, safe, SkillExit};
use crate::api::{
    skills::{SkillError, SkillResult},
    ApiError,
};
use anyhow::Result;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Serialize)]
pub(super) struct Row {
    pub skill_id: String,
    pub name: String,
    pub status: String,
    pub exit_code: i32,
    pub result: SkillResult<Value>,
}

pub(super) fn envelope(status: &str, data: Value) -> SkillResult<Value> {
    SkillResult {
        schema_version: 1,
        operation_id: None,
        status: status.into(),
        committed: false,
        retryable: false,
        data: Some(data),
        errors: vec![],
    }
}

pub(super) fn failed(error: anyhow::Error) -> (SkillResult<Value>, i32) {
    if let Some(rejected) = error.downcast_ref::<remote_result::Rejected>() {
        let code = if rejected
            .0
            .errors
            .iter()
            .any(|error| error.code == "LOCAL_SKILL_SCOPE_REQUIRED")
        {
            2
        } else {
            1
        };
        return (rejected.0.clone(), code);
    }
    let (code, message) = if let Some(api) = error.downcast_ref::<ApiError>() {
        (
            api.code().unwrap_or("SKILL_QUERY_FAILED").to_owned(),
            "Server request failed; no new acceptance is implied.".to_owned(),
        )
    } else {
        let message = error.to_string();
        let code = message
            .split_once(':')
            .map(|(code, _)| code)
            .filter(|code| {
                !code.is_empty()
                    && code.len() <= 80
                    && code
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            })
            .unwrap_or("SKILL_SOURCE_FAILED")
            .to_owned();
        (code, message)
    };
    let exit = match code.as_str() {
        "SOURCE_INTERRUPTED" => 130,
        "LOCAL_SOURCE_REQUIRED"
        | "SOURCE_PINNED"
        | "INVALID_ARGUMENT"
        | "INVALID_REF"
        | "REF_AMBIGUOUS"
        | "LOCAL_SKILL_COMMAND_UNSUPPORTED" => 2,
        _ => 1,
    };
    let mut result = envelope("failed", Value::Null);
    result.data = None;
    result.errors.push(SkillError {
        code,
        message,
        object_id: None,
        details: Default::default(),
    });
    (result, exit)
}

pub(super) fn render<T: Serialize>(
    result: &SkillResult<T>,
    code: i32,
    json_mode: bool,
) -> Result<()> {
    if code == 130 && !json_mode {
        return Err(SkillExit(130).into());
    }
    if json_mode {
        print_json(result)?;
    } else {
        for line in serde_json::to_string_pretty(result)?.lines() {
            eprintln!("{}", safe(line));
        }
    }
    if code == 0 {
        Ok(())
    } else {
        Err(SkillExit(code).into())
    }
}

pub(super) async fn display(result: SkillResult<Value>, code: i32, json_mode: bool) -> Result<()> {
    super::output::finish(json_mode, move || render(&result, code, json_mode)).await
}

pub(super) async fn display_batch(rows: Vec<Row>, planned: bool, json_mode: bool) -> Result<()> {
    super::output::finish(json_mode, move || batch(rows, planned, json_mode)).await
}

pub(super) fn batch(rows: Vec<Row>, planned: bool, json_mode: bool) -> Result<()> {
    let code = if rows.iter().any(|row| row.exit_code == 130) {
        130
    } else if rows
        .iter()
        .any(|row| row.exit_code != 0 && row.exit_code != 3)
    {
        1
    } else if rows.iter().any(|row| row.exit_code == 3) {
        3
    } else {
        0
    };
    let errors = rows
        .iter()
        .flat_map(|row| {
            row.result.errors.iter().map(move |error| {
                let mut error = error.clone();
                if error.object_id.is_none() && !row.skill_id.is_empty() {
                    error.object_id = Some(row.skill_id.clone());
                }
                error
            })
        })
        .collect();
    let committed = rows.iter().any(|row| row.result.committed);
    let mut result = envelope(
        if code != 0 {
            "partial"
        } else if planned {
            "planned"
        } else {
            "complete"
        },
        json!({"items":rows}),
    );
    result.committed = committed;
    result.errors = errors;
    render(&result, code, json_mode)
}

/// Cancellation of reads/capture/upload never silently proceeds to a configuration POST.
pub(super) async fn interruptible<T>(
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        result = work => result,
        signal = crate::skill_commands::interruption::cancelled() => {
            signal?;
            anyhow::bail!("SOURCE_INTERRUPTED: this invocation stopped; retained operations remain queryable");
        }
    }
}
