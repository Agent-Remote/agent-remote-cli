//! Bounded tool snapshots are observations, never executable trust decisions.

use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{publication, tools};

const MAX_TOOL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Serialize)]
pub struct ToolSnapshot {
    pub name: &'static str,
    pub state: &'static str,
    pub path: Option<PathBuf>,
    pub identity: Option<String>,
    pub sha256: Option<String>,
}

pub(super) fn snapshot(tool: tools::ToolInfo, canceled: &AtomicBool) -> ToolSnapshot {
    let binding = if tool.state == "available" {
        tool.path.as_deref().and_then(|path| read(path, canceled))
    } else {
        None
    };
    let (identity, sha256) = binding.map_or((None, None), |(id, digest)| (Some(id), Some(digest)));
    ToolSnapshot {
        name: tool.name,
        state: tool.state,
        path: tool.path,
        identity,
        sha256,
    }
}

fn read(path: &std::path::Path, canceled: &AtomicBool) -> Option<(String, String)> {
    let plan = publication::inspect(path).ok()?;
    let directory = publication::open_directory(plan.path.parent()?).ok()?;
    let mut file =
        publication::open_regular(&directory, plan.path.file_name()?.to_str()?).ok()??;
    let before = publication::snapshot_identity(&file).ok()?;
    if plan
        .target_identity
        .as_deref()
        .map(publication::snapshot_fingerprint)
        .as_ref()
        != Some(&before)
        || file.metadata().ok()?.len() > MAX_TOOL_BYTES
    {
        return None;
    }
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        if canceled.load(Ordering::Acquire) {
            return None;
        }
        let size = file.read(&mut buffer).ok()?;
        if size == 0 {
            break;
        }
        total += size as u64;
        if total > MAX_TOOL_BYTES {
            return None;
        }
        hash.update(&buffer[..size]);
    }
    if publication::snapshot_identity(&file).ok().as_ref() != Some(&before)
        || publication::inspect(path).ok().as_ref() != Some(&plan)
    {
        return None;
    }
    Some((before, format!("{:x}", hash.finalize())))
}
