//! Private temporary disclosure survives paging without inflating the command journal or heap.

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use anyhow::{bail, Context, Result};
use serde::ser::{Error, SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use crate::api::skill_state::PruneDisclosure;
use crate::api::skills::SkillResult;

const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(super) struct Spool {
    file: File,
    pub rows: u64,
    bytes: u64,
}

impl Spool {
    pub async fn new() -> Result<Self> {
        tokio::task::spawn_blocking(|| {
            Ok(Self {
                file: tempfile::tempfile()?,
                rows: 0,
                bytes: 0,
            })
        })
        .await?
    }

    pub async fn append(mut self, rows: Vec<PruneDisclosure>) -> Result<Self> {
        tokio::task::spawn_blocking(move || {
            for row in rows {
                let bytes = serde_json::to_vec(&row)?;
                self.bytes = self.bytes.checked_add(bytes.len() as u64 + 1).context("prune disclosure size overflow")?;
                if self.bytes > MAX_BYTES { bail!("Complete prune disclosure exceeds the 2 GiB temporary display limit; nothing was submitted."); }
                self.file.write_all(&bytes)?;
                self.file.write_all(b"\n")?;
                self.rows += 1;
            }
            Ok(self)
        }).await?
    }

    pub async fn display(
        mut self,
        result: SkillResult<Value>,
        json: bool,
        displaying: &Cell<bool>,
    ) -> Result<()> {
        displaying.set(true);
        let cancelled = Arc::new(AtomicBool::new(false));
        let _guard = CancelDisplay(cancelled.clone());
        let (send, receive) = tokio::sync::oneshot::channel();
        // Output has no mutation authority; a blocked pipe must not hold Tokio shutdown after Ctrl-C.
        std::thread::Builder::new()
            .name("prune-display".to_owned())
            .spawn(move || {
                let result = (|| {
                    self.file.seek(SeekFrom::Start(0))?;
                    if !json {
                        for line in serde_json::to_string_pretty(&result)?.lines() {
                            eprintln!("{}", super::super::safe(line));
                        }
                        for line in BufReader::new(self.file).lines() {
                            if cancelled.load(Ordering::Relaxed) {
                                bail!("prune display interrupted");
                            }
                            eprintln!("{}", super::super::safe(&line?));
                        }
                        return Ok(());
                    }
                    let metadata = result
                        .data
                        .context("prune display metadata missing")?
                        .as_object()
                        .context("invalid prune display metadata")?
                        .clone();
                    let output = SkillResult {
                        schema_version: result.schema_version,
                        operation_id: result.operation_id,
                        status: result.status,
                        committed: result.committed,
                        retryable: result.retryable,
                        errors: result.errors,
                        data: Some(DisplayData {
                            metadata,
                            rows: Rows {
                                reader: RefCell::new(BufReader::new(self.file)),
                                cancelled,
                            },
                        }),
                    };
                    let stdout = std::io::stdout();
                    let mut writer = stdout.lock();
                    serde_json::to_writer(&mut writer, &output)?;
                    writer.write_all(b"\n")?;
                    writer.flush()?;
                    Ok(())
                })();
                let _ = send.send(result);
            })?;
        let result = receive.await.context("prune display unavailable")?;
        // A partially written JSON envelope cannot be followed by another error envelope.
        result.map_err(|_| anyhow::Error::from(super::super::SkillExit(1)))?;
        displaying.set(false);
        Ok(())
    }
}

struct DisplayData {
    metadata: Map<String, Value>,
    rows: Rows,
}

impl Serialize for DisplayData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.metadata.len() + 1))?;
        for (key, value) in &self.metadata {
            map.serialize_entry(key, value)?;
        }
        map.serialize_entry("rows", &self.rows)?;
        map.end()
    }
}

struct CancelDisplay(Arc<AtomicBool>);
impl Drop for CancelDisplay {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

struct Rows {
    reader: RefCell<BufReader<File>>,
    cancelled: Arc<AtomicBool>,
}

impl Serialize for Rows {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        let mut reader = self.reader.borrow_mut();
        let mut line = String::new();
        loop {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(S::Error::custom("prune display interrupted"));
            }
            line.clear();
            if reader.read_line(&mut line).map_err(S::Error::custom)? == 0 {
                break;
            }
            let row: PruneDisclosure = serde_json::from_str(&line).map_err(S::Error::custom)?;
            sequence.serialize_element(&row)?;
        }
        sequence.end()
    }
}
