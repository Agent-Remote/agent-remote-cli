#![allow(dead_code)]

use agent_remote_cli::skills::manifest::{ContentKind, Entry, EntryKind, Manifest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::support::*;

pub const SECOND: &str = "55555555-5555-4555-8555-555555555555";

pub fn file(path: &str, bytes: &[u8]) -> Entry {
    Entry {
        path: path.to_owned(),
        kind: EntryKind::File,
        mode: 0o750,
        size: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        target: String::new(),
        content_kind: if std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0) {
            ContentKind::Text
        } else {
            ContentKind::Binary
        },
        dependency: String::new(),
    }
}

pub fn directory(path: &str) -> Entry {
    Entry {
        path: path.to_owned(),
        kind: EntryKind::Directory,
        mode: 0o700,
        size: 0,
        sha256: String::new(),
        target: String::new(),
        content_kind: ContentKind::Empty,
        dependency: String::new(),
    }
}

pub fn link(path: &str, target: &str, runtime: bool) -> Entry {
    Entry {
        path: path.to_owned(),
        kind: if runtime {
            EntryKind::RuntimeLink
        } else {
            EntryKind::Symlink
        },
        mode: 0o777,
        size: 0,
        sha256: String::new(),
        target: target.to_owned(),
        content_kind: ContentKind::Empty,
        dependency: if runtime {
            "python".to_owned()
        } else {
            String::new()
        },
    }
}

pub fn checkpoint(directory: bool) -> Value {
    json!({"id":OP,"account_id":ACCOUNT,"scope":if directory {"account-directory"} else {"item"},
        "state_id":if directory {None} else {Some(SECOND)},"skill_id":if directory {None} else {Some(SKILL)},
        "origin":if directory {None} else {Some("user_library")},"revision_id":if directory {None} else {Some(REVISION)},
        "installation_epoch":if directory {None} else {Some(9007199254740993_i64)},
        "state_epoch":if directory {None} else {Some(7)},"directory_epoch":3,
        "backing_directory_id":if directory {None} else {Some(SECOND)},
        "current_state_epoch":if directory {None} else {Some(9)},"current_directory_epoch":4,
        "subtree_prefix":if directory {""} else {"sample"},"parent_id":null,"content_digest":"a".repeat(64),
        "retained":true,"is_head":false,"invalid_skill_format":false,"source_session_reference_id":SECOND,
        "finalization_id":SECOND,"finalization_status":"detached","storage_location":"server","created_at":"2026-09-22T12:00:00Z"})
}

pub fn tree(checkpoint: &mut Value, manifest: &Manifest) -> Value {
    let digest = manifest.digest().unwrap();
    checkpoint["content_digest"] = json!(digest);
    json!({"checkpoint_id":OP,"source_tree_digest":digest,"tree_digest":digest,
        "subtree_prefix":checkpoint["subtree_prefix"],"dependency_roots":[],"locally_removed":false,"manifest":manifest})
}

pub fn pending() -> Value {
    json!({"id":SECOND,"snapshot_id":OP,"session_reference_id":OP,"node_id":REVISION,
        "incoming_digest":"b".repeat(64),"status":"upload_pending","storage_location":"source_node","exportable_from_server":false})
}

pub fn diff() -> Value {
    json!({"checkpoint_id":OP,"base_kind":"package_revision","base_reference_id":REVISION,
        "base_tree_digest":"a".repeat(64),"current_tree_digest":"b".repeat(64),
        "items":[{"path":"sample/memory","base":null,"current":file("sample/memory",b"memory")}],"next_cursor":null})
}

pub enum Response {
    Disconnect,
    Rejected(u16, Value),
    Json(Value),
    File {
        bytes: Vec<u8>,
        digest: String,
        length: usize,
    },
}

pub fn serve_raw(
    responses: Vec<Response>,
    hook: impl Fn(usize) + Send + 'static,
) -> (String, std::thread::JoinHandle<Vec<String>>) {
    use std::io::Write;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for (index, response) in responses.into_iter().enumerate() {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("expected request: {e}"),
                }
            };
            requests.push(request(&mut stream));
            hook(index);
            let mut code = 200;
            let (bytes, digest, length) = match response {
                Response::Rejected(status, value) => {
                    code = status;
                    let bytes = value.to_string().into_bytes();
                    let len = bytes.len();
                    (bytes, None, len)
                }
                Response::Disconnect => continue,
                Response::Json(value) => {
                    let bytes = value.to_string().into_bytes();
                    let len = bytes.len();
                    (bytes, None, len)
                }
                Response::File {
                    bytes,
                    digest,
                    length,
                } => (bytes, Some(digest), length),
            };
            write!(
                stream,
                "HTTP/1.1 {code} Test\r\nContent-Length: {length}\r\nConnection: close\r\n"
            )
            .unwrap();
            if let Some(digest) = digest {
                write!(stream, "ETag: \"{digest}\"\r\n").unwrap();
            }
            write!(stream, "\r\n").unwrap();
            let _ = stream.write_all(&bytes);
        }
        requests
    });
    (url, thread)
}
