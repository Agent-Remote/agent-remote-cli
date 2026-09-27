#![allow(dead_code)]

use super::support::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const USER: &str = "55555555-5555-4555-8555-555555555555";
pub const CONFIRMATION: &str = "final-confirmation-do-not-print";

pub fn summary(total: usize) -> Value {
    json!({"binding":{"selector":{"account_id":ACCOUNT,"scope":"item","skill":SKILL},"cutoff":"2026-09-23T00:00:00Z","all_unreferenced":false,"plan_digest":"a".repeat(64)},
        "ready":true,"history_losses":total,"groups":usize::from(total > 0),"blocked_histories":0,"compacted_directories":0,"compacted_items":0,"trees":usize::from(total > 0),"package_bytes":0,"state_bytes":10,"pending_file_bytes":10})
}

pub fn rows(offset: usize, total: usize) -> Value {
    json!((offset..total.min(offset + 100)).map(|i| json!({"kind":"history","history":{"kind":"checkpoint","id":uuid::Uuid::from_u128(i as u128 + 1).to_string()},"retained":true,"selected":true,"group":1,"blockers":[],"dependency_blocked":false,"protected_by":[],"released_at":"2026-08-01T00:00:00Z","expires_at":"2026-09-01T00:00:00Z","archived":false,"content_digests":["b".repeat(64)]})).collect::<Vec<_>>())
}

pub fn page(offset: usize, total: usize) -> Value {
    let end = total.min(offset + 100);
    let mut value = envelope(
        json!({"summary":summary(total),"offset":offset,"total":total,"rows":rows(offset,total),"next_cursor":if end < total {Some(format!("page-{end}"))} else {None},"confirmation":if end == total {Some(CONFIRMATION)} else {None}}),
    );
    value["status"] = json!("preview");
    value
}

pub fn accepted(data: Value) -> Value {
    let mut value = envelope(data);
    value["operation_id"] = json!(OP);
    value["status"] = json!("accepted");
    value["committed"] = json!(true);
    value
}

pub fn receipt(total: usize, request: &Value) -> Value {
    accepted(
        json!({"operation_id":OP,"idempotency_key":request["idempotency_key"],"status":"accepted","confirmation_fingerprint":format!("{:x}",Sha256::digest(request["confirmation"].as_str().unwrap().as_bytes())),"summary":summary(total),"disclosure_rows":total}),
    )
}

pub fn entries(offset: usize, total: usize) -> Value {
    let end = total.min(offset + 100);
    accepted(
        json!({"operation_id":OP,"offset":offset,"total":total,"rows":rows(offset,total),"next_offset":if end < total {Some(end)} else {None}}),
    )
}

pub fn progress() -> Value {
    accepted(
        json!({"operation_id":OP,"pending_tasks":1,"completed_tasks":0,"pending_file_bytes":10,"deleted_file_bytes":0,"retrying_tasks":1}),
    )
}

pub fn rejected(code: &str) -> Value {
    json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,"retryable":false,"data":null,"errors":[{"code":code,"message":"rejected","object_id":null,"details":{}}]})
}

pub fn body(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}

pub enum Reply {
    User,
    Data(u16, Value),
    Receipt(usize),
    Tampered(usize),
    Disconnect,
    Block(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>),
}

pub fn reads(total: usize) -> Vec<Reply> {
    let mut replies = vec![Reply::User];
    for offset in (0..total.max(1)).step_by(100) {
        replies.push(Reply::Data(200, page(offset, total)));
    }
    replies
}

pub fn serve(replies: Vec<Reply>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let thread = thread::spawn(move || {
        let mut requests = Vec::new();
        let mut original =
            json!({"idempotency_key":"known-original-key","confirmation":CONFIRMATION});
        for reply in replies {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("expected prune request: {e}"),
                }
            };
            let request = request(&mut stream);
            if request.starts_with("POST /api/v1/skills/state/prune HTTP") {
                original = body(&request);
            }
            requests.push(request);
            let (code, value) = match reply {
                Reply::User => (200, json!({"data":{"id":USER}})),
                Reply::Data(code, value) => (code, value),
                Reply::Receipt(total) => (200, receipt(total, &original)),
                Reply::Tampered(total) => {
                    let mut value = receipt(total, &original);
                    value["data"]["summary"]["binding"]["plan_digest"] = json!("f".repeat(64));
                    (200, value)
                }
                Reply::Disconnect => continue,
                Reply::Block(ready, release) => {
                    ready.send(()).unwrap();
                    release.recv_timeout(Duration::from_secs(15)).unwrap();
                    continue;
                }
            };
            let body = value.to_string();
            let written = write!(stream,"HTTP/1.1 {code} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
            if let Err(error) = written {
                // The bounded client can reject Content-Length before this oversized body is sent.
                assert!(
                    body.len() > 1024 * 1024
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                        ),
                    "{error}"
                );
            }
        }
        requests
    });
    (url, thread)
}
