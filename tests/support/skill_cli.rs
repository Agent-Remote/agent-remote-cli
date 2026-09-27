#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub const BIN: &str = env!("CARGO_BIN_EXE_agent-remote");
pub const OP: &str = "11111111-1111-4111-8111-111111111111";
pub const ACCOUNT: &str = "22222222-2222-4222-8222-222222222222";
pub const SKILL: &str = "33333333-3333-4333-8333-333333333333";
pub const REVISION: &str = "44444444-4444-4444-8444-444444444444";

pub fn private(path: &Path, body: String) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

pub fn home(server: &str) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::create_dir(home.path().join("secrets")).unwrap();
    fs::set_permissions(
        home.path().join("secrets"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    private(
        &home.path().join("config.toml"),
        format!("server_url = {server:?}\n"),
    );
    let name: String = format!("user-token:{server}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    private(&home.path().join("secrets").join(format!("{name}.secret")),json!({"version":1,"token":{"access_token":"skill-user-token","expires_in":3600,"refresh_token":"private-refresh","refresh_expires_in":2592000},"refresh_at":4102444800_u64,"expires_at":4102444800_u64,"session_expires_at":4102444800_u64}).to_string());
    home
}

pub fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--home")
        .arg(home)
        .args(args)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

pub fn request(stream: &mut TcpStream) -> String {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut byte = [0];
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 32 * 1024);
        assert_eq!(stream.read(&mut byte).unwrap(), 1);
        bytes.push(byte[0]);
    }
    let headers = String::from_utf8(bytes.clone()).unwrap();
    let length = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.parse::<usize>().ok())
        })
        .unwrap_or(0);
    assert!(length <= 64 * 1024 * 1024);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    bytes.extend(body);
    String::from_utf8(bytes).unwrap()
}

pub fn serve(responses: Vec<(u16, Value)>) -> (String, JoinHandle<Vec<String>>) {
    serve_with_hook(responses, |_, _| {})
}

pub fn serve_with_hook<F>(
    responses: Vec<(u16, Value)>,
    hook: F,
) -> (String, JoinHandle<Vec<String>>)
where
    F: Fn(usize, &str) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let thread = thread::spawn(move || {
        let mut requests = Vec::new();
        for (code, value) in responses {
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
                    Err(e) => panic!("client did not request expected response: {e}"),
                }
            };
            requests.push(request(&mut stream));
            hook(requests.len() - 1, requests.last().unwrap());
            if code == 0 {
                continue;
            }
            let body = value.to_string();
            write!(stream,"HTTP/1.1 {code} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        }
        requests
    });
    (url, thread)
}

pub fn envelope(data: Value) -> Value {
    json!({"schema_version":1,"operation_id":null,"status":"ready","committed":false,"retryable":false,"data":data,"errors":[]})
}
pub fn installation() -> Value {
    json!({"id":SKILL,"name":"sample","epoch":9007199254740993_i64,"removed":false,"source":{"kind":"local","locator":"a".repeat(64),"subpath":""},"tracking":{"ref_kind":"local","ref":"","commit":""},"default_enabled":true,"default_revision_id":REVISION,"revisions":[{"id":REVISION,"number":1,"content_digest":"b".repeat(64),"provenance":{"ref_kind":"local","ref":"","commit":""},"retained":true,"metadata":{"description":"Example"}}],"tool_overrides":{"claude":{"enabled":false,"revision_id":null}},"account_overrides":{},"effective":{"enabled":true,"revision_id":REVISION,"enabled_source":"account","revision_source":"user","eligible":true,"included":true,"exclusion_reason":null},"project_discovery":"not_inspected","model_loaded":false})
}
pub fn operation(status: &str, readiness: &str) -> Value {
    json!({"schema_version":1,"operation_id":OP,"status":status,"committed":true,"retryable":false,"data":{"generation":3,"skill_ids":[SKILL],"revision_ids":[REVISION],"changed":true,"warnings":[],"targets":[{"account_id":ACCOUNT,"node_id":null,"readiness":readiness,"deploy_on_first_use":readiness=="stored","error_code":null}],"replacement_id":null},"errors":[]})
}
pub fn json_output(output: &Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid single JSON result: {e}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert!(!String::from_utf8_lossy(&output.stdout).contains("skill-user-token"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-refresh"));
    value
}

pub fn local_skill() -> Value {
    json!({"origin":"account_local","id":SKILL,"account_id":ACCOUNT,"name":"notes",
        "status":"active","enabled":false,"default_revision_id":REVISION,
        "source_checkpoint_id":OP,"revisions":[{"id":REVISION,"number":1,
        "content_digest":"b".repeat(64),"retained":true,"subtree_prefix":"notes","metadata":{}}],
        "effective":{"enabled":false,"revision_id":REVISION,"enabled_source":"account",
        "revision_source":"account","eligible":true,"included":false,"exclusion_reason":null},"model_loaded":false})
}
