use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub struct Reply {
    pub status: u16,
    pub body: Option<Vec<u8>>,
    pub advertised_length: Option<usize>,
}
impl Reply {
    pub fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            body: Some(body.to_string().into_bytes()),
            advertised_length: None,
        }
    }
}
pub struct Fixture {
    pub _temp: tempfile::TempDir,
    pub home: std::path::PathBuf,
    pub context: Value,
    pub requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Fixture {
    pub fn new(replies: Vec<Reply>) -> Self {
        Self::with_hook(replies, None)
    }
    pub fn with_hook(replies: Vec<Reply>, mut hook: Option<Box<dyn FnOnce() + Send>>) -> Self {
        Self::with_device(replies, hook.take(), "device-test")
    }
    pub fn with_device(
        replies: Vec<Reply>,
        mut hook: Option<Box<dyn FnOnce() + Send>>,
        device: &str,
    ) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = format!("http://{}", listener.local_addr().unwrap());
        let seeded = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "seed_account_device"])
            .env("ACCOUNT_TEST_SERVER", &server)
            .env("ACCOUNT_TEST_DEVICE", device)
            .env("AGENT_REMOTE_HOME", &home)
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .output()
            .unwrap();
        assert!(
            seeded.status.success(),
            "{}",
            String::from_utf8_lossy(&seeded.stderr)
        );
        let context = json!({"home":home,"server_url":server,"active_device_id":device});
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let worker_stop = stop.clone();
        let captured = requests.clone();
        let thread = std::thread::spawn(move || {
            let mut replies: VecDeque<_> = replies.into();
            // Bound idle HTTP waiting, not the duration of a multi-process review,
            // apply, status and forget scenario.
            let mut deadline = Instant::now() + Duration::from_secs(15);
            while !worker_stop.load(Ordering::Acquire) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                };
                deadline = Instant::now() + Duration::from_secs(15);
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    if let Some(position) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        break position + 4;
                    }
                    let mut block = [0; 1024];
                    let n = stream.read(&mut block).unwrap();
                    assert!(n > 0 && bytes.len() < 65536);
                    bytes.extend_from_slice(&block[..n]);
                };
                let header = String::from_utf8_lossy(&bytes[..header_end]);
                let content_length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(content_length < 65536);
                while bytes.len() < header_end + content_length {
                    let mut block = [0; 1024];
                    let n = stream.read(&mut block).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&block[..n]);
                }
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(bytes).unwrap());
                if let Some(hook) = hook.take() {
                    hook();
                }
                let reply = replies.pop_front().expect("unexpected API retry/request");
                if let Some(body) = reply.body {
                    let _=write!(stream,"HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.status,reply.advertised_length.unwrap_or(body.len()));
                    let _ = stream.write_all(&body);
                }
            }
        });
        Self {
            _temp: temp,
            home,
            context,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    pub fn action(&self) -> Value {
        json!({"confirmed":true,"expected_context":self.context,"account_id":ACCOUNT_ID})
    }
    pub fn create(&self) -> Value {
        json!({"confirmed":true,"expected_context":self.context,"tool":"claude","name":"测试 account","region":"SG","timezone":"Asia/Singapore","locale":"zh_CN.UTF-8","tags":["gpu","preferred:asia"]})
    }
    pub fn invoke(&self, method: &str, params: Value) -> (bool, Value) {
        invoke(&self.home, method, params)
    }
    pub fn wires(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}
pub const ACCOUNT_ID: &str = "12345678-1234-1234-1234-123456789abc";
pub fn account(status: &str) -> Value {
    json!({"id":ACCOUNT_ID,"user_id":"secret-user-id","tool_type":"claude","display_name":"测试 account","status":status,"region_code":"SG","timezone":"Asia/Singapore","locale":"zh_CN.UTF-8","preferred_node_tags":["gpu","preferred:asia"],"affinity_node_id":null,"runtime_backend":null,"created_at":"2026-10-18T00:00:00Z","updated_at":"2026-10-18T00:00:00Z","private_cookie":"secret-cookie"})
}
pub fn binding(status: &str) -> Value {
    json!({"tool_account_id":ACCOUNT_ID,"status":status,"node_id":"node-test","binding_session_id":"bind-test","tmux_session_name":"claude-test","account_remote_path":"/accounts/test","task_id":"create_binding_session:account:attempt","verifier":"secret-verifier","connect_command":"ssh attacker secret-command","error":"secret-binding-error"})
}
pub fn envelope(value: Value) -> Reply {
    Reply::json(200, json!({"data":value}))
}
pub fn request(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"protocol_version":1,"request_id":"account-operation","method":method,"params":params})).unwrap()
}
pub fn command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-remote"));
    command
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
pub fn invoke(home: &Path, method: &str, params: Value) -> (bool, Value) {
    let mut child = command(home).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request(method, params))
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout.iter().filter(|&&v| v == b'\n').count(), 1);
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}
pub fn redact(response: &Value) {
    let value = response.to_string();
    for secret in [
        "secret-verifier",
        "secret-command",
        "secret-binding-error",
        "secret-cookie",
        "secret-user-id",
        "account-test-token",
    ] {
        assert!(!value.contains(secret), "leaked {secret}");
    }
}
