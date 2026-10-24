use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use agent_remote_cli::{config::AppPaths, local_state::LocalState};
use base64::Engine;
use serde_json::{json, Value};

pub const DEVICE: &str = "device-test";
pub const TOKEN: &str = "wireguard-contract-device-token";

#[derive(Clone, Default)]
pub struct Behavior {
    pub enroll_status: Option<u16>,
    pub drop_enroll: bool,
    pub wrong_enroll_device: bool,
    pub invalid_config: bool,
    pub config_status: Option<u16>,
    pub change_output: Option<PathBuf>,
    pub enroll_barrier: Option<PathBuf>,
    pub enroll_body: Option<String>,
    pub config_body: Option<String>,
}

pub struct Fixture {
    pub temp: tempfile::TempDir,
    pub home: PathBuf,
    pub server: String,
    pub requests: Arc<Mutex<Vec<(String, Value)>>>,
    stopped: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    pub fn new(behavior: Behavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let (stop, calls) = (stopped.clone(), requests.clone());
        let thread = std::thread::spawn(move || {
            let mut enrolled_public_key: Option<String> = None;
            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                        let (request, body) = read_request(&mut stream);
                        calls.lock().unwrap().push((request.clone(), body.clone()));
                        if request.contains("/wireguard/peer") {
                            if let Some(public_key) = body.get("public_key").and_then(Value::as_str)
                            {
                                enrolled_public_key = Some(public_key.to_owned());
                            }
                            if let Some(marker) = &behavior.enroll_barrier {
                                fs::write(marker, b"request accepted locally").unwrap();
                                while !stop.load(Ordering::Acquire) {
                                    std::thread::sleep(std::time::Duration::from_millis(5));
                                }
                                continue;
                            }
                            if behavior.drop_enroll {
                                continue;
                            }
                            if let Some(body) = &behavior.enroll_body {
                                respond_raw(&mut stream, body);
                                continue;
                            }
                            let status = behavior.enroll_status.unwrap_or(200);
                            let device = if behavior.wrong_enroll_device {
                                "other-device"
                            } else {
                                DEVICE
                            };
                            respond(
                                &mut stream,
                                status,
                                json!({"data":{"device_id":device,"peer_id":"peer-test","interface_address":"10.77.0.2","peer_version":1}}),
                            );
                        } else if request.contains("/wireguard/config") {
                            if let Some(body) = &behavior.config_body {
                                respond_raw(&mut stream, body);
                                continue;
                            }
                            if let Some(path) = &behavior.change_output {
                                fs::write(path, b"concurrent-user-edit").unwrap();
                            }
                            let address = if behavior.invalid_config {
                                "10.77.0.2\nPostUp = forbidden"
                            } else {
                                "10.77.0.2"
                            };
                            let peer_public_key =
                                enrolled_public_key.clone().unwrap_or_else(|| {
                                    base64::engine::general_purpose::STANDARD.encode([6u8; 32])
                                });
                            respond(
                                &mut stream,
                                behavior.config_status.unwrap_or(200),
                                json!({"data":{
                                    "device_id":DEVICE,"peer_id":"peer-test","peer_public_key":peer_public_key,"peer_version":1,"interface_address":address,"private_key_ref":"local-only","dns":[],"peers":[]
                                }}),
                            );
                        } else if request.contains("/auth/refresh") {
                            respond(
                                &mut stream,
                                200,
                                json!({"data":{"access_token":TOKEN,"expires_in":3600}}),
                            );
                        } else {
                            respond(&mut stream, 404, json!({}));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5))
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            }
        });
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let paths = AppPaths::new(Some(home.clone())).unwrap();
        assert!(
            agent_remote_cli::setup::initialize(&paths)
                .unwrap()
                .complete
        );
        fs::write(
            paths.config_path(),
            format!("server_url = {server:?}\nactive_device_id = {DEVICE:?}\n"),
        )
        .unwrap();
        private_file(
            &secret_path(&home, &format!("device-token:{server}:{DEVICE}")),
            TOKEN.as_bytes(),
        );
        LocalState::open(&paths)
            .unwrap()
            .set_kv(
                &format!("device-token-refresh-at:{server}:{DEVICE}"),
                "4102444800",
            )
            .unwrap();
        Self {
            temp,
            home,
            server,
            requests,
            stopped,
            thread: Some(thread),
        }
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-remote"));
        command
            .env("AGENT_REMOTE_HOME", &self.home)
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .env(
                "AGENT_REMOTE_WIREGUARD_LOCK_ROOT",
                self.temp.path().join("locks"),
            );
        command
    }

    pub fn invoke(&self, method: &str, params: Value) -> (bool, Value) {
        let mut child = self
            .command()
            .arg("--desktop-control")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let request =
            json!({"protocol_version":1,"request_id":"wg-test","method":method,"params":params});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.stderr.is_empty(), "machine diagnostics leaked");
        assert_eq!(
            output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
            1
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status.success(), value)
    }

    pub fn plan(&self, output: Option<&Path>) -> Value {
        let (ok, value) = self.invoke(
            "wireguard.config.plan",
            json!({"expected_home":self.home,"output":output}),
        );
        assert!(ok, "{value}");
        value["result"].clone()
    }

    pub fn apply(&self, plan: Value) -> Value {
        let (ok, value) = self.invoke(
            "wireguard.config.apply",
            json!({"confirmed":true,"expected_plan":plan}),
        );
        assert!(ok, "{value}");
        assert_eq!(value["result"]["operation_id"], "wg-test");
        value["result"].clone()
    }

    pub fn private_path(&self) -> PathBuf {
        secret_path(
            &self.home,
            &format!("wireguard-private-key:{}:{DEVICE}", self.server),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let result = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            assert!(result.is_ok(), "HTTP fixture failed");
        }
    }
}

pub fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn secret_path(home: &Path, key: &str) -> PathBuf {
    let name: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    home.join("secrets").join(format!("{name}.secret"))
}

fn read_request(stream: &mut TcpStream) -> (String, Value) {
    let mut bytes = Vec::new();
    let end = loop {
        let mut chunk = [0; 1024];
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0 && bytes.len() < 16384);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(at) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let length: usize = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|value| value.trim().parse().unwrap())
        })
        .unwrap_or(0);
    assert!(length < 16384);
    while bytes.len() < end + length {
        let mut chunk = [0; 1024];
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
    }
    let body = if length == 0 {
        Value::Null
    } else {
        serde_json::from_slice(&bytes[end..end + length]).unwrap()
    };
    (headers.lines().next().unwrap().to_owned(), body)
}

fn respond(stream: &mut TcpStream, status: u16, body: Value) {
    let body = body.to_string();
    write!(stream, "HTTP/1.1 {status} response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
}

fn respond_raw(stream: &mut TcpStream, body: &str) {
    // A bounded client may close an oversized response before the fixture finishes writing.
    let _ = write!(stream, "HTTP/1.1 200 response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}
