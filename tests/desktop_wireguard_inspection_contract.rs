use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

struct Fixture {
    temp: tempfile::TempDir,
    home: PathBuf,
    config: PathBuf,
    tool: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("missing-home");
        let config = temp.path().join("client.conf");
        let tool = temp
            .path()
            .join(if cfg!(windows) { "tool.exe" } else { "tool" });
        fs::write(
            &tool,
            b"#!/bin/sh\nprintf invoked > \"$WG_UNEXPECTED_EXECUTION\"\nexit 7\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            temp,
            home,
            config,
            tool,
        }
    }

    fn command(&self, binary: &str) -> Command {
        let mut command = Command::new(binary);
        command
            .env("AGENT_REMOTE_HOME", &self.home)
            .env("AGENT_REMOTE_WG", &self.tool)
            .env("AGENT_REMOTE_WG_QUICK", &self.tool)
            .env("AGENT_REMOTE_WIREGUARD", &self.tool)
            .env("WG_UNEXPECTED_EXECUTION", self.temp.path().join("invoked"));
        command
    }

    fn write(&self, bytes: &[u8]) {
        fs::write(&self.config, bytes).unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.config)
            .unwrap();
        agent_remote_cli::platform::set_private_wireguard_file_permissions(&file).unwrap();
    }

    fn request(&self, method: &str, params: Value) -> (bool, Value) {
        let mut child = self
            .command(env!("CARGO_BIN_EXE_agent-remote"))
            .arg("--desktop-control")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let request =
            json!({"protocol_version":1,"request_id":"inspect-wg","method":method,"params":params});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.stderr.is_empty());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(!value.to_string().contains(&STANDARD.encode([7; 32])));
        assert!(!value.to_string().contains("SECRET_COMMAND_PAYLOAD"));
        (output.status.success(), value)
    }

    fn check(&self, config: Option<&Path>) -> Value {
        let (ok, value) = self.request(
            "wireguard.check",
            json!({"expected_home":self.home,"config":config}),
        );
        assert!(ok, "{value}");
        value["result"].clone()
    }

    fn assert_untouched(&self) {
        assert!(!self.home.exists());
        assert!(!self.temp.path().join("invoked").exists());
    }
}

fn valid_config() -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.77.0.2\nMTU = 1000\n",
        STANDARD.encode([7; 32])
    )
}

#[test]
fn check_is_local_passive_and_returns_only_the_documented_snapshot() {
    let fixture = Fixture::new();
    let missing = fixture.check(None);
    assert_eq!(missing["home"], fixture.home.to_str().unwrap());
    assert_eq!(missing["config"]["state"], "missing");
    let expected_path = fixture.home.join("wireguard").join("agent-remote.conf");
    assert_eq!(missing["config"]["path"], expected_path.to_str().unwrap());
    assert!(missing["config"]["mtu"].is_null());
    assert!(missing["config"]["peer_count"].is_null());
    fixture.write(valid_config().as_bytes());
    let ready = fixture.check(Some(&fixture.config));
    assert_eq!(ready["config"]["state"], "ready");
    assert_eq!(ready["config"]["path"], fixture.config.to_str().unwrap());
    assert_eq!(ready["config"]["addresses"], json!(["10.77.0.2"]));
    assert_eq!(ready["config"]["mtu"], 1000);
    assert_eq!(ready["config"]["peer_count"], 0);
    assert_eq!(ready["config"]["unsupported_directives"], json!([]));
    assert_eq!(ready["tools"][0]["name"], "wg");
    assert_eq!(ready["tools"][0]["state"], "available");
    fixture.assert_untouched();
}

#[test]
fn unsupported_directives_are_named_without_executing_or_exposing_their_values() {
    let fixture = Fixture::new();
    fixture.write(
        format!(
            "{}PostUp = SECRET_COMMAND_PAYLOAD\nSaveConfig = true\n",
            valid_config()
        )
        .as_bytes(),
    );
    let result = fixture.check(Some(&fixture.config));
    assert_eq!(result["config"]["state"], "unsupported");
    assert_eq!(
        result["config"]["unsupported_directives"],
        json!(["PostUp", "SaveConfig"])
    );
    assert_eq!(result["config"]["peer_count"], 0);
    fixture.assert_untouched();
}

#[test]
fn malformed_and_oversized_configurations_never_return_partial_fields() {
    let fixture = Fixture::new();
    for bytes in [
        format!("{}Unknown = SECRET_COMMAND_PAYLOAD\n", valid_config()).into_bytes(),
        vec![b' '; 1024 * 1024 + 1],
        vec![0xff],
    ] {
        fixture.write(&bytes);
        let result = fixture.check(Some(&fixture.config));
        assert_eq!(result["config"]["state"], "invalid");
        assert_eq!(result["config"]["addresses"], json!([]));
        assert_eq!(result["config"]["dns"], json!([]));
        assert!(result["config"]["mtu"].is_null());
        assert!(result["config"]["peer_count"].is_null());
    }
    fixture.assert_untouched();
}

#[test]
fn unusable_explicit_tool_overrides_never_fall_back_or_execute() {
    let fixture = Fixture::new();
    fixture.write(valid_config().as_bytes());
    fs::remove_file(&fixture.tool).unwrap();
    let check = fixture.check(Some(&fixture.config));
    for tool in check["tools"].as_array().unwrap() {
        assert_eq!(tool["state"], "missing");
        assert!(tool["path"].is_null());
    }
    let (ok, value) = fixture.request("wireguard.status", json!({"expected_home":fixture.home}));
    assert!(ok);
    assert_eq!(value["result"]["state"], "tool_missing");
    assert_eq!(value["result"]["interfaces"], json!([]));
    fs::create_dir(&fixture.tool).unwrap();
    let check = fixture.check(Some(&fixture.config));
    for tool in check["tools"].as_array().unwrap() {
        assert_eq!(tool["state"], "not_executable");
        assert!(tool["path"].is_string());
    }
    let (ok, value) = fixture.request("wireguard.status", json!({"expected_home":fixture.home}));
    assert!(ok);
    assert_eq!(value["result"]["state"], "tool_not_executable");
    assert_eq!(value["result"]["interfaces"], json!([]));
    fixture.assert_untouched();
}

#[cfg(unix)]
#[test]
fn unsafe_paths_and_permissions_are_rejected_without_opening_fifo_or_following_links() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let fixture = Fixture::new();
    fixture.write(valid_config().as_bytes());
    fs::set_permissions(&fixture.config, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        fixture.check(Some(&fixture.config))["config"]["state"],
        "insecure_permissions"
    );
    fs::remove_file(&fixture.config).unwrap();
    let outside = fixture.temp.path().join("outside");
    fs::write(&outside, valid_config()).unwrap();
    symlink(&outside, &fixture.config).unwrap();
    assert_eq!(
        fixture.check(Some(&fixture.config))["config"]["state"],
        "unsafe_path"
    );
    fs::remove_file(&fixture.config).unwrap();
    fs::hard_link(&outside, &fixture.config).unwrap();
    assert_eq!(
        fixture.check(Some(&fixture.config))["config"]["state"],
        "unsafe_path"
    );
    fs::remove_file(&fixture.config).unwrap();
    let fifo = std::ffi::CString::new(fixture.config.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_eq!(
        fixture.check(Some(&fixture.config))["config"]["state"],
        "unsafe_path"
    );
    fs::remove_file(&fixture.config).unwrap();
    fs::create_dir(&fixture.config).unwrap();
    assert_eq!(
        fixture.check(Some(&fixture.config))["config"]["state"],
        "unsafe_path"
    );
    fixture.assert_untouched();
}

#[test]
fn requests_bind_home_and_reject_relative_config_and_unknown_fields() {
    let fixture = Fixture::new();
    for (method, params, code) in [
        (
            "wireguard.check",
            json!({"expected_home":fixture.temp.path(),"config":null}),
            "configuration_changed",
        ),
        (
            "wireguard.check",
            json!({"expected_home":fixture.home,"config":"relative.conf"}),
            "invalid_params",
        ),
        (
            "wireguard.check",
            json!({"expected_home":fixture.home,"config":null,"execute":true}),
            "invalid_params",
        ),
        (
            "wireguard.status",
            json!({"expected_home":fixture.temp.path()}),
            "configuration_changed",
        ),
        (
            "wireguard.status",
            json!({"expected_home":fixture.home,"sudo":true}),
            "invalid_params",
        ),
    ] {
        let (ok, value) = fixture.request(method, params);
        assert!(!ok);
        assert_eq!(value["error"]["code"], code);
    }
    fixture.assert_untouched();
}

#[test]
fn cli_and_helper_check_accept_dry_run_and_share_the_strict_parser() {
    let fixture = Fixture::new();
    fixture.write(valid_config().as_bytes());
    for helper in [false, true] {
        let mut command = fixture.command(if helper {
            env!("CARGO_BIN_EXE_agent-remote-wireguard")
        } else {
            env!("CARGO_BIN_EXE_agent-remote")
        });
        command.args(["--color", "never"]);
        if !helper {
            command.arg("wireguard");
        }
        let output = command
            .arg("check")
            .arg("--config")
            .arg(&fixture.config)
            .arg("--dry-run")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("WireGuard configuration is readable")
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(&STANDARD.encode([7; 32])));
    }
    fixture.assert_untouched();
    fixture.write(b"[Interface]\nPrivateKey = invalid\n");
    let output = fixture
        .command(env!("CARGO_BIN_EXE_agent-remote"))
        .args(["wireguard", "check", "--config"])
        .arg(&fixture.config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid"));
}

#[cfg(unix)]
#[test]
fn status_machine_output_discards_private_keys_psks_and_raw_failures() {
    let fixture = Fixture::new();
    let private = STANDARD.encode([7; 32]);
    let public = STANDARD.encode([8; 32]);
    let psk = STANDARD.encode([9; 32]);
    let peer = STANDARD.encode([10; 32]);
    fs::write(&fixture.tool, format!("#!/bin/sh\n[ \"$*\" = 'show all dump' ] || exit 8\nprintf '%s\\n' 'wg0\t{private}\t{public}\t51820\toff' 'wg0\t{peer}\t{psk}\t127.0.0.1:51820\t10.77.0.0/24\t0\t12\t34\t25'\n")).unwrap();
    let (ok, value) = fixture.request("wireguard.status", json!({"expected_home":fixture.home}));
    assert!(ok, "{value}");
    let result = &value["result"];
    assert_eq!(result["state"], "observed");
    assert_eq!(result["interfaces"][0]["public_key"], public);
    assert_eq!(result["interfaces"][0]["peers"][0]["public_key"], peer);
    assert_eq!(result["interfaces"][0]["peers"][0]["received_bytes"], 12);
    assert!(!value.to_string().contains(&psk));
    fs::write(
        &fixture.tool,
        format!("#!/bin/sh\nprintf '%s' 'Permission denied {private} {psk}' >&2\nexit 1\n"),
    )
    .unwrap();
    let (ok, value) = fixture.request("wireguard.status", json!({"expected_home":fixture.home}));
    assert!(ok, "{value}");
    assert_eq!(value["result"]["state"], "query_failed");
    assert_eq!(value["result"]["interfaces"], json!([]));
    assert!(!value.to_string().contains(&psk));
    assert!(!value.to_string().contains("Permission denied"));
    fixture.assert_untouched();
}

#[cfg(unix)]
#[test]
fn status_sigterm_cancels_and_cleans_up_the_private_tool_process_group() {
    use std::time::{Duration, Instant};
    let fixture = Fixture::new();
    let marker = fixture.temp.path().join("tool-pids");
    fs::write(
        &fixture.tool,
        "#!/bin/sh\n/bin/sleep 30 &\nprintf '%s %s' \"$$\" \"$!\" > \"$WG_TOOL_PIDS\"\nwait\n",
    )
    .unwrap();
    let mut child = fixture
        .command(env!("CARGO_BIN_EXE_agent-remote"))
        .env("WG_TOOL_PIDS", &marker)
        .arg("--desktop-control")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"protocol_version":1,"request_id":"cancel-status","method":"wireguard.status","params":{"expected_home":fixture.home}});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let pids: Vec<i32> = loop {
        let pids: Vec<i32> = fs::read_to_string(&marker)
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|pid| pid.parse().ok())
            .collect();
        if pids.len() == 2 {
            break pids;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("status probe did not reach barrier");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let deadline = Instant::now() + Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("status wrapper did not terminate after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "canceled");
    for pid in pids {
        let deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { libc::kill(pid, 0) } == 0 {
            #[cfg(target_os = "linux")]
            if fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.split_once(") ")
                    .is_some_and(|(_, rest)| rest.starts_with('Z'))
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "status tool process remains alive"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fixture.assert_untouched();
}
