use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn invoke(home: &Path, method: &str, params: Value) -> (bool, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"protocol_version":1,"request_id":"diagnostics-test","method":method,"params":params});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["result"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
}

fn manifest(home: &Path, binary: &str) {
    std::fs::create_dir_all(home.join("dependencies")).unwrap();
    std::fs::write(home.join("dependencies/manifest.json"), json!({"schema_version":1,"dependencies":[{"name":"fixture","required_version":"1","binary":binary,"source":"fixture","license":"MIT","license_notice":"fixture notice"}]}).to_string()).unwrap();
}

#[test]
fn passive_diagnostics_do_not_create_state_or_claim_authenticated() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("not-created");
    for method in ["diagnostics.inspect", "dependencies.inspect"] {
        let (ok, response) = invoke(&home, method, json!({}));
        assert!(ok, "{response}");
        assert!(!home.exists());
        assert_eq!(response["result"]["manifest_source"], "default");
        assert_eq!(check(&response, "manifest")["status"], "missing");
        assert!(!response["result"]["dependencies"]
            .as_array()
            .unwrap()
            .is_empty());
        if method == "diagnostics.inspect" {
            assert_eq!(check(&response, "credential")["status"], "not_checked");
            assert_eq!(
                check(&response, "server_connection")["status"],
                "not_checked"
            );
        }
    }
}

#[test]
fn invalid_params_never_repair_or_initialize_state() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    for (method, params) in [
        ("diagnostics.inspect", json!({"fix":true})),
        ("dependencies.inspect", json!({"fix":true})),
        ("dependencies.inspect", json!({"online":true})),
        ("diagnostics.inspect", json!({"verify_versions":"true"})),
    ] {
        let (ok, response) = invoke(&home, method, params);
        assert!(!ok);
        assert_eq!(response["error"]["code"], "invalid_params");
        assert!(!home.exists());
    }
}

#[test]
fn broken_configuration_and_manifest_have_distinct_results() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), "broken = [ private-input").unwrap();
    std::fs::write(home.path().join("state.sqlite3"), "not a database").unwrap();
    manifest(home.path(), "../../outside");
    let (ok, report) = invoke(
        home.path(),
        "diagnostics.inspect",
        json!({"verify_versions":true}),
    );
    assert!(ok, "{report}");
    assert_eq!(check(&report, "config")["status"], "invalid");
    assert_eq!(check(&report, "sqlite")["suggestion"], "presence_only");
    assert_eq!(report["result"]["dependencies"][0]["status"], "invalid");
    assert_eq!(
        report["result"]["dependencies"][0]["version_status"],
        "unsafe_path"
    );
    assert!(!report.to_string().contains("private-input"));
    std::fs::write(home.path().join("dependencies/manifest.json"), "{}").unwrap();
    let (_, report) = invoke(home.path(), "dependencies.inspect", json!({}));
    assert_eq!(check(&report, "manifest")["status"], "invalid");
    assert_eq!(report["result"]["manifest_source"], "unavailable");
    assert_eq!(report["result"]["dependencies"], json!([]));
}

#[cfg(unix)]
fn executable(path: &Path, content: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn version_probes_are_explicit_and_preserve_real_exit_and_output() {
    let home = tempfile::tempdir().unwrap();
    manifest(home.path(), "bin/fixture");
    let marker = home.path().join("ran");
    executable(
        &home.path().join("bin/fixture"),
        &format!(
            "#!/bin/sh\nprintf '%s' \"$1\" > '{}'\nprintf 'fixture version 1\\n'\n",
            marker.display()
        ),
    );
    let (ok, report) = invoke(home.path(), "dependencies.inspect", json!({}));
    assert!(ok);
    assert_eq!(
        report["result"]["dependencies"][0]["version_status"],
        "not_checked"
    );
    assert!(!marker.exists());
    let (ok, report) = invoke(
        home.path(),
        "dependencies.inspect",
        json!({"verify_versions":true}),
    );
    assert!(ok, "{report}");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "--version");
    assert_eq!(report["result"]["dependencies"][0]["version_status"], "ok");
    assert_eq!(
        report["result"]["dependencies"][0]["version_output"],
        "fixture version 1"
    );
    assert_eq!(report["result"]["dependencies"][0]["version_exit_code"], 0);
    executable(
        &home.path().join("bin/fixture"),
        "#!/bin/sh\nprintf 'not supported' >&2\nexit 7\n",
    );
    let (_, report) = invoke(
        home.path(),
        "dependencies.inspect",
        json!({"verify_versions":true}),
    );
    assert_eq!(
        report["result"]["dependencies"][0]["version_status"],
        "failed"
    );
    assert_eq!(
        report["result"]["dependencies"][0]["version_output"],
        "not supported"
    );
    assert_eq!(report["result"]["dependencies"][0]["version_exit_code"], 7);
}

#[cfg(unix)]
#[test]
fn version_probes_reject_escaping_symlinks_and_bound_time_and_output() {
    let home = tempfile::tempdir().unwrap();
    manifest(home.path(), "bin/fixture");
    std::fs::create_dir_all(home.path().join("bin")).unwrap();
    std::os::unix::fs::symlink("/bin/sh", home.path().join("bin/fixture")).unwrap();
    let (_, report) = invoke(
        home.path(),
        "dependencies.inspect",
        json!({"verify_versions":true}),
    );
    assert_eq!(
        report["result"]["dependencies"][0]["version_status"],
        "unsafe_path"
    );
    std::fs::remove_file(home.path().join("bin/fixture")).unwrap();
    executable(&home.path().join("bin/fixture"), "#!/bin/sh\nsleep 10\n");
    let start = std::time::Instant::now();
    let (_, report) = invoke(
        home.path(),
        "dependencies.inspect",
        json!({"verify_versions":true}),
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(7));
    assert_eq!(
        report["result"]["dependencies"][0]["version_status"],
        "timeout"
    );
    executable(
        &home.path().join("bin/fixture"),
        "#!/bin/sh\nwhile :; do printf '0123456789012345678901234567890123456789'; done\n",
    );
    let (_, report) = invoke(
        home.path(),
        "dependencies.inspect",
        json!({"verify_versions":true}),
    );
    assert_eq!(
        report["result"]["dependencies"][0]["version_status"],
        "output_limit"
    );
}

#[test]
fn online_health_check_is_explicit_and_never_authenticates() {
    let home = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    std::fs::write(
        home.path().join("config.toml"),
        format!("server_url = \"{server}\"\n"),
    )
    .unwrap();
    let (_, report) = invoke(home.path(), "diagnostics.inspect", json!({}));
    assert_eq!(check(&report, "server_connection")["status"], "not_checked");
    assert!(listener.accept().is_err());
    let worker = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut bytes = [0; 8192];
        let length = stream.read(&mut bytes).unwrap();
        let request = String::from_utf8_lossy(&bytes[..length]);
        assert!(request.starts_with("GET /healthz "));
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
        let body = r#"{"status":"ok"}"#;
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
    });
    let (ok, report) = invoke(home.path(), "diagnostics.inspect", json!({"online":true}));
    worker.join().unwrap();
    assert!(ok);
    assert_eq!(check(&report, "server_connection")["status"], "reachable");
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn seed_diagnostic_credential() {
    let Ok(home) = std::env::var("DIAGNOSTIC_TEST_SEED_HOME") else {
        return;
    };
    use agent_remote_cli::config::{AppPaths, Config};
    use agent_remote_cli::secrets::{user_token_key, SecretStore};
    let paths = AppPaths::new(Some(home.into())).unwrap();
    let server = "https://diagnostics.invalid";
    Config {
        server_url: Some(server.into()),
        active_device_id: None,
    }
    .save(&paths)
    .unwrap();
    SecretStore::new(paths.clone())
        .set_secret(&user_token_key(server), "private-diagnostic-token")
        .unwrap();
    let state = agent_remote_cli::local_state::LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
}

#[test]
fn explicit_deep_check_reads_credentials_and_sqlite_without_refresh_or_migration() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "seed_diagnostic_credential", "--nocapture"])
        .env("DIAGNOSTIC_TEST_SEED_HOME", home.path())
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let database = std::fs::read(home.path().join("state.sqlite3")).unwrap();
    let (ok, report) = invoke(
        home.path(),
        "diagnostics.inspect",
        json!({"deep_check":true}),
    );
    assert!(ok, "{report}");
    assert_eq!(check(&report, "credential")["status"], "present");
    assert_eq!(
        check(&report, "credential")["suggestion"],
        "credential_present"
    );
    assert_eq!(check(&report, "sqlite")["suggestion"], "sqlite_readable");
    assert_eq!(
        std::fs::read(home.path().join("state.sqlite3")).unwrap(),
        database
    );
    assert!(!report.to_string().contains("private-diagnostic-token"));
    std::fs::remove_dir_all(home.path().join("secrets")).unwrap();
    std::fs::write(home.path().join("state.sqlite3"), b"corrupt").unwrap();
    let (_, report) = invoke(
        home.path(),
        "diagnostics.inspect",
        json!({"deep_check":true}),
    );
    assert_eq!(check(&report, "credential")["status"], "missing");
    assert_eq!(check(&report, "sqlite")["status"], "invalid");
}

#[test]
fn oversized_manifest_is_reported_without_replacing_it() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("dependencies")).unwrap();
    let path = home.path().join("dependencies/manifest.json");
    let bytes = vec![b' '; 256 * 1024 + 1];
    std::fs::write(&path, &bytes).unwrap();
    let (ok, report) = invoke(home.path(), "dependencies.inspect", json!({}));
    assert!(ok);
    assert_eq!(check(&report, "manifest")["status"], "invalid");
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn passive_manifest_reader_rejects_fifo_without_waiting_for_writer() {
    use std::os::unix::ffi::OsStrExt;
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("dependencies")).unwrap();
    let path = home.path().join("dependencies/manifest.json");
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let start = std::time::Instant::now();
    let (ok, report) = invoke(home.path(), "dependencies.inspect", json!({}));
    assert!(ok);
    assert!(start.elapsed() < std::time::Duration::from_secs(3));
    assert_eq!(check(&report, "manifest")["status"], "invalid");
}

#[cfg(unix)]
#[test]
fn executable_permission_check_includes_files_with_extensions() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    manifest(home.path(), "bin/fixture.sh");
    std::fs::create_dir_all(home.path().join("bin")).unwrap();
    let path = home.path().join("bin/fixture.sh");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (ok, report) = invoke(home.path(), "dependencies.inspect", json!({}));
    assert!(ok);
    assert_eq!(
        report["result"]["dependencies"][0]["status"],
        "inaccessible"
    );
}
