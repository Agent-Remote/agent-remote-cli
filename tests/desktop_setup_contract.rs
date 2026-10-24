use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use agent_remote_cli::{config::AppPaths, local_state::LocalState};
use serde_json::{json, Value};

fn command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-remote"));
    command
        .env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file");
    command
}

fn invoke(home: &Path, params: Value) -> (bool, Value) {
    let mut child = command(home)
        .arg("--desktop-control")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"protocol_version":1,"request_id":"setup-123","method":"setup.local","params":params});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout.iter().filter(|&&b| b == b'\n').count(), 1);
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["request_id"], "setup-123");
    (output.status.success(), response)
}

fn setup(home: &Path) -> Value {
    let (ok, response) = invoke(home, json!({"confirmed":true,"expected_home":home}));
    assert!(ok, "{response}");
    assert_eq!(response["phase"], "completed");
    let result = response["result"].clone();
    assert_eq!(result["operation_id"], "setup-123");
    assert_eq!(result["home"], home.to_str().unwrap());
    let ids = [
        "home",
        "bin",
        "dependencies",
        "secrets",
        "wireguard",
        "ssh",
        "database",
        "manifest",
    ];
    let suffixes = [
        "",
        "bin",
        "dependencies",
        "secrets",
        "wireguard",
        "ssh",
        "state.sqlite3",
        "dependencies/manifest.json",
    ];
    let steps = result["steps"].as_array().unwrap();
    assert_eq!(steps.len(), ids.len());
    for ((step, id), suffix) in steps.iter().zip(ids).zip(suffixes) {
        assert_eq!(step["id"], id);
        let expected = if suffix == "dependencies/manifest.json" {
            // Keep the public contract's slash spelling stable on Windows;
            // Path::join treats the slash-containing suffix as one literal
            // component and produces a mixed-separator string.
            PathBuf::from(format!("{}/{}", home.display(), suffix))
        } else if suffix.is_empty() {
            home.to_path_buf()
        } else {
            home.join(suffix)
        };
        assert_eq!(step["path"], expected.to_str().unwrap());
    }
    result
}

#[test]
fn rejects_unconfirmed_changed_or_invalid_requests_before_creating_state() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    for (params, code) in [
        (
            json!({"confirmed":false,"expected_home":home}),
            "confirmation_required",
        ),
        (
            json!({"confirmed":true,"expected_home":temp.path()}),
            "configuration_changed",
        ),
        (
            json!({"confirmed":true,"expected_home":"relative"}),
            "invalid_params",
        ),
        (
            json!({"confirmed":true,"expected_home":home,"extra":true}),
            "invalid_params",
        ),
        (json!({"confirmed":true}), "invalid_params"),
    ] {
        let (ok, response) = invoke(&home, params);
        assert!(!ok);
        assert_eq!(response["error"]["code"], code);
        assert_eq!(response["error"]["retryable"], false);
        assert!(!home.exists());
    }
}

#[test]
fn prepares_absent_home_without_configuration_or_secrets_and_preserves_existing_data() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let first = setup(&home);
    assert_eq!(first["complete"], true);
    for step in first["steps"].as_array().unwrap() {
        assert_eq!(step["status"], "applied");
        assert_eq!(step["code"], "none");
    }
    let paths = AppPaths::new(Some(home.clone())).unwrap();
    assert!(!paths.config_path().exists());
    assert_eq!(fs::read_dir(paths.secrets_dir()).unwrap().count(), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for step in first["steps"].as_array().unwrap() {
            let metadata = fs::metadata(step["path"].as_str().unwrap()).unwrap();
            let expected = if metadata.is_dir() { 0o700 } else { 0o600 };
            assert_eq!(metadata.permissions().mode() & 0o777, expected);
        }
    }
    let state = LocalState::open(&paths).unwrap();
    state.set_kv("retained", "custom-value").unwrap();
    drop(state);
    // Deliberately malformed configuration must not block metadata preparation.
    let config = b"server_url = [ invalid config never parsed";
    fs::write(paths.config_path(), config).unwrap();
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(paths.dependency_manifest_path()).unwrap()).unwrap();
    manifest["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "name":"custom", "required_version":"1", "binary":"bin/custom",
            "source":"local", "license":"MIT", "license_notice":"custom notice"
        }));
    let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    fs::write(paths.dependency_manifest_path(), &bytes).unwrap();
    let second = setup(&home);
    assert_eq!(second["complete"], true);
    for step in second["steps"].as_array().unwrap() {
        assert_eq!(step["status"], "ready");
        assert_eq!(step["code"], "none");
    }
    assert_eq!(fs::read(paths.config_path()).unwrap(), config);
    assert_eq!(fs::read(paths.dependency_manifest_path()).unwrap(), bytes);
    assert_eq!(
        LocalState::open(&paths)
            .unwrap()
            .get_kv("retained")
            .unwrap()
            .as_deref(),
        Some("custom-value")
    );
}

#[test]
fn invalid_dependency_directory_skips_manifest_but_prepares_database() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    fs::write(home.join("dependencies"), b"preserve me").unwrap();
    let result = setup(home);
    assert_eq!(result["complete"], false);
    assert_eq!(result["steps"][2]["status"], "failed");
    assert_eq!(result["steps"][2]["code"], "path_invalid");
    assert_eq!(result["steps"][6]["status"], "applied");
    assert_eq!(result["steps"][7]["status"], "skipped");
    assert_eq!(result["steps"][7]["code"], "dependency_failed");
    assert_eq!(fs::read(home.join("dependencies")).unwrap(), b"preserve me");
}

#[test]
fn corrupt_and_future_database_are_preserved_by_setup_doctor_and_init() {
    for future in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let database = home.join("state.sqlite3");
        if future {
            let connection = rusqlite::Connection::open(&database).unwrap();
            connection.pragma_update(None, "user_version", 999).unwrap();
        } else {
            fs::write(&database, b"not a sqlite database").unwrap();
        }
        let original = fs::read(&database).unwrap();
        let result = setup(home);
        assert_eq!(result["complete"], false);
        assert_eq!(result["steps"][6]["status"], "failed");
        assert_eq!(
            result["steps"][6]["code"],
            if future {
                "unsupported_state_version"
            } else {
                "state_unavailable"
            }
        );
        assert_eq!(result["steps"][7]["status"], "applied");
        assert_eq!(fs::read(&database).unwrap(), original);
        for args in [["doctor", "--fix"], ["init", "--yes"]] {
            let output = command(home)
                .args(args)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("local metadata preparation is incomplete"));
            assert_eq!(fs::read(&database).unwrap(), original);
        }
        if future {
            let connection = rusqlite::Connection::open(&database).unwrap();
            let version: i64 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap();
            assert_eq!(version, 999);
        }
    }
}

#[test]
fn malformed_and_future_manifests_are_retained_as_partial_failures() {
    for bytes in [
        b"{bad manifest".as_slice(),
        br#"{"schema_version":999,"dependencies":[]}"#,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        fs::create_dir(home.join("dependencies")).unwrap();
        let manifest = home.join("dependencies/manifest.json");
        fs::write(&manifest, bytes).unwrap();
        let result = setup(home);
        assert_eq!(result["complete"], false);
        assert_eq!(result["steps"][6]["status"], "applied");
        assert_eq!(result["steps"][7]["status"], "failed");
        assert_eq!(result["steps"][7]["code"], "manifest_invalid");
        assert_eq!(fs::read(manifest).unwrap(), bytes);
    }
}

#[test]
fn dependency_repair_does_not_initialize_database_or_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let output = command(&home)
        .args(["deps", "status", "--fix"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(home.join("dependencies/manifest.json").is_file());
    assert!(!home.join("state.sqlite3").exists());
    assert!(!home.join("config.toml").exists());
}

#[cfg(unix)]
#[test]
fn preparation_never_executes_managed_tools_or_credential_helpers() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(home.join("bin")).unwrap();
    fs::create_dir(home.join("dependencies")).unwrap();
    let marker = temp.path().join("executed");
    let program = b"#!/bin/sh\n: > \"$SETUP_EXECUTION_MARKER\"\nexit 1\n";
    for name in ["tool", "security", "secret-tool"] {
        let path = home.join("bin").join(name);
        fs::write(&path, program).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(
        home.join("dependencies/manifest.json"),
        json!({
            "schema_version":1,"dependencies":[{
                "name":"tool","required_version":"1","binary":"bin/tool",
                "source":"local","license":"MIT","license_notice":"test"
            }]
        })
        .to_string(),
    )
    .unwrap();
    let mut child = command(&home)
        .arg("--desktop-control")
        .env("PATH", home.join("bin"))
        .env("SETUP_EXECUTION_MARKER", &marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"protocol_version":1,"request_id":"setup-no-exec","method":"setup.local",
        "params":{"confirmed":true,"expected_home":home}});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["complete"], true);
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn controlled_directory_symlinks_are_rejected_without_writing_to_targets() {
    use std::os::unix::fs::symlink;
    for link_home in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let home = temp.path().join("home");
        if link_home {
            symlink(&target, &home).unwrap();
        } else {
            fs::create_dir(&home).unwrap();
            symlink(&target, home.join("dependencies")).unwrap();
        }
        let result = setup(&home);
        assert_eq!(result["complete"], false);
        let failed = if link_home { 0 } else { 2 };
        assert_eq!(result["steps"][failed]["status"], "failed");
        assert_eq!(result["steps"][failed]["code"], "path_invalid");
        assert_eq!(result["steps"][7]["status"], "skipped");
        if link_home {
            assert!(result["steps"].as_array().unwrap()[1..]
                .iter()
                .all(|step| step["status"] == "skipped"));
        }
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }
}

#[cfg(unix)]
#[test]
fn setup_rejects_home_link_aliases_and_accepts_real_trailing_separators() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let link = temp.path().join("linked-home");
    symlink(&target, &link).unwrap();
    for suffix in ["/", "/.", "/./"] {
        let mut spelling = link.as_os_str().to_os_string();
        spelling.push(suffix);
        let home = std::path::PathBuf::from(spelling);
        let (ok, response) = invoke(&home, json!({"confirmed":true,"expected_home":home}));
        assert!(ok);
        assert_eq!(response["result"]["complete"], false);
        assert_eq!(response["result"]["steps"][0]["code"], "path_invalid");
        assert!(response["result"]["steps"].as_array().unwrap()[1..]
            .iter()
            .all(|step| step["status"] == "skipped"));
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }
    for suffix in ["/", "/."] {
        let mut spelling = target.as_os_str().to_os_string();
        spelling.push(suffix);
        let home = std::path::PathBuf::from(spelling);
        let (ok, response) = invoke(&home, json!({"confirmed":true,"expected_home":home}));
        assert!(ok);
        assert_eq!(response["result"]["home"], target.to_str().unwrap());
        assert_eq!(response["result"]["complete"], true);
    }
}

#[test]
fn home_normalization_preserves_roots_and_rejects_parent_traversal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().ancestors().last().unwrap().to_path_buf();
    let paths = AppPaths::new(Some(root.clone())).unwrap();
    assert_eq!(
        agent_remote_cli::setup::absolute_home(&paths).unwrap(),
        root
    );
    let paths = AppPaths::new(Some(temp.path().join(".."))).unwrap();
    assert!(agent_remote_cli::setup::absolute_home(&paths).is_err());
}
