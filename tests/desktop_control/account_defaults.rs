use super::*;
use agent_remote_cli::{
    config::{AppPaths, Config},
    local_state::LocalState,
};

fn get(home: &Path) -> Value {
    let (ok, response) = invoke(
        home,
        &request(
            "accounts.default.get",
            json!({"expected_home": home, "tool":"claude"}),
        ),
    );
    assert!(ok, "{response}");
    response["result"].clone()
}
fn mutation(snapshot: &Value) -> Value {
    json!({"confirmed": true, "expected_context":snapshot["context"], "expected_account_id":snapshot["account_id"], "tool":"claude"})
}
fn paths(home: &Path) -> AppPaths {
    AppPaths::new(Some(home.to_path_buf())).unwrap()
}
fn seed_default(home: &Path, value: &str) {
    let state = LocalState::open(&paths(home)).unwrap();
    state.init_schema().unwrap();
    state.set_kv("default_tool_account:claude", value).unwrap();
}
fn account(id: &str, tool: &str) -> Value {
    json!({"data":{"id":id,"user_id":"secret-user", "tool_type":tool,"display_name":"private-account-name","status":"ready","region_code":"cn","timezone":"UTC","locale":"en","preferred_node_tags":[],"affinity_node_id":null,"runtime_backend":null,"created_at":"now","updated_at":"now","secret":"must-not-project"}})
}

#[test]
fn read_missing_home_and_existing_database_without_initialization() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("missing");
    assert!(get(&home)["account_id"].is_null());
    assert!(!home.exists());
    seed_default(&home, "existing-full-account");
    let before = std::fs::read(paths(&home).state_db_path()).unwrap();
    assert_eq!(get(&home)["account_id"], "existing-full-account");
    assert_eq!(before, std::fs::read(paths(&home).state_db_path()).unwrap());
    assert!(!home.join("config-write.lock").exists());
    let entries: Vec<_> = std::fs::read_dir(paths(&home).secrets_dir())
        .unwrap()
        .collect();
    assert!(entries.is_empty());
}

#[test]
fn clear_is_confirmed_context_bound_compare_and_set_and_shared_with_human_cli() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    seed_default(&home, "account-original");
    let snapshot = get(&home);
    let mut input = mutation(&snapshot);
    input["confirmed"] = json!(false);
    let (_, denied) = invoke(&home, &request("accounts.default.clear", input));
    assert_eq!(denied["error"]["code"], "confirmation_required");
    assert_eq!(get(&home)["account_id"], "account-original");
    seed_default(&home, "account-replaced");
    let (_, stale) = invoke(
        &home,
        &request("accounts.default.clear", mutation(&snapshot)),
    );
    assert_eq!(stale["error"]["code"], "default_changed");
    let snapshot = get(&home);
    let mut changed = mutation(&snapshot);
    changed["expected_context"]["active_device_id"] = json!("another-device");
    let (_, stale) = invoke(&home, &request("accounts.default.clear", changed));
    assert_eq!(stale["error"]["code"], "configuration_changed");
    let (ok, result) = invoke(
        &home,
        &request("accounts.default.clear", mutation(&snapshot)),
    );
    assert!(ok, "{result}");
    assert_eq!(result["result"]["previous_account_id"], "account-replaced");
    assert!(result["result"]["account_id"].is_null());
    assert_eq!(result["result"]["changed"], true);
    assert_eq!(result["result"]["operation_id"], "query-123");
    let snapshot = get(&home);
    let (ok, result) = invoke(
        &home,
        &request("accounts.default.clear", mutation(&snapshot)),
    );
    assert!(ok);
    assert_eq!(result["result"]["changed"], false);
    seed_default(&home, "human-visible-account");
    let output = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .args(["account", "default", "get"])
        .env("AGENT_REMOTE_HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("human-visible-account"));
    let output = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .args(["account", "default", "clear"])
        .env("AGENT_REMOTE_HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(get(&home)["account_id"].is_null());
}

#[test]
fn strict_request_validation_rejects_missing_nullable_and_unknown_fields_before_io() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let snapshot = get(&home);
    for method in ["accounts.default.set", "accounts.default.clear"] {
        for field in ["expected_account_id", "server_url", "active_device_id"] {
            let mut input = mutation(&snapshot);
            if method.ends_with("set") {
                input["account_id"] = json!("exact-full-account");
            }
            if field == "expected_account_id" {
                input.as_object_mut().unwrap().remove(field);
            } else {
                input["expected_context"]
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
            }
            let (_, result) = invoke(&home, &request(method, input));
            assert_eq!(
                result["error"]["code"], "invalid_params",
                "{field} {result}"
            );
            assert!(!home.exists());
        }
    }
    for input in [
        json!({"expected_home":home,"tool":"../bad"}),
        json!({"expected_home":home,"tool":"claude","extra":"secret"}),
        json!({"expected_home":"relative","tool":"claude"}),
    ] {
        let (_, response) = invoke(&home, &request("accounts.default.get", input));
        assert_eq!(response["error"]["code"], "invalid_params");
        assert!(!home.exists());
    }
}

#[test]
fn set_validates_exact_account_and_tool_and_only_projects_default_metadata() {
    for (id, tool, expected) in [
        ("exact-full-account", "claude", None),
        ("different-account", "claude", Some("account_mismatch")),
        ("exact-full-account", "codex", Some("account_mismatch")),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let server = fixture(&home, 200, account(id, tool));
        let mut input = mutation(&get(&home));
        input["account_id"] = json!("exact-full-account");
        let (ok, response) = invoke(&home, &request("accounts.default.set", input));
        let wire = server.join().unwrap();
        assert!(wire.starts_with("GET /api/v1/tool-accounts/exact-full-account "));
        assert!(wire
            .to_ascii_lowercase()
            .contains("authorization: bearer test-private-token"));
        if let Some(code) = expected {
            assert!(!ok);
            assert_eq!(response["error"]["code"], code);
            assert!(get(&home)["account_id"].is_null());
        } else {
            assert!(ok, "{response}");
            assert_eq!(response["result"]["account_id"], "exact-full-account");
            assert_eq!(response["result"]["changed"], true);
            assert_eq!(get(&home)["account_id"], "exact-full-account");
        }
        for secret in [
            "private-account-name",
            "test-private-token",
            "must-not-project",
            "secret-user",
        ] {
            assert!(!response.to_string().contains(secret));
        }
    }
}

#[test]
fn rejected_remote_read_is_redacted_and_preserves_default() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let server = fixture(
        &home,
        403,
        json!({"error":{"code":"denied","message":"sensitive-token-private-detail"}}),
    );
    seed_default(&home, "original-account");
    let mut input = mutation(&get(&home));
    input["account_id"] = json!("exact-full-account");
    let (_, response) = invoke(&home, &request("accounts.default.set", input));
    server.join().unwrap();
    assert_eq!(response["error"]["code"], "permission_denied");
    assert!(!response.to_string().contains("sensitive"));
    assert_eq!(get(&home)["account_id"], "original-account");
}

#[test]
fn config_change_while_waiting_for_login_lock_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    seed_default(&home, "original-account");
    let snapshot = get(&home);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let guard = runtime
        .block_on(agent_remote_cli::auth::login::lock(&paths(&home)))
        .unwrap();
    let cloned_home = home.clone();
    let worker = std::thread::spawn(move || {
        invoke(
            &cloned_home,
            &request("accounts.default.clear", mutation(&snapshot)),
        )
    });
    // Both schedules are valid: mismatch must be rejected before or after waiting.
    Config {
        server_url: Some("http://127.0.0.1:9".into()),
        active_device_id: Some("new-device".into()),
    }
    .save(&paths(&home))
    .unwrap();
    drop(guard);
    let (ok, response) = worker.join().unwrap();
    assert!(!ok);
    assert_eq!(response["error"]["code"], "configuration_changed");
    assert_eq!(get(&home)["account_id"], "original-account");
}

fn scripted_server<F>(
    home: &Path,
    replies: Vec<(&'static str, Value)>,
    before_last: F,
) -> std::thread::JoinHandle<()>
where
    F: FnOnce() -> bool + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let seeded = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "seed_device_credential"])
        .env("DESKTOP_CONTROL_TEST_SERVER", server)
        .env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert!(seeded.status.success());
    std::thread::spawn(move || {
        let mut before_last = Some(before_last);
        let count = replies.len();
        for (index, (path, body)) in replies.into_iter().enumerate() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(error) => panic!("missing HTTP request: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                let mut block = [0; 1024];
                let n = stream.read(&mut block).unwrap();
                assert!(n > 0 && bytes.len() < 8192);
                bytes.extend_from_slice(&block[..n]);
            }
            assert!(String::from_utf8_lossy(&bytes).starts_with(&format!("GET {path} ")));
            if index + 1 == count && !before_last.take().unwrap()() {
                return;
            }
            let body = body.to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    })
}

#[test]
fn human_prefix_set_is_visible_to_desktop_and_desktop_clear_to_human() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let id = "12345678-1234-1234-1234-123456789abc";
    let server = scripted_server(
        &home,
        vec![
            (
                "/api/v1/tool-accounts",
                json!({"data":{"items":[account(id, "claude")["data"]]}}),
            ),
            (
                "/api/v1/tool-accounts/12345678-1234-1234-1234-123456789abc",
                account(id, "claude"),
            ),
        ],
        || true,
    );
    let output = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .args(["account", "default", "set", "--account-id", "12345678"])
        .env("AGENT_REMOTE_HOME", &home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains(&format!("Default claude account set to {id}")));
    let snapshot = get(&home);
    assert_eq!(snapshot["account_id"], id);
    let (ok, _) = invoke(
        &home,
        &request("accounts.default.clear", mutation(&snapshot)),
    );
    assert!(ok);
    let output = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .args(["account", "default", "get"])
        .env("AGENT_REMOTE_HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Default claude account is not set."));
}

#[test]
fn context_or_prior_default_changed_during_remote_validation_prevents_publication() {
    for config_change in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let changed_home = home.clone();
        let server = scripted_server(
            &home,
            vec![(
                "/api/v1/tool-accounts/exact-full-account",
                account("exact-full-account", "claude"),
            )],
            move || {
                if config_change {
                    Config {
                        server_url: Some("http://127.0.0.1:9".into()),
                        active_device_id: Some("replacement-device".into()),
                    }
                    .save(&paths(&changed_home))
                    .unwrap();
                } else {
                    seed_default(&changed_home, "replacement-account");
                }
                true
            },
        );
        seed_default(&home, "original-account");
        let mut input = mutation(&get(&home));
        input["account_id"] = json!("exact-full-account");
        let (ok, response) = invoke(&home, &request("accounts.default.set", input));
        server.join().unwrap();
        assert!(!ok);
        assert_eq!(
            response["error"]["code"],
            if config_change {
                "configuration_changed"
            } else {
                "default_changed"
            }
        );
        assert_eq!(
            get(&home)["account_id"],
            if config_change {
                "original-account"
            } else {
                "replacement-account"
            }
        );
    }
}

#[test]
fn setting_existing_default_still_validates_account_and_reports_no_change() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let server = fixture(&home, 200, account("exact-full-account", "claude"));
    seed_default(&home, "exact-full-account");
    let mut input = mutation(&get(&home));
    input["account_id"] = json!("exact-full-account");
    let (ok, response) = invoke(&home, &request("accounts.default.set", input));
    server.join().unwrap();
    assert!(ok, "{response}");
    assert_eq!(response["result"]["changed"], false);
    assert_eq!(
        response["result"]["previous_account_id"],
        "exact-full-account"
    );
    assert_eq!(response["result"]["account_id"], "exact-full-account");
}

#[test]
fn concurrent_confirmed_clears_have_one_winner() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    seed_default(&home, "original-account");
    let snapshot = get(&home);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let home = home.clone();
            let snapshot = snapshot.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                invoke(
                    &home,
                    &request("accounts.default.clear", mutation(&snapshot)),
                )
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|(ok, _)| *ok).count(), 1);
    assert!(results
        .iter()
        .filter(|(ok, _)| !*ok)
        .all(|(_, response)| response["error"]["code"] == "default_changed"));
    assert!(get(&home)["account_id"].is_null());
}

#[test]
fn invalid_or_oversized_persisted_default_is_not_projected() {
    for value in ["private\ncredential".to_owned(), "x".repeat(1024 * 1024)] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        seed_default(&home, &value);
        let (ok, response) = invoke(
            &home,
            &request(
                "accounts.default.get",
                json!({"expected_home":home,"tool":"claude"}),
            ),
        );
        assert!(!ok);
        assert_eq!(response["error"]["code"], "state_unavailable");
        assert!(!response.to_string().contains("private"));
        assert!(response.to_string().len() < 512);
    }
}

#[cfg(unix)]
#[test]
fn cancel_during_account_validation_returns_unknown_without_publishing_or_retrying() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let server = scripted_server(
        &home,
        vec![(
            "/api/v1/tool-accounts/exact-full-account",
            account("exact-full-account", "claude"),
        )],
        move || {
            accepted_tx.send(()).unwrap();
            release_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            false
        },
    );
    seed_default(&home, "original-account");
    let mut input = mutation(&get(&home));
    input["account_id"] = json!("exact-full-account");
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", &home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request("accounts.default.set", input))
        .unwrap();
    accepted_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let output = child.wait_with_output().unwrap();
    release_tx.send(()).unwrap();
    server.join().unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["error"]["code"], "default_outcome_unknown");
    assert_eq!(get(&home)["account_id"], "original-account");
    // Cancellation released the login guard; a fresh explicitly confirmed local
    // operation can proceed without replaying the canceled account selection.
    let (ok, _) = invoke(
        &home,
        &request("accounts.default.clear", mutation(&get(&home))),
    );
    assert!(ok);
}
