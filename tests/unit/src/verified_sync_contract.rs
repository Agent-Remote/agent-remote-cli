//! Full library workflow against isolated HTTP and contained Mutagen subprocesses.
#![cfg(unix)]
use crate::{
    account_defaults::Context,
    api::SyncSessionData,
    auth,
    config::{AppPaths, Config},
    local_state::{LocalState, LocalSyncSession, LocalWorkspace},
    mutagen::desktop::environment,
    secrets::{device_token_key, SecretStore, SecretValue},
    session_sync::flush_verified,
    sync_operations::{fingerprint, Target},
    workspace,
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WS: &str = "12345678-1234-1234-1234-123456789abc";
const SYNC: &str = "87654321-1234-1234-1234-123456789abc";
const DEVICE: &str = "22222222-1234-1234-1234-123456789abc";

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn integer(mut n: u64, out: &mut Vec<u8>) {
    while n >= 128 {
        out.push(n as u8 | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn bytes(tag: u64, value: &[u8], out: &mut Vec<u8>) {
    integer(tag << 3 | 2, out);
    integer(value.len() as u64, out);
    out.extend(value);
}
fn number(tag: u64, value: u64, out: &mut Vec<u8>) {
    integer(tag << 3, out);
    integer(value, out);
}
fn disk_session(data: &Path, sync: &SyncSessionData, identifier: &str) {
    let mut session = vec![];
    bytes(1, identifier.as_bytes(), &mut session);
    number(2, 1, &mut session);
    bytes(3, &[8, 1], &mut session);
    number(5, 18, &mut session);
    number(6, 1, &mut session);
    let mut local = vec![];
    bytes(5, sync.local_path.as_bytes(), &mut local);
    let mut remote = vec![];
    number(1, 1, &mut remote);
    bytes(2, b"agent-remote", &mut remote);
    bytes(3, b"127.0.0.1", &mut remote);
    number(4, 22, &mut remote);
    bytes(5, sync.remote_path.as_bytes(), &mut remote);
    bytes(7, &local, &mut session);
    bytes(8, &remote, &mut session);
    bytes(9, &[], &mut session);
    bytes(14, b"agent-remote-sync-test", &mut session);
    fs::create_dir_all(data.join("sessions")).unwrap();
    fs::write(data.join("sessions").join(identifier), session).unwrap();
}

#[test]
fn verified_flush_keeps_original_target_and_never_creates_sessions_or_repairs() {
    if let Ok(root) = std::env::var("VERIFIED_FLUSH_ROOT") {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(exercise(
            Path::new(&root),
            &std::env::var("VERIFIED_FLUSH_CASE").unwrap(),
        ));
        return;
    }
    for case in [
        "success",
        "paused",
        "unknown",
        "conflict",
        "git-lock",
        "worktree",
        "replace",
        "post-conflict",
        "post-git-lock",
        "config-change",
        "directory-change",
        "server-change",
        "server-health",
        "server-conflict",
        "flush-fail",
        "cancel",
        "timeout",
        "stopped",
    ] {
        let root = tempfile::Builder::new()
            .prefix("arvf-")
            .tempdir_in("/tmp")
            .unwrap();
        fs::create_dir(root.path().join("os-home")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "session_sync::verified::contract_tests::verified_flush_keeps_original_target_and_never_creates_sessions_or_repairs",
                "--nocapture",
            ])
            .env("VERIFIED_FLUSH_ROOT", root.path())
            .env("VERIFIED_FLUSH_CASE", case)
            .env("HOME", root.path().join("os-home"))
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .env("MUTAGEN_DATA_DIRECTORY", root.path().join("mutagen"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

async fn exercise(root: &Path, case: &str) {
    let paths = AppPaths::new(Some(root.join("home"))).unwrap();
    paths.ensure_base_dirs().unwrap();
    let data = root.join("mutagen");
    fs::create_dir_all(data.join("daemon")).unwrap();
    let project = root.join("project");
    fs::create_dir(&project).unwrap();
    let project = project.canonicalize().unwrap();
    let identifier = format!("sync_{}", "a".repeat(43));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let config = Config {
        server_url: Some(url.clone()),
        active_device_id: Some(DEVICE.into()),
    };
    config.save(&paths).unwrap();
    drop(auth::login::lock(&paths).await.unwrap());
    let context = Context {
        home: paths.home().into(),
        server_url: Some(url.clone()),
        active_device_id: Some(DEVICE.into()),
    };
    let sync_wire = json!({"id":SYNC,"user_id":"user","workspace_id":WS,"node_id":null,"local_path":project,"remote_path":"/workspaces/test","status":"active","conflict_status":"none","sync_mode":"two_way","sync_git":true,"exclude":workspace::DEFAULT_EXCLUDES,"mutagen_session_id":"agent-remote-sync-test","remote_endpoint":"agent-remote@127.0.0.1:22:/workspaces/test","prepare_task_id":null,"created_at":"now","updated_at":"now"});
    let sync: SyncSessionData = serde_json::from_value(sync_wire.clone()).unwrap();
    let identity = workspace::identify_workspace(Some(&project)).unwrap();
    let target = Target {
        local_path: sync.local_path.clone(),
        project_key: identity.project_key.clone(),
        workspace_id: Some(WS.into()),
        sync_session_id: Some(SYNC.into()),
        fingerprint: Some(fingerprint(&sync)),
    };
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state
        .upsert_workspace(&LocalWorkspace {
            id: WS.into(),
            server_url: url.clone(),
            project_key: identity.project_key,
            local_path: sync.local_path.clone(),
            display_name: "project".into(),
            remote_path: Some(sync.remote_path.clone()),
        })
        .unwrap();
    state
        .upsert_sync_session(&LocalSyncSession {
            id: SYNC.into(),
            server_url: url.clone(),
            workspace_id: WS.into(),
            node_id: None,
            status: "active".into(),
            conflict_status: "none".into(),
            mutagen_session_id: sync.mutagen_session_id.clone(),
            remote_endpoint: sync.remote_endpoint.clone(),
        })
        .unwrap();
    state
        .set_kv(
            &format!("device-token-refresh-at:{url}:{DEVICE}"),
            "9999999999",
        )
        .unwrap();
    drop(state);
    SecretStore::new(paths.clone())
        .write_strict(
            &device_token_key(&url, DEVICE),
            &SecretValue::new("fixture-token".into()).unwrap(),
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
    let initial_db = fs::read(paths.state_db_path()).unwrap();
    let script = include_bytes!("../../fixtures/verified_sync_mutagen.py");
    for name in ["mutagen", "ssh", "scp"] {
        let binary = paths.bin_dir().join(name);
        fs::write(&binary, script).unwrap();
        fs::set_permissions(binary, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut model = json!({"identifier":identifier,"name":"agent-remote-sync-test","paused":false,"status":"watching","successfulCycles":1,"mode":"two-way-safe","ignore":{"paths":workspace::DEFAULT_EXCLUDES},"permissions":{"defaultFileMode":"0660","defaultDirectoryMode":"0770"},"alpha":{"protocol":"local","path":project,"connected":true,"scanned":true},"beta":{"protocol":"ssh","user":"agent-remote","host":"127.0.0.1","port":22,"path":"/workspaces/test","connected":true,"scanned":true}});
    match case {
        "paused" => model["paused"] = json!(true),
        "unknown" => model["successfulCycles"] = json!(0),
        "conflict" => model["conflicts"] = json!([{}]),
        "git-lock" => {
            fs::create_dir(project.join(".git")).unwrap();
            fs::write(project.join(".git/index.lock"), "").unwrap();
        }
        "worktree" => fs::write(project.join(".git"), "gitdir: /unreviewed").unwrap(),
        _ => {}
    }
    fs::write(data.join("model.json"), model.to_string()).unwrap();
    fs::write(data.join("case"), case).unwrap();
    fs::write(
        data.join("config-path"),
        paths.config_path().as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    disk_session(&data, &sync, &identifier);
    fs::write(data.join("agent-remote-environment.lock"), "").unwrap();
    let daemon = Daemon(
        Command::new("python3")
            .arg(paths.bin_dir().join("mutagen"))
            .arg("--fixture-daemon")
            .arg(&data)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !data.join("ready").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let plan = environment::preview(&paths).await.unwrap();
    assert_eq!(plan.daemon_state, "running", "{plan:?}");
    fs::write(data.join("agent-remote-environment.json"), json!({"version":2,"binding":plan.desired,"namespace_fingerprint":plan.namespace_fingerprint,"running_fingerprint":plan.running_fingerprint}).to_string()).unwrap();
    let marker = fs::read(data.join("agent-remote-environment.json")).unwrap();
    let _daemon = if case == "stopped" {
        drop(daemon);
        None
    } else {
        Some(daemon)
    };
    let requests = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
    let seen = requests.clone();
    let mode = case.to_owned();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 8192];
            let n = socket.read(&mut bytes).await.unwrap();
            let request = String::from_utf8_lossy(&bytes[..n]).to_string();
            assert!(request.starts_with(&format!("GET /api/v1/sync-sessions/{SYNC} ")));
            let mut seen = seen.lock().await;
            seen.push(request);
            let mut response = sync_wire.clone();
            response["target_precondition_version"] = json!(1);
            if mode == "server-change" && seen.len() > 1 {
                response["remote_path"] = json!("/changed");
            }
            if mode == "server-health" && seen.len() > 1 {
                response["status"] = json!("paused");
            }
            if mode == "server-conflict" && seen.len() > 1 {
                response["conflict_status"] = json!("unknown");
            }
            let body = json!({"data":response}).to_string();
            drop(seen);
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
        }
    });
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    let cancel_data = data.clone();
    let cancellation = if case == "cancel" {
        Some(tokio::spawn(async move {
            while !cancel_data.join("child-pid").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            flag.store(true, Ordering::Release);
        }))
    } else {
        None
    };
    let result = if case == "timeout" {
        super::flush_with_limit(&paths, &context, &target, &cancel, Duration::from_secs(10)).await
    } else {
        flush_verified(&paths, &context, &target, &cancel).await
    };
    if case == "success" {
        let value = result.unwrap();
        assert_eq!(value.mutagen_identifier, identifier);
        assert_eq!(value.target, target);
        assert_eq!(value.context, context);
    } else {
        let error = result.unwrap_err();
        assert_eq!(
            error.flush_may_have_run,
            data.join("flushed").exists(),
            "{error:?}"
        );
        if case == "cancel" {
            assert_eq!(error.code, "sync_flush_canceled");
        }
        if case == "timeout" {
            assert_eq!(error.code, "sync_flush_timeout");
            assert!(error.flush_may_have_run);
        }
    }
    if let Some(task) = cancellation {
        task.await.unwrap();
    }
    if matches!(case, "cancel" | "timeout") {
        let pid: i32 = fs::read_to_string(data.join("child-pid"))
            .unwrap()
            .parse()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while unsafe { libc::kill(pid, 0) } == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    assert_eq!(initial_db, fs::read(paths.state_db_path()).unwrap());
    assert_eq!(
        marker,
        fs::read(data.join("agent-remote-environment.json")).unwrap()
    );
    for line in fs::read_to_string(data.join("calls")).unwrap().lines() {
        let args: Vec<String> = serde_json::from_str(line).unwrap();
        assert!(matches!(args[1].as_str(), "list" | "flush"));
        if args[1] == "flush" {
            assert_eq!(args, ["sync", "flush", "--", &identifier]);
        }
    }
    assert!(!requests.lock().await.is_empty());
    server.abort();
}
