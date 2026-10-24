//! Protected platform WireGuard broker service entry point.
//!
//! Each supported target uses its native service boundary. Unsupported
//! targets exit without attempting a shell, elevation helper, or PATH lookup.

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = agent_remote_cli::wireguard::linux_broker::service::run() {
        eprintln!("agent-remote-wireguard-broker: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = agent_remote_cli::wireguard::macos_broker_service::run() {
        eprintln!("agent-remote-wireguard-broker: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
fn main() {
    eprintln!("agent-remote-wireguard-broker is unsupported on this platform");
    std::process::exit(78);
}

#[cfg(windows)]
mod windows_service {
    use std::env;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use anyhow::{bail, Context, Result};
    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SERVICE_WIN32_OWN_PROCESS,
    };

    use agent_remote_cli::config::AppPaths;
    use agent_remote_cli::wireguard::replay::ReplayJournal;
    use agent_remote_cli::wireguard::target::{TargetObservation, TargetReason, TargetState};
    use agent_remote_cli::wireguard::windows_broker::{
        now_unix_ms, BrokerWorkerHandshake, PipeWorker, WorkerAction, WorkerLifetime,
        WorkerResponse, MAX_WORKER_LIFETIME, PROTOCOL_VERSION,
    };

    const SERVICE_NAME: &str = "AgentRemoteWireGuardBroker";
    const WIREGUARD_PATH: &str = r"C:\Program Files\WireGuard\wireguard.exe";
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
    static mut STATUS_HANDLE: SERVICE_STATUS_HANDLE = std::ptr::null_mut();

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set_status(state: u32, controls: u32, win32_exit: u32) {
        let mut status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: controls,
            dwWin32ExitCode: win32_exit,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 5_000,
        };
        unsafe {
            if !STATUS_HANDLE.is_null() {
                let _ = SetServiceStatus(STATUS_HANDLE, &mut status);
            }
        }
    }

    unsafe extern "system" fn control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        if control == SERVICE_CONTROL_STOP {
            STOP_REQUESTED.store(true, Ordering::Release);
            set_status(SERVICE_STOP_PENDING, 0, ERROR_SUCCESS);
        }
        ERROR_SUCCESS
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name = wide(SERVICE_NAME);
        STATUS_HANDLE = RegisterServiceCtrlHandlerExW(
            name.as_ptr(),
            Some(control_handler),
            std::ptr::null_mut(),
        );
        if STATUS_HANDLE.is_null() {
            return;
        }
        set_status(SERVICE_START_PENDING, 0, ERROR_SUCCESS);
        set_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, ERROR_SUCCESS);
        if let Err(error) = run_loop() {
            eprintln!("Windows WireGuard broker stopped: {error:#}");
        }
        set_status(SERVICE_STOPPED, 0, ERROR_SUCCESS);
    }

    pub fn main() {
        if env::args().any(|arg| arg == "--console") {
            if let Err(error) = run_loop() {
                eprintln!("Windows WireGuard broker failed: {error:#}");
                std::process::exit(1);
            }
            return;
        }
        let name = wide(SERVICE_NAME);
        let mut table = [
            windows_sys::Win32::System::Services::SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_ptr() as *mut u16,
                lpServiceProc: Some(service_main),
            },
            windows_sys::Win32::System::Services::SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];
        let started = unsafe { StartServiceCtrlDispatcherW(table.as_mut_ptr()) };
        if started == 0 {
            eprintln!("agent-remote-wireguard-broker must be started by SCM");
            std::process::exit(1);
        }
    }

    fn run_loop() -> Result<()> {
        // Load the durable one-shot journal before accepting any pipe. A
        // malformed or inaccessible journal keeps the service offline.
        let mut replay =
            ReplayJournal::open(journal_path()?).map_err(|error| anyhow::anyhow!(error.0))?;
        while !STOP_REQUESTED.load(Ordering::Acquire) {
            let worker = PipeWorker::bind("service")?;
            let mut lifetime = WorkerLifetime::new(Instant::now(), MAX_WORKER_LIFETIME)?;
            let now = now_unix_ms()?;
            let _ = worker.serve_broker_once(&mut lifetime, now, |handshake| {
                handle_request(handshake, &mut replay)
            });
        }
        Ok(())
    }

    fn handle_request(
        handshake: BrokerWorkerHandshake,
        replay: &mut ReplayJournal,
    ) -> Result<WorkerResponse> {
        let request_id = handshake.request.request_id.clone();
        let now = now_unix_ms()?;
        // Recompute the native SCM scope in the privileged service. The
        // desktop-provided digest is only a binding to its reviewed plan; it
        // is never treated as an observation. This fence also makes service
        // restart/reuse fail closed when the target changed while the worker
        // was being created.
        let scope =
            agent_remote_cli::wireguard::target::scope_digest_for_broker(&handshake.logical_name)
                .map_err(|error| anyhow::anyhow!(error.0))?;
        if scope != handshake.target_scope_sha256 {
            bail!("wireguard_windows_broker_scope_mismatch");
        }
        let before = observe_target(&handshake.logical_name);
        let expected_before = match handshake.request.action {
            WorkerAction::Up => TargetState::Absent,
            WorkerAction::Down => TargetState::Present,
        };
        if before.state != expected_before {
            bail!("wireguard_windows_broker_target_precondition");
        }
        if handshake.request.action == WorkerAction::Down {
            match before_identity(&before) {
                Some(agent_remote_cli::wireguard::target::TargetIdentity::WindowsService {
                    config_identity: Some(identity),
                    ..
                }) if identity == &handshake.config_file_identity => {}
                _ => bail!("wireguard_windows_broker_config_mismatch"),
            }
        }
        // Reserve before launching WireGuard. This survives SCM service
        // restarts and prevents a lost response from being retried.
        replay
            .reserve(&request_id)
            .map_err(|error| anyhow::anyhow!(error.0))?;

        let mut permit = handshake.issue_permit(true, now)?;
        let _claims = permit.consume(&handshake.request, &handshake.identity, now)?;
        // A down request uninstalls the already-observed service by its exact
        // logical name and must not overwrite a protected config copy first.
        // Up stages the reviewed bytes in the LocalSystem-owned state root.
        let config_path = if handshake.request.action == WorkerAction::Up {
            Some(write_config(&handshake)?)
        } else {
            None
        };
        let wireguard = PathBuf::from(WIREGUARD_PATH);
        let tool_metadata =
            fs::symlink_metadata(&wireguard).context("wireguard_windows_broker_tool_missing")?;
        if !tool_metadata.is_file() || tool_metadata.file_type().is_symlink() {
            bail!("wireguard_windows_broker_tool_missing");
        }
        let mut command = Command::new(&wireguard);
        match handshake.request.action {
            WorkerAction::Up => {
                command
                    .arg("/installtunnelservice")
                    .arg(config_path.as_ref().expect("up config path"));
            }
            WorkerAction::Down => {
                command
                    .arg("/uninstalltunnelservice")
                    .arg(&handshake.logical_name);
            }
        }
        // Fixed executable and fixed argv only; no shell and no inherited user
        // command path.  WireGuard's service manager owns the resulting SCM
        // target, while this process only observes the operation outcome.
        command
            .env_clear()
            .env("PATH", r"C:\Windows\System32;C:\Windows")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .context("failed to execute WireGuard service manager")?;
        let deadline = std::time::Instant::now() + MAX_WORKER_LIFETIME;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("wireguard_windows_broker_tool_timeout");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        if !status.success() {
            bail!("wireguard_windows_broker_tool_failed");
        }
        let target_state = observe_target(&handshake.logical_name).state;
        let expected_state = match handshake.request.action {
            WorkerAction::Up => TargetState::Present,
            WorkerAction::Down => TargetState::Absent,
        };
        if target_state != expected_state {
            bail!("wireguard_windows_broker_target_observation_failed");
        }
        let operation_id = operation_id(&handshake, now);
        Ok(WorkerResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            accepted: true,
            error: None,
            operation_id: Some(operation_id),
            target_state: Some(target_state),
        })
    }

    fn before_identity(
        observation: &agent_remote_cli::wireguard::target::TargetObservation,
    ) -> Option<&agent_remote_cli::wireguard::target::TargetIdentity> {
        observation.identity.as_ref()
    }

    fn observe_target(name: &str) -> TargetObservation {
        let Ok(paths) = AppPaths::new(None) else {
            return unknown_target(name);
        };
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return unknown_target(name);
        };
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime
            .block_on(agent_remote_cli::wireguard::target::observe(
                &paths, name, cancel,
            ))
            .unwrap_or_else(|_| unknown_target(name))
    }

    fn unknown_target(name: &str) -> TargetObservation {
        TargetObservation {
            logical_name: name.to_owned(),
            state: TargetState::Unknown,
            reason: Some(TargetReason::NativeQueryFailed),
            status_state: "unavailable".into(),
            identity: None,
        }
    }

    fn operation_id(handshake: &BrokerWorkerHandshake, now: u64) -> String {
        let mut digest = Sha256::new();
        digest.update(b"agent-remote:wireguard:windows-broker-operation:v1\0");
        digest.update(handshake.request.request_id.as_bytes());
        digest.update(handshake.plan_sha256.as_bytes());
        digest.update(handshake.target_scope_sha256.as_bytes());
        digest.update(now.to_be_bytes());
        format!("{:x}", digest.finalize())
    }

    fn state_root() -> Result<PathBuf> {
        let root = env::var_os("ProgramData")
            .map(PathBuf::from)
            .context("ProgramData is unavailable")?
            .join("Agent-Remote")
            .join("WireGuard");
        fs::create_dir_all(root.join("configs"))?;
        fs::create_dir_all(root.join("journal"))?;
        Ok(root)
    }

    fn journal_path() -> Result<PathBuf> {
        Ok(state_root()?.join("journal").join("operations.log"))
    }

    fn write_config(handshake: &BrokerWorkerHandshake) -> Result<PathBuf> {
        let path = state_root()?
            .join("configs")
            .join(format!("{}.conf", handshake.logical_name));
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("wireguard_windows_broker_config_path_unsafe");
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        file.write_all(&handshake.request.config_bytes)?;
        file.sync_all()?;
        Ok(path)
    }
}

#[cfg(windows)]
fn main() {
    windows_service::main();
}
