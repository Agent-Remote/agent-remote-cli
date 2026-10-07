//! Local loopback listeners and the restricted SSH/HTTP2 tunnel client.

use std::cmp::min;
use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use h2::client::SendRequest;
use http::{Method, Request, StatusCode};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{sleep, timeout};

#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

use crate::api::{
    ApiClient, CreatePortForwardRequest, CreatedPortForwardData, PortForwardConnectionData,
    SessionData,
};
use crate::auth::load_device_token;
use crate::cli::{ForwardAction, ForwardArgs};
use crate::config::AppPaths;
use crate::identifiers::{resolve_id, short_id};
use crate::local_state::LocalState;
use crate::{platform, ssh, terminal, workspace};

const PROTOCOL_MAGIC: &[u8] = b"ARPF\x00\x01";
const MAX_HANDSHAKE_BYTES: usize = 8 << 10;
const LOCAL_CONNECTION_WAIT: Duration = Duration::from_secs(5);
const TUNNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(6);

/// Runs a forward start, list, or stop command.
pub async fn run(paths: &AppPaths, args: &ForwardArgs, workspace_tool: Option<&str>) -> Result<()> {
    match &args.action {
        Some(ForwardAction::List) => list(paths).await,
        Some(ForwardAction::Stop(stop_args)) => stop(paths, stop_args).await,
        None => start(paths, args, workspace_tool).await,
    }
}

async fn start(paths: &AppPaths, args: &ForwardArgs, workspace_tool: Option<&str>) -> Result<()> {
    start_with_ssh(paths, args, workspace_tool, platform::ssh_binary()).await
}

async fn start_with_ssh(
    paths: &AppPaths,
    args: &ForwardArgs,
    workspace_tool: Option<&str>,
    ssh_binary: std::path::PathBuf,
) -> Result<()> {
    let remote_port = args
        .remote_port
        .filter(|port| *port > 0)
        .context("REMOTE_PORT must be between 1 and 65535")?;
    let listeners = bind_loopback_listeners(&args.local_port, remote_port).await?;
    let local_port = listeners
        .first()
        .context("no local loopback listener was created")?
        .local_addr()?
        .port();
    let (server_url, device_id, token) = load_device_token(paths).await?;
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    state
        .get_device(&device_id)?
        .and_then(|device| device.ssh_key_id)
        .context("current device has no SSH key metadata; run agent-remote login again")?;
    let client = ApiClient::new(server_url)?;
    let session = resolve_session(&client, &token, args.session.as_deref(), workspace_tool).await?;
    let created = client
        .create_port_forward(
            &token,
            &session.id,
            &CreatePortForwardRequest {
                remote_port,
                local_port,
                client_instance_id: client_instance_id(),
                ttl_seconds: args.ttl_seconds,
            },
        )
        .await?;

    serve_local_forward(
        paths, ssh_binary, client, token, created, listeners, args.open,
    )
    .await
}

async fn list(paths: &AppPaths) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(paths).await?;
    let forwards = ApiClient::new(server_url)?
        .list_port_forwards(&token)
        .await?;
    if forwards.is_empty() {
        terminal::note("No session port forwards found.");
        return Ok(());
    }
    let mut table = terminal::Table::new([
        "ID",
        "STATUS",
        "SESSION",
        "LOCAL",
        "REMOTE",
        "CONNECTIONS",
        "EXPIRES",
    ]);
    for forward in forwards {
        table.row([
            short_id(&forward.id),
            sanitize(&forward.status),
            short_id(&forward.session_id),
            forward.requested_local_port.to_string(),
            forward.remote_port.to_string(),
            forward.connection_count.to_string(),
            sanitize(&forward.expires_at),
        ]);
    }
    table.render();
    Ok(())
}

async fn stop(paths: &AppPaths, args: &crate::cli::ForwardStopArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(paths).await?;
    let client = ApiClient::new(server_url)?;
    let forwards = client.list_port_forwards(&token).await?;
    let targets: Vec<_> = if args.all {
        let session_reference = args
            .session
            .as_deref()
            .context("--session is required with --all")?;
        let session_ids: std::collections::BTreeSet<_> = forwards
            .iter()
            .map(|forward| forward.session_id.as_str())
            .collect();
        let session_id = resolve_id(session_reference, "session", session_ids.into_iter())?;
        forwards
            .iter()
            .filter(|forward| forward.session_id == session_id && !is_terminal(&forward.status))
            .collect()
    } else {
        let reference = args
            .forward_id
            .as_deref()
            .context("FORWARD is required unless --session --all is used")?;
        let forward_id = resolve_id(
            reference,
            "forward",
            forwards.iter().map(|forward| forward.id.as_str()),
        )?;
        forwards
            .iter()
            .filter(|forward| forward.id == forward_id)
            .collect()
    };
    if targets.is_empty() {
        bail!("no active port forwards match the selected scope");
    }
    for target in targets {
        let stopped = client.stop_port_forward(&token, &target.id).await?;
        terminal::success_line(format!(
            "Stopped forward {} ({})",
            short_id(&stopped.id),
            stopped.status
        ));
    }
    Ok(())
}

async fn resolve_session(
    client: &ApiClient,
    token: &str,
    reference: Option<&str>,
    workspace_tool: Option<&str>,
) -> Result<SessionData> {
    if let Some(reference) = reference {
        let sessions = client.list_sessions(token, workspace_tool, &[]).await?;
        let session_id = resolve_id(
            reference,
            "session",
            sessions.iter().map(|session| session.id.as_str()),
        )?;
        let session = sessions
            .into_iter()
            .find(|session| session.id == session_id)
            .context("resolved session disappeared")?;
        ensure_running_session(session)
    } else if let Some(tool_type) = workspace_tool {
        let identity = workspace::identify_workspace(None)?;
        let session = client
            .get_current_project_session(token, tool_type, &identity.project_key)
            .await?;
        ensure_running_session(session)
    } else {
        let statuses = vec!["running".to_string(), "active".to_string()];
        let sessions = client.list_sessions(token, None, &statuses).await?;
        match sessions.as_slice() {
            [session] => ensure_running_session(session.clone()),
            [] => bail!("no running session found; pass --session after starting a session"),
            _ => bail!("multiple running sessions found; pass --session explicitly"),
        }
    }
}

fn ensure_running_session(session: SessionData) -> Result<SessionData> {
    if !matches!(session.status.as_str(), "running" | "active") {
        bail!("session {} is not running", short_id(&session.id));
    }
    Ok(session)
}

async fn bind_loopback_listeners(value: &str, remote_port: u16) -> Result<Vec<TcpListener>> {
    let requested = parse_local_port(value, remote_port)?;
    let ipv4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, requested)))
        .await
        .with_context(|| format!("local port {requested} is unavailable on 127.0.0.1"))?;
    let port = ipv4.local_addr()?.port();
    let mut listeners = vec![ipv4];
    if let Ok(ipv6) = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await {
        listeners.push(ipv6);
    }
    Ok(listeners)
}

fn parse_local_port(value: &str, remote_port: u16) -> Result<u16> {
    match value {
        "same" => Ok(remote_port),
        "auto" => Ok(0),
        _ => {
            let port = value
                .parse::<u16>()
                .with_context(|| format!("invalid local port {value:?}"))?;
            if port == 0 {
                bail!("local port must be between 1 and 65535, or auto");
            }
            Ok(port)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_local_forward(
    paths: &AppPaths,
    ssh_binary: std::path::PathBuf,
    client: ApiClient,
    token: String,
    created: CreatedPortForwardData,
    listeners: Vec<TcpListener>,
    open: bool,
) -> Result<()> {
    let forward_id = created.forward.id.clone();
    let session_id = created.forward.session_id.clone();
    let remote_port = created.forward.remote_port;
    let expires_at = created.forward.expires_at.clone();
    let local_port = listeners
        .first()
        .context("local listener missing")?
        .local_addr()?
        .port();
    let (sender_tx, sender_rx) = watch::channel::<Option<SendRequest<Bytes>>>(None);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (status_tx, mut status_rx) = mpsc::channel(1);
    let (initial_probe_tx, initial_probe_rx) = oneshot::channel();
    let supervisor = tokio::spawn(supervise_tunnel(
        paths.clone(),
        ssh_binary,
        client.clone(),
        token.clone(),
        created,
        sender_tx,
        shutdown_rx,
        status_tx,
        initial_probe_tx,
    ));
    let outcome = async {
        let remote_ready = tokio::select! {
            probe = timeout(Duration::from_secs(20), initial_probe_rx) => {
                match probe {
                    Err(_) => return Err(anyhow!("timed out establishing the SSH tunnel")),
                    Ok(Ok(remote_ready)) => remote_ready,
                    Ok(Err(_)) => {
                        return status_rx.recv().await.unwrap_or_else(|| Err(anyhow!(
                            "tunnel supervisor stopped before establishing the SSH tunnel"
                        )));
                    }
                }
            }
            status = status_rx.recv() => {
                return status.unwrap_or_else(|| Err(anyhow!(
                    "tunnel supervisor stopped before establishing the SSH tunnel"
                )));
            }
        };

        terminal::success_line("Forward active");
        terminal::Details::new()
            .field("Session", short_id(&session_id))
            .field("Local", format!("http://127.0.0.1:{local_port}"))
            .field("Remote", format!("127.0.0.1:{remote_port}"))
            .field("Forward ID", &forward_id)
            .field("Expires", expires_at)
            .render();
        println!("Press Ctrl-C to stop. The remote dev server is not exposed publicly.");
        if open && remote_ready {
            open_browser(&format!("http://127.0.0.1:{local_port}"))?;
        } else if !remote_ready {
            terminal::note(
                "The remote port is not listening yet. The forward will remain active and accept later connections.",
            );
        }

        let (connection_tx, mut connection_rx) = mpsc::channel(128);
        let mut accept_tasks = Vec::new();
        for listener in listeners {
            let connection_tx = connection_tx.clone();
            accept_tasks.push(tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((connection, _)) => {
                            if connection_tx.send(connection).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }));
        }
        drop(connection_tx);
        let outcome = loop {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => {
                    signal.context("failed to wait for Ctrl-C")?;
                    break Ok(());
                }
                status = status_rx.recv() => {
                    break status.unwrap_or_else(|| Err(anyhow!("tunnel supervisor stopped unexpectedly")));
                }
                connection = connection_rx.recv() => {
                    let Some(connection) = connection else {
                        break Err(anyhow!("all local loopback listeners stopped"));
                    };
                    tokio::spawn(proxy_local_connection(connection, sender_rx.clone(), forward_id.clone()));
                }
            }
        };
        for task in accept_tasks {
            task.abort();
        }
        outcome
    }
    .await;
    let _ = shutdown_tx.send(true);
    let _ = supervisor.await;
    let _ = client.stop_port_forward(&token, &forward_id).await;
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn supervise_tunnel(
    paths: AppPaths,
    ssh_binary: std::path::PathBuf,
    client: ApiClient,
    token: String,
    created: CreatedPortForwardData,
    sender_tx: watch::Sender<Option<SendRequest<Bytes>>>,
    mut shutdown_rx: watch::Receiver<bool>,
    status_tx: mpsc::Sender<Result<()>>,
    initial_probe_tx: oneshot::Sender<bool>,
) {
    let mut initial_connection = Some(created.connection.clone());
    let mut initial_probe_tx = Some(initial_probe_tx);
    let mut delay = Duration::from_millis(250);
    loop {
        if *shutdown_rx.borrow() {
            return;
        }
        let connection = match initial_connection.take() {
            Some(connection) => Ok(connection),
            None => {
                client
                    .create_port_forward_connection(&token, &created.forward.id)
                    .await
            }
        };
        let connection = match connection {
            Ok(connection) => connection,
            Err(error) => {
                if *shutdown_rx.borrow() {
                    return;
                }
                if error.is_port_forward_terminal() {
                    let _ = status_tx.send(Err(error.into())).await;
                    return;
                }
                if wait_retry(&mut shutdown_rx, delay).await {
                    return;
                }
                delay = min(delay.saturating_mul(2), Duration::from_secs(10));
                continue;
            }
        };
        match timeout(
            TUNNEL_CONNECT_TIMEOUT,
            connect_ssh_tunnel(&ssh_binary, &paths, &created, connection),
        )
        .await
        {
            Err(_) => {}
            Ok(Ok((mut sender, connection, mut process))) => {
                let mut connection = Box::pin(connection);
                let (remote_ready, shutdown_requested) = {
                    let probe = probe_remote(&mut sender, &created.forward.id);
                    tokio::pin!(probe);
                    tokio::select! {
                        result = &mut probe => (Some(result.is_ok()), false),
                        _ = &mut connection => (None, false),
                        changed = shutdown_rx.changed() => {
                            let _ = changed;
                            (None, true)
                        }
                    }
                };
                if shutdown_requested {
                    drop(connection);
                    wait_or_kill_child(&mut process).await;
                    return;
                }
                let Some(remote_ready) = remote_ready else {
                    let _ = process.child.kill().await;
                    if wait_retry(&mut shutdown_rx, delay).await {
                        return;
                    }
                    delay = min(delay.saturating_mul(2), Duration::from_secs(10));
                    continue;
                };
                delay = Duration::from_millis(250);
                let _ = sender_tx.send(Some(sender));
                if let Some(initial_probe_tx) = initial_probe_tx.take() {
                    let _ = initial_probe_tx.send(remote_ready);
                }
                let shutdown_requested = tokio::select! {
                    result = &mut connection => {
                        let _ = result;
                        false
                    }
                    changed = shutdown_rx.changed() => {
                        let _ = changed;
                        true
                    }
                };
                let _ = sender_tx.send(None);
                if shutdown_requested {
                    drop(connection);
                    wait_or_kill_child(&mut process).await;
                    return;
                }
                let _ = process.child.kill().await;
            }
            Ok(Err(error)) => {
                if error.terminal {
                    let _ = status_tx.send(Err(error.error)).await;
                    return;
                }
            }
        }
        if wait_retry(&mut shutdown_rx, delay).await {
            return;
        }
        delay = min(delay.saturating_mul(2), Duration::from_secs(10));
    }
}

async fn wait_or_kill_child(process: &mut TunnelProcess) {
    if timeout(TUNNEL_SHUTDOWN_TIMEOUT, process.child.wait())
        .await
        .is_err()
    {
        let _ = process.child.kill().await;
        let _ = process.child.wait().await;
    }
}

struct TunnelProcess {
    child: Child,
    #[cfg(windows)]
    _job: OwnedHandle,
}

impl TunnelProcess {
    fn new(child: Child) -> Result<Self> {
        #[cfg(windows)]
        let _job = assign_kill_on_close_job(&child)?;
        Ok(Self {
            child,
            #[cfg(windows)]
            _job,
        })
    }
}

#[cfg(windows)]
fn assign_kill_on_close_job(child: &Child) -> Result<OwnedHandle> {
    let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw_job.is_null() {
        return Err(io::Error::last_os_error()).context("failed to create an SSH process job");
    }
    let job = unsafe { OwnedHandle::from_raw_handle(raw_job) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let configured = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&limits).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured == 0 {
        return Err(io::Error::last_os_error()).context("failed to configure the SSH process job");
    }
    let child_handle = child
        .raw_handle()
        .context("SSH process handle is unavailable")?;
    let assigned = unsafe { AssignProcessToJobObject(job.as_raw_handle(), child_handle) };
    if assigned == 0 {
        return Err(io::Error::last_os_error()).context("failed to assign SSH to its process job");
    }
    Ok(job)
}

async fn wait_retry(shutdown: &mut watch::Receiver<bool>, duration: Duration) -> bool {
    tokio::select! {
        _ = sleep(duration) => false,
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

struct TunnelConnectError {
    terminal: bool,
    error: anyhow::Error,
}

async fn connect_ssh_tunnel(
    ssh_binary: &Path,
    paths: &AppPaths,
    created: &CreatedPortForwardData,
    connection_token: PortForwardConnectionData,
) -> std::result::Result<
    (
        SendRequest<Bytes>,
        h2::client::Connection<ChildStdio, Bytes>,
        TunnelProcess,
    ),
    TunnelConnectError,
> {
    paths.ensure_base_dirs().map_err(retryable)?;
    let known_hosts = paths.ssh_dir().join("known_hosts");
    let child = Command::new(ssh_binary)
        .args(ssh::tunnel_args(
            &created.node_wireguard_ip,
            created.ssh_port,
            &created.ssh_user,
            &created.forward.id,
            &known_hosts,
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(retryable)?;
    let mut process = TunnelProcess::new(child).map_err(|error| TunnelConnectError {
        terminal: true,
        error,
    })?;
    let mut input = process
        .child
        .stdin
        .take()
        .context("SSH stdin is unavailable")
        .map_err(retryable)?;
    let mut output = process
        .child
        .stdout
        .take()
        .context("SSH stdout is unavailable")
        .map_err(retryable)?;
    write_client_handshake(
        &mut input,
        ClientHandshake {
            forward_id: created.forward.id.clone(),
            connect_token: connection_token.token,
            client_version: crate::cli::VERSION.to_string(),
            max_streams: 128,
        },
    )
    .await
    .map_err(retryable)?;
    let response = read_server_handshake(&mut output)
        .await
        .map_err(retryable)?;
    if !response.ok {
        let code = response
            .error_code
            .unwrap_or_else(|| "AUTH_INVALID".to_string());
        return Err(TunnelConnectError {
            terminal: is_terminal_code(&code),
            error: anyhow!("tunnel authorization failed: {code}"),
        });
    }
    if response.protocol != Some(1) || response.max_streams.is_none_or(|value| value == 0) {
        return Err(TunnelConnectError {
            terminal: true,
            error: anyhow!("node returned an incompatible tunnel protocol"),
        });
    }
    h2::client::handshake(ChildStdio { output, input })
        .await
        .map(|(sender, connection)| (sender, connection, process))
        .map_err(retryable)
}

fn retryable(error: impl Into<anyhow::Error>) -> TunnelConnectError {
    TunnelConnectError {
        terminal: false,
        error: error.into(),
    }
}

fn is_terminal_code(code: &str) -> bool {
    matches!(
        code,
        "AUTH_INVALID"
            | "AUTH_EXPIRED"
            | "AUTH_REDEEMED"
            | "DEVICE_REVOKED"
            | "SESSION_NOT_RUNNING"
            | "SESSION_MISMATCH"
            | "NODE_MISMATCH"
            | "PORT_NOT_ALLOWED"
            | "POLICY_LIMIT"
            | "TUNNEL_EXPIRED"
            | "PROTOCOL_UNSUPPORTED"
    )
}

async fn probe_remote(sender: &mut SendRequest<Bytes>, forward_id: &str) -> Result<()> {
    let mut ready = sender.clone().ready().await?;
    let request = connect_request(forward_id)?;
    let (response, _) = ready.send_request(request, true)?;
    let response = timeout(Duration::from_secs(10), response)
        .await
        .context("remote port probe timed out")??;
    if response.status() != StatusCode::OK {
        bail!("remote port probe returned {}", response.status());
    }
    Ok(())
}

async fn proxy_local_connection(
    connection: TcpStream,
    mut sender_rx: watch::Receiver<Option<SendRequest<Bytes>>>,
    forward_id: String,
) {
    let sender = match timeout(LOCAL_CONNECTION_WAIT, wait_for_sender(&mut sender_rx)).await {
        Ok(Ok(sender)) => sender,
        _ => return,
    };
    if let Err(error) = proxy_stream(connection, sender, &forward_id).await {
        terminal::warning_line(format!(
            "Port-forward stream {forward_id} closed with an error: {error:#}"
        ));
    }
}

async fn wait_for_sender(
    receiver: &mut watch::Receiver<Option<SendRequest<Bytes>>>,
) -> Result<SendRequest<Bytes>> {
    loop {
        if let Some(sender) = receiver.borrow().clone() {
            return Ok(sender);
        }
        receiver
            .changed()
            .await
            .context("tunnel supervisor stopped")?;
    }
}

async fn proxy_stream(
    connection: TcpStream,
    sender: SendRequest<Bytes>,
    forward_id: &str,
) -> Result<()> {
    let mut ready = sender.ready().await?;
    let request = connect_request(forward_id)?;
    let (response, send_stream) = ready.send_request(request, false)?;
    let (read_half, mut write_half) = connection.into_split();
    let upload = tokio::spawn(upload_stream(read_half, send_stream));
    let response = response.await?;
    if response.status() != StatusCode::OK {
        upload.abort();
        bail!("remote tunnel stream returned {}", response.status());
    }
    let mut body = response.into_body();
    while let Some(data) = body.data().await {
        let data = data?;
        write_half.write_all(&data).await?;
        body.flow_control().release_capacity(data.len())?;
    }
    write_half.shutdown().await?;
    upload.await??;
    Ok(())
}

async fn upload_stream(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut stream: h2::SendStream<Bytes>,
) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(64 << 10);
    loop {
        buffer.resize(64 << 10, 0);
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            stream.send_data(Bytes::new(), true)?;
            return Ok(());
        }
        buffer.truncate(read);
        while buffer.has_remaining() {
            stream.reserve_capacity(buffer.remaining());
            let capacity = poll_fn(|context| stream.poll_capacity(context))
                .await
                .transpose()?
                .context("HTTP/2 stream closed before upload completed")?;
            let size = min(capacity, buffer.remaining());
            if size == 0 {
                continue;
            }
            stream.send_data(buffer.split_to(size).freeze(), false)?;
        }
    }
}

fn connect_request(forward_id: &str) -> Result<Request<()>> {
    Request::builder()
        .method(Method::CONNECT)
        .uri("https://session-loopback")
        .header("x-agent-remote-forward-id", forward_id)
        .body(())
        .context("failed to build tunnel stream request")
}

#[derive(Serialize)]
struct ClientHandshake {
    forward_id: String,
    connect_token: String,
    client_version: String,
    max_streams: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerHandshake {
    ok: bool,
    protocol: Option<u32>,
    #[serde(rename = "lease_expires_at")]
    _lease_expires_at: Option<String>,
    max_streams: Option<u32>,
    #[serde(rename = "max_bytes_per_second")]
    _max_bytes_per_second: Option<u64>,
    error_code: Option<String>,
}

async fn write_client_handshake(
    writer: &mut (impl AsyncWrite + Unpin),
    value: ClientHandshake,
) -> Result<()> {
    let payload = serde_json::to_vec(&value)?;
    if payload.len() > MAX_HANDSHAKE_BYTES {
        bail!("tunnel handshake is too large");
    }
    writer.write_all(PROTOCOL_MAGIC).await?;
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_server_handshake(reader: &mut (impl AsyncRead + Unpin)) -> Result<ServerHandshake> {
    timeout(Duration::from_secs(10), async {
        let mut magic = [0_u8; 6];
        reader.read_exact(&mut magic).await?;
        if magic != PROTOCOL_MAGIC {
            bail!("node returned invalid tunnel handshake magic");
        }
        let length = reader.read_u32().await? as usize;
        if length == 0 || length > MAX_HANDSHAKE_BYTES {
            bail!("node returned invalid tunnel handshake length");
        }
        let mut payload = vec![0; length];
        reader.read_exact(&mut payload).await?;
        serde_json::from_slice(&payload).context("node returned invalid tunnel handshake payload")
    })
    .await
    .context("tunnel handshake timed out")?
}

struct ChildStdio {
    output: ChildStdout,
    input: ChildStdin,
}

impl AsyncRead for ChildStdio {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.output).poll_read(context, buffer)
    }
}

impl AsyncWrite for ChildStdio {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.input).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.input).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.input).poll_shutdown(context)
    }
}

fn open_browser(url: &str) -> Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = std::process::Command::new("open");
        command.arg(url);
        command
    } else if cfg!(target_os = "windows") {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", "", url]);
        command
    } else {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(url);
        command
    };
    command
        .spawn()
        .context("failed to open the local forward URL")?;
    Ok(())
}

fn client_instance_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut value = String::with_capacity(35);
    value.push_str("ci_");
    for byte in bytes {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

fn sanitize(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn is_terminal(status: &str) -> bool {
    matches!(status, "stopped" | "expired" | "revoked" | "failed")
}

#[cfg(test)]
#[path = "../tests/unit/src/port_forward.rs"]
mod tests;
