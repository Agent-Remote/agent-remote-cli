# Windows WireGuard UAC worker boundary

The Windows helper contains a small, one-shot worker transport in
`src/wireguard/windows_broker.rs`. The packaged
`agent-remote-wireguard-broker.exe` is the protected SCM LocalSystem service;
linking the module alone does not mean that it is installed, and
`wireguard.bridge.status` observes the fixed SCM service after
`-InstallBroker` registers it. Installation alone, or merely finding the
fixed named pipe, is not enough to report an authenticated/ready bridge: a
user process can create the same endpoint while the service is absent. The
status projection therefore reports installation/protocol facts while keeping
caller authentication and execution fail-closed until the server-process
identity handshake is accepted on Windows hosts.

The worker creates a `\\.\pipe\AgentRemote-WireGuard-v1-*` message pipe with
`PIPE_REJECT_REMOTE_CLIENTS`, a single instance, a protected DACL for SYSTEM,
Administrators, and the interactive user, and a 30-second default timeout. It
accepts one connection and one bounded frame, then disconnects and exits. A
caller that does not connect before the deadline cannot keep an elevated process
alive. Frames are capped at 64 KiB and transferred configuration bytes at 48 KiB.
`PipeWorker::handshake` performs the complete one-shot exchange and
`PipeWorker::serve_once` disconnects after one response. The unprivileged side
uses `PipeClient::connect`/`transact`; it never executes a helper locally.

After the pipe connects, the worker obtains the client process ID and session ID
with `GetNamedPipeClientProcessId` and `GetNamedPipeClientSessionId`. It opens
the client token with `TOKEN_QUERY`, reads the user SID and token
authentication ID, and computes a domain-separated caller digest from the
token, process ID, and session ID. The request's `caller_sha256` must equal
this independently observed digest. A different process, replaced token,
different session, malformed digest, expired request, changed config hash,
unknown field, non-canonical JSON, or second request is rejected before any
privileged action. The desktop can use `observe_current_caller` and
`WorkerRequest::new` to build a request, but the worker always repeats the
observation from the named-pipe peer.

The private configuration is carried as bounded base64 bytes and is immediately
decoded into a zeroizing buffer. The worker compares its SHA-256 before use; the
bytes and source path never enter desktop JSON, logs, operation records, or
debug output. `WorkerResponse` contains only protocol version, request ID, an
acceptance bit, and a fixed error code.

This identity check is transport authentication only. A broker must call
`WorkerHandshake::issue_permit` only after the execution-store submission has
reported durable, target-scoped facts. The resulting `ExecutionPermit` binds
the request, caller token digest, config digest, target scope and expiry; its
`consume` method marks it used before returning claims, so retries after an
uncertain helper result cannot execute again. A false durability flag, stale
request, identity mismatch, or second consume fails closed.

The transport does not replace the existing caller challenge, execution-store
journal, plan recheck, trusted-tool checks, target observation, or UAC policy.
The packaged `agent-remote-wireguard-broker.exe` is the protected execution
service. `scripts/install.ps1 -InstallBroker` copies it to
`%ProgramFiles%\Agent-Remote\bin`, grants only LocalSystem and Administrators
access, creates the `AgentRemoteWireGuardBroker` SCM service with
`New-Service`, applies a LocalSystem/Administrators service ACL, and starts it.
The service runs as LocalSystem, reports its SCM lifecycle, binds the fixed
`service` pipe, persists a flush-synced non-secret operation journal, consumes
the one-shot permit, writes the reviewed bytes under the protected
`%ProgramData%\Agent-Remote\WireGuard` tree, and invokes the fixed
`%ProgramFiles%\WireGuard\wireguard.exe` path with fixed arguments. It then
re-observes the named Windows service and returns only an operation digest and
target state. Any missing tool, ACL, identity, digest, permit, journal or
service response fails closed. The client never uses `runas`, `sudo`, PATH
resolution, or a user-controlled executable path for this operation.

The existing human `agent-remote-wireguard up/down` command retains its
interactive UAC helper for direct CLI use. Desktop reviewed mutations always
use the installed service endpoint. Windows and Linux releases do not require
publisher code signing; macOS keeps the community self-signing policy.

Focused contract tests live in `tests/unit/src/wireguard_windows_broker.rs` and
exercise pipe-name validation, caller binding, config integrity, canonical
frames, reviewed plan/target/config binding, expiry, durable-permit
requirements, single-use consumption, and the one-request lifetime. They do
not prompt for UAC or create a real tunnel. A native acceptance run on Windows
must install the package with `-InstallBroker`, verify the SCM service account
and ACL, issue one desktop apply, inspect the returned receipt, and confirm a
second replay is rejected.

The host-only status entry point is
`scripts/native-wireguard-broker-acceptance.ps1`. Invoke it with an already
built native binary, for example:

```powershell
pwsh -File scripts/native-wireguard-broker-acceptance.ps1 `
  -CliBinary C:\path\to\agent-remote.exe `
  -EvidenceDir $env:TEMP\agent-remote-wireguard-native
```

It checks the protected Program Files path and running LocalSystem SCM service,
then requires the desktop `wireguard.bridge.status` response. The client-side server-process identity handshake is implemented in the broker
transport, but the current Windows run remains failed/unfinished until native
acceptance exercises the installed service, handshake, tunnel operation and
restart evidence. A named pipe or service record alone cannot become `ready`.
The evidence file therefore never claims tunnel up/down, replay or restart until
a separate native destructive acceptance supplies those receipts.
