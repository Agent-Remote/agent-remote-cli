# Exact native session attachment

Desktop connects to a reviewed existing Claude session with:

```sh
fclaude attach <canonical-nonzero-session-uuid> \
  --expected-server https://server.example \
  --expected-device <canonical-nonzero-device-uuid>
```

Both expectation flags are optional together for ordinary CLI use. Without them,
the existing short-ID resolution and attach behavior remain unchanged. Desktop
always supplies both and selects the original `AGENT_REMOTE_HOME`. These arguments
contain only public identities; credentials remain inside Rust. Capability
discovery advertises `terminal_operations` entry `sessions.attach`, version 1.
This is a native terminal operation, not a machine stdio request method.

The CLI compares strict configuration before authentication work, acquires the
existing per-home login lock followed by the configuration publication lock, then
rechecks the complete configuration before reading or refreshing device credentials.
It never registers a device. The frozen client, credential and expected identities
are retained through bounded authorization. A configuration change cannot redirect
the request to another server or device.

The CLI submits one request; the Server verifies the session is Claude before
creating any authorization task:

```text
POST /api/v1/sessions/<session-id>/attach/exact
{"expected_device_id":"<device-id>"}
```

The Server compares the expected device with the authenticated active device before
creating authorization work. Session ownership must match that device's user.
The strict version-1 response contains exactly:

```text
version, session_id, tool_type, device_id, node_id, ssh_host, ssh_port, ssh_user,
tmux_session_name, forward_ssh_agent, authorization_task_id,
authorization_task_record_id, authorization_task_status, expires_in
```

`tool_type` is required and must be `claude`. UUIDs are canonical and nonzero.
Host, user, tmux name and task identifier are
bounded and validated. Task status is required, with only `pending`, `leased`,
`running`, `succeeded`, `failed`, `cancelled`, and `expired` accepted. TTL is 1–300
seconds. No server command text is accepted. Missing, extra or malformed fields
fail closed, including missing status; legacy success defaults do not apply.

Pending authorization is observed only through:

```text
GET /api/v1/sessions/<session-id>/attach/exact/<encoded-task-id>?expected_device_id=<device-id>&expected_task_record_id=<task-record-uuid>
```

GET verifies the original database task row, device, session and payload without
creating, resetting or replacing a task. Every response target field, including
the forwarding decision and task record UUID, must equal the first response;
only status and lifetime may change. Polling is limited to 30 seconds or the
original TTL, whichever is shorter, within a 90-second authorization boundary.
Unknown outcomes, old endpoints, incompatible Nodes, missing data and timeouts
never trigger a second POST or a legacy fallback. A new attempt requires a fresh
explicit user decision. `--print-only` still authorizes and waits, then prints
the locally constructed command without executing SSH.

Only succeeded authorization starts the native terminal. Credentials and locks
are released before that terminal's lifetime. SSH uses frozen connection fields
and the fixed remote command:

```text
agent-remote-attach --session <session-id> --expected-device <device-id>
```

The Server requires `runtime_capabilities.session_attach` version 1, obtained from
the Node's probe of its actually installed gateway. The gateway compares the
expected device with the authorized-key forced device and asks the Server to
validate the actual active SSH key, device and session. Missing/incompatible
capability returns `NODE_SESSION_ATTACH_UNSUPPORTED`, with no old-command fallback.
The account-binding protocol remains separate; its generation/key checks alone
do not claim this additional expected-device comparison.

Exact SSH disables configured port and X11 forwarding. Agent forwarding is
explicitly enabled only when the frozen Server authorization allows it; otherwise
it is explicitly disabled. SIGTERM cancels authorization and kills owned SSH/PTY
work after launch, without claiming to stop the remote Claude session or roll back
an already accepted SSH authorization. Terminal text copy/paste and login-link
copying remain available. Exact mode does not initialize the legacy clipboard
image/file receiver: that independent transfer channel does not verify the
expected device and SSH key. The implemented exact attachment transfer channel provides those
checks through the `session_attachment_transfer` v1 lease. It remains release-gated
by real Server/Node/SSH acceptance; until that evidence exists, exact mode stays
text-only and no legacy fallback is attempted. Ordinary CLI attachment retains its existing file transfer behavior.

Desktop live connection reuse is bound to home, server, device, session and local
project. UUID-only history is a navigation hint, not connection authority: refresh
the remote list and obtain a new confirmation before reconnecting.

Focused tests use isolated HTTP, credential state and fake SSH to verify exact
request/response identities, one-POST polling, context races, strict decoding,
forwarding and cancellation. These tests do not replace live three-platform
Server/Node acceptance.
