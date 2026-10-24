# Native account binding terminal

Account binding sessions are not regular tool sessions. `agent-remote attach`
continues to address normal session UUIDs. Use the generation-bound command for
an account login terminal:

```sh
agent-remote account attach <full-account-uuid> \
  --binding-session <exact-binding-session-id> \
  --expected-server https://server.example \
  --expected-device <current-device-id>
```

The last two flags are optional for direct human use but must be provided together.
Desktop supplies both from the reviewed account context and selects the same
`AGENT_REMOTE_HOME`. It runs the command in its native terminal, not through
`--desktop-control`, and does not read credentials or execute a server-provided
command string. The account must be a full lowercase canonical UUID; the binding
ID must match `bind-<first-12-account-hex>-<12-lowercase-attempt-hex>` exactly.
Prefixes and a replacement binding attempt are rejected.

Capability discovery advertises this separate protocol:

```json
{"terminal_operations":[{"method":"accounts.binding.attach","protocol_version":1}]}
```

It is not an `operations` entry and is not a machine stdio request method. The
schema version announces CLI command support, not Server/Node compatibility,
current device permissions, or authorization success. Unsupported old servers
fail closed; the CLI never falls back to parsing `connect_command`, plain binding
SSH, or a different/latest session generation.

The Server requires `runtime_capabilities.binding_attach` from the Node's bounded
probe of its actual installed SSH gateway. Missing or incompatible support returns
`NODE_BINDING_ATTACH_UNSUPPORTED`; the CLI asks the user to upgrade both Node and
gateway and wait for a fresh heartbeat. It never sends the new command to a known
legacy gateway or retries with the old three-word binding form. The same check
applies while polling the original authorization task.

## Authorization and connection

The CLI validates the selected context, acquires its existing login lock, reads or
renews the device credential, then locks and rechecks configuration. It submits
exactly one typed request:

```text
POST /api/v1/tool-accounts/<account-id>/bind/attach
{"expected_binding_session_id":"<binding-id>"}
```

The version-1 response requires exactly `version`, `tool_account_id`,
`binding_session_id`, `node_id`, `device_id`, `ssh_host`, `ssh_port`, `ssh_user`,
`tmux_session_name`, `authorization_task_id`, `authorization_task_status`, and
`expires_in`. Unknown fields, endpoint injection, mismatched IDs, future task
states, and invalid lifetimes fail closed. No executable command field is accepted.
The TTL must be 1–300 seconds. Device/account/binding IDs must match the original
request; node must be a canonical UUID. Hosts must be IP addresses or bounded DNS
labels, users and task/tmux identifiers use bounded safe ASCII characters.

While authorization is `pending`, `leased`, or `running`, the CLI only polls:

```text
GET /api/v1/tool-accounts/<account-id>/bind/attach/<encoded-task-id>?expected_binding_session_id=<encoded-binding-id>
```

All target identity/endpoint fields and the task ID must remain unchanged. Only
status and remaining lifetime may change. The CLI allows up to the lesser of
30 seconds and the original TTL for polling; the overall authorization boundary
is 90 seconds. Failed/cancelled/expired tasks stop the connection. Poll failures,
malformed replies, cancellation, and timeout never trigger another POST. A lost
submission result may already have created an authorization task: refresh account
status and make a new explicit decision instead of automatically retrying.

Only `succeeded` authorization proceeds to SSH. Credential and configuration
lock guards are released before the long-lived terminal starts. SSH receives the
fixed five remote arguments:

```text
agent-remote-attach --binding <account-id> --binding-session <binding-id>
```

Binding SSH explicitly disables agent forwarding, X11 forwarding, and configured
port forwarding (`-a`, `-x`, `ClearAllForwardings=yes`). It uses existing known-host
storage, batch authentication, connect timeout, and keepalive policies. The matching Server and updated Node are required. The Node
must independently validate the current SSH key and exact account/binding generation; a CLI
validation is not a substitute for Node enforcement. The Server's generated
`connect_command`, raw error text, verifier, and device token are never printed or
executed by this workflow.

These binding generation/key checks do not assert the additional client-selected
expected-device comparison introduced by [exact session attach](desktop-session-attach.md).
That separate session protocol does not change the existing binding command.

SIGTERM cancels pending authorization without replay. Once SSH starts, canceled
native/PTY work kills its owned SSH child and releases the PTY wait task. Stopping
this local connection does not claim to roll back authorization, terminate the
remote binding task, delete agent login state, or stop other remote sessions.

## Validation boundary

Isolated HTTP and fake-SSH tests exercise one POST followed by GET-only polling,
exact endpoints/argv, target changes, unsupported servers, command-field injection,
error redaction, and cancellation. A real local PTY fixture checks that canceling
the bridge reaps its owned SSH child. These are local tests, not evidence of a live
Server/Node binding or a real agent login. Native Windows/Linux and community package
acceptance remain separate platform checks.
