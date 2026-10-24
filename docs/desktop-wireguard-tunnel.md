# WireGuard tunnel plans and execution

`wireguard.tunnel.plan` is protocol version 1, effect `read`, credential `none`.
It does not start or stop a tunnel, initialize the home directory, log in, request
privilege, or run configuration hooks. Ordinary CLI up/down continue to use their
existing helper behavior. `wireguard.tunnel.apply` is the explicit confirmed
execution endpoint described below; the plan remains read-only.

Request parameters are exactly `expected_home`, `action` (`up` or `down`), and
`config` (required nullable absolute normalized path; null selects
`HOME/wireguard/agent-remote.conf`). The configured home must match exactly.

The result contains:

| Field | Meaning |
| --- | --- |
| `version` | 1 |
| `home`, `platform`, `action` | Bound local context and requested direction |
| `config` | The same seven-field configuration inspection as `wireguard.check` |
| `binding` | Null unless the configuration was parsed from a stable private regular file; otherwise `file_identity`, `content_sha256`, `public_key` |
| `tools` | `wg` and the platform tunnel tool, each with required `name`, `state`, `path`, `identity`, `sha256` |
| `target` | Native target observation described below |
| `issues` | Deduplicated fixed codes in the order below |

Configuration parsing and SHA-256 use exactly the bytes from one safely opened
handle, limited to 1 MiB. Handle metadata, native identity, parent/path identity,
and private permissions are rechecked. Changed observations become `unreadable`
with null binding; `ready` and `unsupported` always have a binding. Private keys
and configuration bytes are never serialized. The public key is derived locally.
Tool files are hashed with a 64 MiB limit and before/after identity checks;
failed snapshots retain their inventory but have null identity and hash. Missing
or non-executable tools always have both null. Tool hashes describe current bytes;
they do not establish trusted executable provenance or authorize elevation.
All public object identities are domain-separated SHA-256 lowercase hex strings.

`target` contains required `logical_name`, `state`, nullable `reason`,
`status_state`, and nullable `identity`. Native state is `absent`, `present`,
`unknown`, or `conflict`. Invalid names produce an empty logical name and
`unknown` with `invalid_name`. `identity.kind` selects:

- `linux_interface`: name, index, namespace identity, nullable public key.
- `macos_interface`: actual utun name and index, mapping and socket identities,
  nullable public key.
- `windows_service`: actual service name, executable path, configuration path,
  nullable configuration identity, service state, start type, account, nullable
  public key.

Unknown, inaccessible, or ambiguous native observations never mean absence.
Up requires positively observed absence before execution.
Down requires an actual observed target and matching configuration public key;
a Windows service additionally needs a matching configuration object identity.
Equivalent OS path aliases can match through object identity. No synthetic
runtime generation or ownership claim is made by this read-only plan.

Issues have this exact order (only applicable entries appear):

1. `config_not_ready`: configuration state is neither ready nor unsupported.
2. `config_unsupported`: unsupported configuration directives were found.
3. `tool_unavailable`: at least one tool is unavailable.
4. `tool_snapshot_unavailable`: an available tool lacks a stable snapshot.
5. `target_unknown`: native target cannot be established.
6. `target_conflict`: conflicting native target facts.
7. `target_already_present`: up requested for a present target.
8. `target_absent`: down requested for an absent target.
9. `config_target_mismatch`: down target public key differs from binding.
10. `target_key_unobserved`: present down target has no observed public key.
11. `service_config_mismatch`: present Windows down target's configuration
    identity is missing or does not match the configuration binding.
The list contains only applicable issues; an empty list is required before apply.

The plan is planning coverage only. GUI start/stop requires an explicit confirmed
apply with an unchanged plan; no plan alone is an elevation request or replayable
execution authorization.

## Confirmed apply handshake

`wireguard.tunnel.apply` is a version-1 machine endpoint for the explicit two-phase
boundary. Its parameters are exactly:

```json
{
  "confirmed": true,
  "expected_home": "/selected/home",
  "action": "up",
  "config": "/selected/home/wireguard/agent-remote.conf",
  "expected_plan": { "...": "the unchanged plan result" }
}
```

`config` must be present and either null or an absolute normalized path. The
`expected_plan` must be the complete result previously returned by
`wireguard.tunnel.plan`; all fields and nested object fields are compared with a
fresh read-only plan generated for the same home, action, and configuration. The
selection and plan are never replaced with a latest value. `confirmed: false`,
unknown fields, invalid paths, or any changed observation return fixed errors
(`confirmation_required`, `invalid_params`, or `wireguard_plan_stale`). A plan with
issues returns `wireguard_precondition_failed`. When the plan is clear, desktop-control reads the validated configuration at
ordinary user authority and sends the bytes, binding, plan digest and target
scope digest through the fixed platform broker client. The broker must
authenticate the native caller, consume a one-shot execution permit, and return
an operation receipt. There is no sudo, runas or helper fallback for this
endpoint. A second read-only plan must observe `present` for up or `absent`
for down; otherwise the result is `wireguard_outcome_unknown`. Success returns:

```json
{
  "operation_id": "request-id",
  "home": "/selected/home",
  "action": "up",
  "config": "/selected/home/wireguard/agent-remote.conf",
  "state": "observed",
  "target_state": "present"
}
```

The Rust client and request contracts do not install a long-lived privileged
broker. The repository supplies the protected macOS LaunchDaemon, Linux
system D-Bus/Polkit service and Windows SCM LocalSystem service; installation
is an explicit platform packaging step. The protected execution foundation
persists a hash-chained recovery journal, but it is not a privileged broker and
cannot authorize or replay a tunnel action. Caller authentication, permit
issuance, and native Windows/macOS/Linux runtime acceptance remain separate
release gates.

On macOS, `wireguard.bridge.status` additionally observes the fixed
LaunchDaemon label and paths with bounded `launchctl print` and strict
`codesign` checks. It rejects unsafe ownership, links, permissions, missing
identity pins, and malformed lifecycle output. This probe is diagnostics only:
it does not use Device.app's Network Broker XPC, install or control a daemon,
call `SMAppService`, or connect to XPC. The protected LaunchDaemon socket
client and caller binding are implemented separately; until the service is
installed and accepted on a target host, the macOS projection keeps protocol,
authentication, and execution unavailable.
