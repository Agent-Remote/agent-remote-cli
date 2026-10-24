# Desktop remote account operations, version 1

The `--desktop-control` protocol provides `accounts.create`, `accounts.status`,
`accounts.bind`, `accounts.verify`, and `accounts.disable`. They reuse the existing
control-plane API with the selected device credential. Human CLI names, flags,
prefix resolution, and presentation remain unchanged. Desktop requests use full
exact IDs and never parse human CLI output or directly read credentials/database.

## Context and confirmation

Every request includes `expected_context` with all three keys present:

```json
{"home":"/absolute/cli/home","server_url":"https://server.example","active_device_id":"device-id"}
```

The two nullable credential-context fields must be explicitly present, but these
remote operations require both to be nonnull. Context must match the selected CLI
home, server, and device before credentials are read. Mutations also require
`confirmed: true`; false confirmation never calls the server. Input types, unknown
fields, IDs, field lengths, and confirmation are checked before operation work.

`accounts.status` takes only `expected_context` and `account_id`. Its result is
`{context, account, binding}`. Account and binding are **two separate HTTP GET
observations**, not an atomic snapshot; their statuses may legitimately differ.
Status does not start a binding or verification task.

`accounts.create` takes all existing CLI create fields:

```json
{"confirmed":true,"expected_context":{"home":"/absolute/cli/home","server_url":"https://server.example","active_device_id":"device-id"},"tool":"claude","name":"My account","region":"SG","timezone":"Asia/Singapore","locale":"en_US.UTF-8","tags":["preferred:asia"]}
```

`accounts.bind`, `accounts.verify`, and `accounts.disable` take
`{confirmed, expected_context, account_id}`. They perform one POST to the existing
`bind/start`, `bind/verify`, or `disable` endpoint. No account ID prefix resolution
or automatic retry occurs. Create POSTs to the existing account collection.

## Public results

Every accepted mutation returns all of these keys:

```json
{"operation_id":"request-id","context":{"home":"/absolute/cli/home","server_url":"https://server.example","active_device_id":"device-id"},"accepted":true,"account":null,"binding":{"tool_account_id":"full-account-id","status":"binding_session_starting","node_id":"node-id","binding_session_id":"bind-session-id","tmux_session_name":"claude-binding","account_remote_path":"/remote/accounts/example","task_id":"create_binding_session:account:attempt","error_code":null}}
```

Create and disable return a nonnull `account` and null `binding`. Bind and verify
return the opposite and require a nonnull task ID. A task ID can contain colons:
it is an opaque identifier, not an executable argument or command. `accepted`
means the server accepted this request; it never means that a queued binding task
completed or that a user signed into the agent. Refresh status explicitly to see
later observations. Disable may return accepted for an already disabled account;
there is no `changed` claim.

The account projection contains exactly:

- `id`, `tool_type`, `display_name`, `status`, `region_code`, `timezone`, `locale`;
- `preferred_node_tags`, `affinity_node_id` (nullable), `runtime_backend` (nullable);
- `created_at`, `updated_at`.

The binding projection contains exactly:

- `tool_account_id`, `status`, `node_id` (nullable);
- `binding_session_id`, `tmux_session_name`, `account_remote_path`, `task_id` (nullable);
- `error_code`: null or the fixed `binding_failed` code when upstream error detail
  is present. This code does not reproduce or classify the raw error message.

All nullable keys are emitted explicitly. User IDs, credentials, cookies,
`connect_command`, `verifier`, raw upstream errors, and arbitrary added API fields
are excluded. Binding metadata is informational and grants no terminal authority.
The separate [typed binding terminal flow](desktop-account-binding.md) has its own command contract.

Known account/binding statuses are `binding_requested`,
`binding_session_starting`, `binding_waiting_user_login`, `binding_verifying`,
`active`, `expired`, `disabled`, `failed`, `node_unavailable`, and `migrating`.
Known nonnull runtime backends are `native` and `docker_sandbox`. Unknown projected statuses
or account runtime backends cannot silently authorize an operation or produce a validated receipt.
Create verifies returned create fields exactly, including ordered tags. Disable
requires the exact account ID and `disabled` status. Status and binding operations
verify returned account identity exactly.

Disable changes account availability and revokes its port-forward grants under
the existing server policy. It does **not** delete the account, erase agent login
credentials, or stop/delete existing sessions.

## Bounds and failure semantics

Account/node/device IDs and tool identifiers are 1–128 ASCII letters, digits,
underscores, or hyphens. Home must be absolute without parent traversal or control
characters, at most 32768 platform path units. Server context is bounded to 8192
UTF-8 bytes. Other text is nonempty, trimmed, and contains no Unicode control
characters. Name is at most 256 UTF-8 bytes; region 64; timezone/locale 128; tags
at most 64 items of 128 bytes each. Duplicate tags are permitted and preserved.
Account timestamps are informational text of at most 128 bytes. Binding session,
tmux, and task strings are at most 512 bytes; remote account path at most 4096.
Nullable binding fields remain nullable on reads even when tasks are absent.

Mutations hold the shared per-home login guard across credential retrieval and
remote submission. After credential refresh, they acquire `config-write.lock`,
recheck context, and hold it through the POST/result projection. This prevents
cooperating `Config::save` writers from switching context during submission; such
writers receive the existing busy error. No SQLite transaction is retained across
network calls, and these operations write no local account records. The existing
credential refresh workflow may update its own credential/renewal metadata.

Explicit HTTP 4xx rejections produce `account_rejected` and the HTTP status.
Transport failure, HTTP 5xx/redirects, malformed successful responses, unexpected
identity/fields, missing mutation task IDs, and future status/backend values
produce `account_outcome_unknown`. A lost receipt or cancellation may occur after
the server accepted a mutation. **Never automatically replay an unknown request.**
Inspect account lists/status and obtain a new explicit decision. Create, bind, and
verify can create a new account/attempt/task every time; `operation_id` is only
request/receipt correlation, not an idempotency key or recovery journal.

Read failures and preflight failures use fixed `invalid_params`,
`confirmation_required`, `configuration_unavailable`, `configuration_changed`,
`authentication_required`, `credential_unavailable`, `permission_denied`,
`account_not_found`, `rate_limited`, `server_unavailable`, or
`account_response_invalid` codes. All account error receipts set `retryable:false`
and never include upstream error text. Read cancellation uses `canceled`, read
deadline uses `timeout`; mutation cancellation/deadline uses
`account_outcome_unknown`.

The shared CLI protocol bounds reads to 75 seconds and mutations to 120 seconds;
HTTP requests use 30-second limits and bounded response bodies. Login lock waits
are bounded. On Unix, SIGTERM drops pending work and guards, allowing native
credential subprocess cleanup. The desktop process deadline remains the final
bound for native credential APIs that cannot be interrupted internally. Unknown
outcomes never imply rollback or remote task cancellation.
