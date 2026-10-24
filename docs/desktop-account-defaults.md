# Desktop account defaults, version 1

The `--desktop-control` protocol exposes `accounts.default.get`,
`accounts.default.set`, and `accounts.default.clear`. These operate on the same
`default_tool_account:<tool>` SQLite metadata used by `agent-remote account
default` and `fclaude`. Defaults remain **per CLI home and tool**, not per server,
user, or device. Selecting a different server does not automatically clear them.
The desktop never opens the database or credentials itself.

## Requests and results

`get` is local-only and requires no credential:

```json
{"expected_home":"/absolute/cli/home","tool":"claude"}
```

Its result is:

```json
{"context":{"home":"/absolute/cli/home","server_url":null,"active_device_id":null},"tool":"claude","account_id":null}
```

Missing metadata means `account_id: null`. Reading does not create the home,
database, schema, login locks, or configuration locks, migrate a schema, refresh a
credential, or call the server. Existing SQLite WAL coordination may use SQLite's
normal sidecars; no metadata records are changed. Invalid existing metadata
returns `state_unavailable`.

`set` requires the exact reviewed snapshot and an exact full account ID:

```json
{"confirmed":true,"expected_context":{"home":"/absolute/cli/home","server_url":"https://server.example","active_device_id":"device-id"},"expected_account_id":null,"tool":"claude","account_id":"full-account-id"}
```

`clear` uses the same shape **without** `account_id`. Clear is entirely local and
requires no credential, including when logged out. Nullable context and previous
ID fields must be present explicitly, including when null. Unknown fields, wrong
types, missing fields, invalid tool/ID characters, and relative homes are rejected
before performing the operation. Tool/account/device identifiers are nonempty,
up to 128 ASCII alphanumeric, hyphen, or underscore characters. “Full ID” means
exact equality to the server account identity; desktop never resolves prefixes.
Human `account default set` retains its existing prefix resolution.

Both mutations return:

```json
{"operation_id":"request-id","context":{"home":"/absolute/cli/home","server_url":"https://server.example","active_device_id":"device-id"},"tool":"claude","previous_account_id":null,"account_id":"full-account-id","changed":true}
```

A clear receipt has `account_id: null`. Setting the existing default or clearing
an empty default returns `changed: false`; set still revalidates the exact account
and tool with the current device API. Only these explicit metadata fields are
projected; API account details and credential values never appear in the receipt.

## Concurrency and failure semantics

Mutations check the original context and previous ID, acquire the existing
per-home login lock, then check again. Set holds that guard through strict device
authentication and the account GET, verifies that the response ID and tool match,
and publishes only after validation. Human writes share this service and lock.
Final publication also holds `config-write.lock`, rechecks context, and uses an
immediate SQLite transaction to compare the exact previous default and replace or
delete it. No SQLite transaction/connection is held across HTTP awaits. The
configuration guard excludes cooperating `Config::save` writers. Arbitrary
external file/database replacement is not a supported concurrency mechanism.

`confirmed: false` returns `confirmation_required`. Changes to home, server, or
device return `configuration_changed`; a changed prior default returns
`default_changed`; an account ID/tool mismatch returns `account_mismatch`.
Other fixed codes are `invalid_params`, `configuration_unavailable`,
`state_unavailable`, `authentication_required`, `credential_unavailable`,
`permission_denied`, `rate_limited`, `server_unavailable`, `timeout`, `canceled`,
and `default_outcome_unknown`. Errors never include raw server/credential text.
API errors may carry the existing envelope's HTTP status and retryability hint;
that hint is not authorization to retry a mutation automatically.

Reads use the protocol's 75-second deadline; mutations use 120 seconds. Login
lock waits are bounded at 30 seconds; SQLite busy waits at three seconds.
Cancellation during asynchronous waits drops the operation and guards; the
outer desktop process termination limit remains the final boundary for native
credential calls. An interrupted mutation or lost receipt has an unknown outcome:
refresh the snapshot and obtain fresh explicit confirmation. No automatic retry,
rollback claim, or exactly-once request journal is provided. The operation ID is
receipt correlation, not an idempotency key. The server validates account access
at the GET instant; remote account status can change later.
