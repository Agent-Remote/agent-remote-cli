# Desktop WireGuard configuration

`wireguard.config.plan` and `wireguard.config.apply` implement the configuration
portion of `agent-remote wireguard config`. Human CLI invocation and the optional
WireGuard step in `init` use the same Rust workflow. No operation starts a tunnel;
`check`, `status`, `up`, and `down` remain separate commands.

## Review and confirmation

`plan` is advertised with `effect: "read"`, `credential: "none"`. Its parameters are:

```json
{"expected_home":"/absolute/cli-home","output":null}
```

An omitted/null output selects `wireguard/agent-remote.conf` under the selected
CLI home. Desktop custom paths must be absolute; the human CLI also accepts relative
`--output` paths resolved against its current directory. Review is local only: it
reads bounded configuration and filesystem metadata, never credentials, and creates
no files, directories, locks, keys or network requests.

The result is an exact plan:

```json
{
  "plan_version":1,
  "home":"/absolute/cli-home",
  "context":{"server_url":"https://agent.example.com","active_device_id":"device-id"},
  "output":{
    "path":"/absolute/cli-home/wireguard/agent-remote.conf",
    "action":"create",
    "anchor_path":"/absolute/cli-home/wireguard",
    "anchor_identity":"<64 lowercase hexadecimal characters>",
    "missing_directories":[],
    "target_identity":null
  }
}
```

`target_identity` is required and null for `create`; it is a 64-character lowercase
hexadecimal fingerprint for `replace`. Identity strings hash native file identity
and, for existing targets, modification metadata; they contain no configuration
contents. The directory identity does not change just because another unrelated
file is added. `missing_directories` contains simple directory names below the
nearest existing anchor. The output is the resolved path reviewed by the user;
fixed macOS aliases `/var`, `/tmp`, and `/etc` may resolve to their system locations.

`apply` is advertised with `effect: "write"`, `credential: "device"`, and
`confirmation: "exact_request"`. Send `confirmed: true` and `expected_plan` containing
the complete unchanged plan. The review must disclose the Server, device, output,
create/replace action, potential local key creation, and registration/update of the
device public key. Changing a selection invalidates that confirmation.

The CLI checks home, context and the entire output plan before mutation and again
after acquiring its locks. It rechecks context/output after credential preparation
and before publication. It never silently replans a confirmed request. Rejected
confirmation and stale plans do not generate a key or enroll a peer.

## Credentials and publication

Login publication is serialized per CLI home. A user-level lock additionally
serializes WireGuard work for the same Server/device across CLI homes; tests can
select an isolated absolute root with `AGENT_REMOTE_WIREGUARD_LOCK_ROOT`. A separate
lock in the selected parent serializes cooperating publishers across homes.

Strict credential reads distinguish absence from denied, inaccessible, invalid and
timed-out storage. A failed system lookup cannot authorize fallback or new key
generation. An explicitly selected file backend only reads that backend. Existing
invalid keys fail without replacement. The local private key is saved before one
enrollment request; only its derived public key is sent to the Server. Neither
private keys, device tokens nor rendered configuration enter JSON, arguments or logs.

Before an existing peer is changed, the CLI reads the sanitized configuration and
freezes `peer_id`, `peer_public_key`, and monotonic `peer_version`. The enrollment
request carries all three as `expected_*` fields; the Server rejects
`WIREGUARD_PEER_CHANGED` when any identity or version has drifted. A first
enrollment may omit the expectations only when the Server has no active peer.
Successful enrollment returns `device_id`, `peer_id`, `peer_version`, and the
interface address. The CLI validates that receipt against the subsequent
configuration read before rendering. Private keys are never returned.

Output preparation and publication use opened directory handles, no-follow access,
and native file identities. Links, junctions, special files and hardlinked targets
are rejected. New files are private before secret bytes are written: 0600 on Unix;
Windows grants the current user access and retains LocalSystem read access. Existing
files are replaced atomically from a same-directory staged file. New destinations
use a non-overwriting publication. File data is synchronized before publication;
Unix parent directories are synchronized afterward. An error after publication can
leave a changed file even when durability confirmation is incomplete.

API response streaming is bounded to 1 MiB. Configuration validation checks the
expected device and enrolled address, at most 1024 peers, 16 DNS addresses and 256
allowed addresses per peer. IP/CIDR, endpoint, canonical public key and low-order key
validation precede rendering. Multiline/control-containing fields are rejected and
node comments are not rendered from Server text. Rendered output is also limited
to 1 MiB; no Server-provided shell/configuration directives are copied.

Cooperating CLI/desktop processes share locks. The workflow does not claim an atomic
compare-and-swap against a hostile same-user process replacing paths during the last
verification/rename interval. A plan is a filesystem snapshot, not an authorization
token or proof of remote permissions.

## Results and uncertainty

A result contains `operation_id` equal to the request ID, `home`, `context`,
`output_path`, `complete`, `key_state`, `enrollment`, `publication`, `code`,
nullable `peer_count`, and sanitized `peer_id`/`peer_version` once enrollment is
confirmed. A partial result still exits 0; callers must inspect its stages.
Ordinary human CLI invocation exits nonzero for an incomplete workflow.

Key states are `not_checked`, `reused`, `created`, `unknown`; enrollment states are
`not_attempted`, `rejected`, `confirmed`, `unknown`; publication states in receipts
are `not_attempted`, `published`, `failed`. The following combinations are allowed:

| Code | Key | Enrollment | Publication | Peer count |
| --- | --- | --- | --- | --- |
| `none` | reused/created | confirmed | published | 0–1024 |
| `credential_unavailable`, `wireguard_key_invalid` | not_checked | not_attempted | not_attempted | null |
| `wireguard_key_store_incomplete` | unknown | not_attempted | not_attempted | null |
| `wireguard_enrollment_rejected` | reused/created | rejected | not_attempted | null |
| `wireguard_enrollment_unknown` | reused/created | unknown | not_attempted | null |
| `wireguard_config_unavailable`, `wireguard_config_invalid` | reused/created | confirmed | not_attempted | null |
| `wireguard_context_changed` | reused/created | not_attempted/confirmed | not_attempted | null |
| `output_changed` before enroll | reused/created | not_attempted | not_attempted | null |
| `output_changed` before publication | reused/created | confirmed | not_attempted | 0–1024 |
| `wireguard_publication_incomplete` | reused/created | confirmed | failed/published | 0–1024 |

`complete` is true only for `code: "none"`. A `published` partial result means that
the destination changed but publication cleanup/durability confirmation failed; it
does not mean that the original file was retained.

Protocol preflight errors include `invalid_params`, `confirmation_required`,
`configuration_changed`, `configuration_unavailable`, `authentication_required`,
`output_invalid`, `output_unavailable`, `output_changed`, and `operation_busy`.
After valid confirmation, output preparation may have created directories/lock
files before a local preparation error; no rollback is claimed.

Only explicit enrollment 4xx responses establish rejection. Transport failure,
5xx, malformed successful responses and mismatched receipt identities leave
enrollment unknown, stop the workflow, and never replay. A stale peer identity is
reported as a rejected compare-and-swap; retain the local key and require a fresh
explicit confirmation before another attempt.

Apply has a 120-second CLI budget and a 150-second desktop waiting budget. All mutation
errors have `retryable: false`. Timeout or a lost process/receipt is
`wireguard_outcome_unknown`, with no inferred rollback. On Unix the machine wrapper
handles SIGTERM, signals cancellation and allows up to one second for async credential
helpers to stop before dropping the workflow. Linux helpers own kill-on-drop process
groups. Native credential calls and secret-bearing file writes retain their locks
through their synchronous boundary; a native call can require outer process termination,
which likewise leaves outcome unknown. SIGKILL cannot run Rust cleanup.

The implementation targets Windows, macOS and Linux. Native Windows ACL/replacement
and Linux credential-process behavior require their platform contract runs; a macOS
test run or cross-compilation does not substitute for that evidence. Tests are isolated
under `tests/` and never use developer credentials.
