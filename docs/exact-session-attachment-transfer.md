# Exact session file and image transfer contract

This document defines the transfer contract reserved for `sessions.attach` v1.
It does not enable transfer by itself. Until all three components advertise the
same capability, exact sessions remain text-only and the CLI must not start the
legacy attachment receiver.

## Admission and identity

The transfer channel is opened only after the exact session authorization has
completed successfully. The CLI starts a dedicated, fixed gateway command with
the reviewed session UUID and expected device UUID. It never accepts an account
path, shell command, or credential from the desktop.

The Node gateway obtains the actual device and SSH key identities from the
forced-command connection and asks the Server to verify this tuple before
creating a transfer lease:

```text
node_id, session_id, device_id, ssh_key_id, lease_id
```

The Server must verify the authenticated device, active key, session owner,
running Claude session, Node capability and runtime account binding under the
same lifecycle checks as exact terminal attach. The response may contain an
opaque runtime scope and expiry, but never a client-selected account path or a
general filesystem token. A missing, old or incompatible capability is a hard
failure; there is no fallback to ordinary `fclaude attach` or the legacy
receiver.

The Node first sends a strict `lease_offer` containing the complete verified
identity, expiry and limits. The client checks it against the reviewed session
and device, then sends the `open` frame with the Node-generated lease ID. Every
later frame repeats the session, expected device and lease IDs. The Node rejects
a changed value and closes the channel. UUIDs are canonical, non-zero and
lower-case. The lease is single-purpose and bounded in time and bytes. The
Node-to-Server admission request calls the same device `device_id`;
`expected_device_id` is the client frame name after that identity has been
verified.

## Frames

The v1 JSON header is strict (`deny_unknown_fields` semantics). Binary payload
bytes follow an `upload` header and are counted before the receiver writes them.
The client sends only a leaf name; path separators, traversal components,
control characters, links, special files and archives are rejected.

```json
{"version":1,"operation":"lease_offer","node_id":"<uuid>","session_id":"<uuid>","expected_device_id":"<uuid>","ssh_key_id":"<uuid>","lease_id":"<uuid>","expires_at":"<rfc3339>","max_bytes":268435456,"max_entries":32}
{"version":1,"operation":"open","session_id":"<uuid>","expected_device_id":"<uuid>","lease_id":"<uuid>"}
{"version":1,"operation":"upload","session_id":"<uuid>","expected_device_id":"<uuid>","lease_id":"<uuid>","batch_id":"<uuid>","kind":"file|image","name":"screenshot.png","size":1234,"sha256":"<64 lowercase hex>"}
{"version":1,"operation":"cleanup","session_id":"<uuid>","expected_device_id":"<uuid>","lease_id":"<uuid>"}
```

Each upload is acknowledged with `upload_ack`, its batch ID and the derived
remote path. The path is produced by the Node from its trusted session account;
the client can only validate and insert that returned path.

The initial limits are 32 entries per lease, 256 MiB per upload batch, a 255
byte leaf name and a 64 KiB JSON header. Images are accepted only as declared
file bytes; the receiver does not interpret or transcode image content.

## Cleanup and uncertainty

Cleanup is scoped to the exact `(session, device, SSH key, lease)` identity and
must never remove another live terminal's lease. The Node returns a strict
receipt and the CLI stores its public fields in the private
`$HOME/attachments/exact-pending/<lease>.json` journal:

```json
{"version":1,"operation":"cleanup_receipt","session_id":"<uuid>","expected_device_id":"<uuid>","lease_id":"<uuid>","status":"cleaned|pending|unknown|rejected","removed_batches":2,"receipt_id":"<uuid>"}
```

Only `cleaned` is completion evidence. `pending`, `unknown` and a lost response
retain the receipt for an explicit later recovery; the CLI must not silently
retry with a new lease. `rejected` is a terminal failure for that lease. EOF,
SIGTERM, SSH loss and gateway shutdown trigger the same scoped cleanup attempt,
but an interrupted local process cannot claim remote deletion.

The Server/Node acceptance matrix must cover wrong device, wrong key, wrong
session, changed lease, replayed batch, expired lease, path traversal, links,
size/checksum mismatch, concurrent leases, lost cleanup response and cleanup
after session deletion. The existing legacy attachment tests remain valid for
ordinary non-exact CLI attachment and are not evidence for this contract.

## Current implementation state

The CLI opens this channel from exact `fclaude attach` sessions through a
dedicated non-PTY SSH connection. It never invokes the legacy account receiver
for an exact session. A private pending receipt is written after admission and
is deleted only after a `cleaned` receipt; pending, unknown or lost responses
remain visible for explicit recovery. Server admission/cleanup routes and the
Node gateway advertise the same fail-closed capability. The ignored
`tests/exact_attachment_live_contract.rs` test is the opt-in real
Server/Node/SSH forced-command acceptance entry used by the desktop
`scripts/exact-attachment-acceptance.sh --live` wrapper; contract fixtures do
not count as real-link evidence, and the desktop remains text-only until that
test passes in a disposable environment.
