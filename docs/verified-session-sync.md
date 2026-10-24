# Verified synchronization flush foundation

This slice adds a Rust library operation for flushing one already prepared
synchronization relationship. It does not add a desktop-control method, terminal
capability, session-creation POST or UI flow, and does not change ordinary
`fclaude` launch behavior. This is an internal verified-flush operation; it is
intentionally not a session-creation API or durable authority to create a session.
The separate caller-key creation contract records its own sync target and receipt.

`session_sync::flush_verified` accepts the existing `AppPaths`, reviewed
`account_defaults::Context`, reviewed `sync_operations::Target`, and cancellation
flag. The target requires a canonical local directory, its original project key,
workspace UUID, sync UUID and existing target fingerprint. Missing synchronization
is an error, never consent to create a replacement.

The successful observation returns the original context and target, actual
Mutagen identifier, and bounded public observations before and after flush. It
contains no credentials, filenames from daemon diagnostics, clipboard data or
remote commands. Errors expose a fixed code and `flush_may_have_run`: after a
flush attempt, cancellation, timeout or failed verification cannot imply rollback.
`flush_may_have_run=false` describes only the transient flush command; it does not
assert that credential renewal had no effect. This applies to every error,
including cancellation and the outer `sync_flush_timeout`: a renewed token may
already have been published before the operation stopped. Errors retain that
warning rather than describing the entire operation as having no effects.

The lock order is the existing home login lock, existing configuration publication
lock, then existing Mutagen namespace lock. The caller's strict configuration and
canonical directory are compared before credentials are read or renewed, and
again after acquiring the locks. SQLite snapshots close before HTTP awaits. The
same Server/device credential and immutable target are used throughout; no current
account selection, remote session selection or metadata replacement takes place.

Before acquiring the login lock, the home, base directories, database and valid
device refresh record must already exist. Missing setup fails with
`sync_setup_required`; initialize/login separately. The existing-only credential
reader never initializes SQLite schema or creates a refresh key. If renewal is
due, credential publication follows the normal strict storage rules, then refresh
metadata is updated only by comparing the original database identity and key
value. Missing/changed keys or an unconfirmed commit fail; a published credential
cannot be described as rolled back. The ordinary loader remains unchanged.

The operation reuses the shared synchronization target validation/fingerprint and
checked Server GET. Both Server observations must match the complete target;
status must be active or healthy with conflict status `none`. The shared local
workspace/sync mappings, directory identity and configuration are rechecked before
returning success. No control-plane mutation is submitted, apart from necessary
device credential renewal under the existing login/configuration locks.

The namespace must already be running and bound to the same home, tools, SSH
directory and environment marker. The guard uses existing-only inspection and
locking, never environment preparation. Missing, stale, stopped, mismatched or
unobservable namespaces require separate review. Flush does not start a daemon,
repair or migrate it, rewrite a marker, ensure synchronization, resume a paused
session or clean an old mapping.

Mutagen's public structured model selects exactly one matching configuration and
its real identifier. Before and after the flush, the selected session must be
unpaused, available, have a known successful healthy cycle and no observed
conflicts; identity or configuration drift is an error. Git locks are checked
before and after. Only this fixed argument shape is executed:

```text
mutagen sync flush -- <verified-identifier>
```

The existing contained subprocess runner disables daemon autostart, bounds output
and execution, and kills its owned Unix process group or Windows job on timeout
or dropped work. Flush itself is limited to 30 seconds; the full operation has a
90-second deadline and observes caller cancellation. Canceling this transient client does not stop the persistent
daemon or claim to undo a synchronization cycle it already accepted. No failure
in this foundation can create a Claude session.

The existing strict credential-store boundary still applies: non-cancellable
native Keychain/Windows credential calls can delay observation of cancellation or
the async deadline until the OS returns. Their guards remain held; an owning
process's external termination limit is the final boundary and has unknown
credential outcome. The foundation adds no new process owner or GUI launcher.

Tests remain under repository `tests/` and cover changed context/target, stopped
or mismatched environment, ambiguous names, identifier replacement, pause/conflict
or unknown observations, Git locks, exact flush arguments, timeout/cancellation,
child cleanup and absence of automatic repair or session creation.
The subprocess contract exercises cancellation and the same outer deadline path
with a shortened test deadline; Windows job containment reuses the existing
contained runner and still requires native Windows CI evidence.
