# Reviewed Mutagen environment recovery

This operation selects the managed local home and repairs an entire Mutagen daemon namespace.
It requires no Server URL, device, login, credential, selected project or SQLite database. It is
separate from project recovery: a project confirmation never authorizes a global daemon restart.
The selected home must already exist safely; local initialization remains a separate action.

## Desktop protocol

`mutagen.environment.preview` takes exactly `{"expected_home":"/absolute/selected/home"}`.
`mutagen.environment.apply` takes required `confirmed:true`, the same `expected_home`, and
`expected_fingerprint` from the reviewed plan. Both advertise `credential:"none"`; apply has
`effect:"write"` and `confirmation:"exact_request"`. The fingerprint binds the complete plan
without resubmitting a potentially large session inventory through the 64 KiB request boundary.

A plan contains:

- `home`, `data_directory`, nullable `namespace_fingerprint`, `daemon_state`
  (`running`, `stopped`, `unavailable`), nullable `running_fingerprint`, and `registration`
  (`unmanaged`, `external`, `unknown`).
- Nullable `previous` and required `desired` bindings, each with `home`, `ssh_directory` and
  `fingerprint`. These select the environment for the whole namespace, including other projects.
- `tools`, with `name`, `path`, and `fingerprint` for each inspected managed tool.
- `sessions`, covering both `sync` and `forward` sessions. Each has `kind`, `identifier`, `name`,
  `paused`, `source`, `destination`, and `configuration_fingerprint`. Each endpoint has `protocol`
  (`local`, `ssh`, `docker`), `user`, `host`, `port`, and `path`.
- `inventory_fingerprint`, nullable `marker_fingerprint`, complete-plan `fingerprint`,
  `repairable`, and nullable fixed `error_code`.

Digests are `sha256:` followed by 64 lowercase hexadecimal characters. Session configuration,
transport environment values, conflict contents, credentials and raw tool errors are not returned.
The inventory includes persisted session metadata when the daemon is stopped. Unreadable,
unsupported or inconsistent metadata cannot be treated as an empty namespace.

The read-only preview does not initialize the selected home, configuration, database or secrets,
create a mutation lock, run login or request HTTP. Apply validates the exact selected home and
fingerprint before acquiring its existing-home configuration lock. That lock uses descriptor-
relative no-follow opens and does not initialize unrelated directories. The backend owns a global
namespace lock, re-previews the full plan, and compares tools, home, namespace, marker, running
daemon generation, configuration and pause states before restarting anything. Configuration and
namespace locks serialize cooperating CLI processes; they do not make external Mutagen clients
or operating-system work transactional.

An apply receipt adds `operation_id`, `home` and `method:"mutagen.environment.apply"` to:
`plan`, `outcome` (`completed`, `partial`, `unknown`), ordered `stages`, nullable `environment`,
and nullable `error_code`. The original reviewed plan remains in every backend receipt.
Stages are `stop`, `start`, `verify`, `persist`; their states are `skipped`, `completed`, `failed`
or `unknown`. For an already stopped namespace, `stop` is skipped. Successful completion requires
the original full roster, immutable configuration and paused states to be verified after startup,
then publication of the namespace environment marker. Its returned environment is running and
records the selected binding. A failed or unknown operation never implies rollback or an
unaffected daemon. Timeouts and cancellation are not automatically replayed.

The version-2 namespace marker binds the selected home/tool environment and running daemon socket
generation. It prevents another home or restarted daemon from silently inheriting an old claim.
Legacy launcher sync and bounded pre-launch flush operations hold the same namespace lock for
the entire transient command. They no longer migrate the old per-home version-1 marker by
stopping a global daemon. Existing stopped/mismatched environments require this separate review;
a genuinely new empty namespace may be initialized by the normal project/launcher operation.
A detected external macOS launchd registration is blocked: this workflow does not stop or start an
unreviewed system service. The diagnostic explicitly identifies that current integration boundary.

After success, explicitly refresh the original project's sync/recovery status and review its next
action. Environment repair does not retry project operations, create replacement syncs, terminate
saved sessions, choose conflict winners or delete project files.

## Human command

```sh
agent-remote deps mutagen-environment
agent-remote deps mutagen-environment --repair
agent-remote --json deps mutagen-environment
```

The default command is read-only. `--repair` prints the whole namespace, including forwarding and
other-project sessions, and asks a separate yes/no question on an interactive terminal. There is
no `--yes` bypass. Noninteractive input is rejected for repair. JSON repair still requires the
same interactive review; prompts and reviews go to stderr, leaving one JSON document on stdout.

Human JSON output has `schema_version:1`. Its `kind` is `mutagen_environment_preview` with `plan`,
`mutagen_environment_receipt` with `home`, `method` and `receipt`, or
`mutagen_environment_error` with fixed `error_code` and `retryable:false`. Partial/unknown receipts
exit nonzero while retaining the complete receipt. Errors do not use the unrelated device-admission
JSON template. Preview success means the observation completed, not that `repairable` is true.
