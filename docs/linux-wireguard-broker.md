# Linux WireGuard broker service

Desktop tunnel execution uses the root-owned `agent-remote-wireguard-broker`
system D-Bus service. The client connects only to
`dev.agentremote.WireGuardBroker` at `/dev/agentremote/WireGuardBroker` and
interface `dev.agentremote.WireGuardBroker1`. The service is installed with
`scripts/install-linux-wireguard-broker.sh`, which registers a systemd unit,
D-Bus activation file, D-Bus policy and the Polkit action
`dev.agentremote.wireguard.manage`.

The service accepts one bounded JSON byte array. It never receives or opens a
caller-selected path. It obtains the request sender, UID, PID and process start
time from the system bus and `/proc`, then calls Polkit's
`CheckAuthorization` with the exact `unix-process` subject, action, and no
interactive flag. A matching UID, root caller, `sudo`, or a user-session bus
does not authorize execution. The process-start check prevents PID reuse.

After authorization, the broker recomputes the Linux network-namespace scope
digest, validates the transferred bytes against the reviewed `ConfigBinding`,
observes the target through rtnetlink, and enforces `up` only for an absent
target or `down` only for a present target. The bytes are written to a root
owned `0600` file beneath `/run/agent-remote-wireguard`; only a fixed,
root-owned `wg-quick` path may execute, with a scrubbed environment and no
hooks accepted by the parser. The temporary file is removed after the command.
The target is observed again in the same process and namespace. A changed or
unexpected target returns an error and no receipt. Request IDs are consumed
once by the root-owned append-only
`/var/lib/agent-remote-wireguard/requests.log`; the reservation is synced
before execution and loaded before the system-bus service accepts calls. A
replay after process or host service restart fails closed.

The systemd unit bounds capabilities to `CAP_NET_ADMIN` and `CAP_NET_RAW`,
protects the host filesystem and home directories, and allows writes only to
the staging directory. The Polkit policy denies inactive and arbitrary callers
and permits an active user only after administrator authentication. Native
Linux acceptance still requires a host with system D-Bus, systemd, Polkit and
WireGuard; contract tests do not claim that host-level validation.

## Host acceptance entry point

Run `scripts/native-wireguard-broker-acceptance.sh` on the Linux host with an
already-built native `agent-remote` binary:

```sh
AGENT_REMOTE_CLI_BINARY=/path/to/agent-remote \
AGENT_REMOTE_WIREGUARD_EVIDENCE_DIR=/tmp/agent-remote-wireguard-native \
scripts/native-wireguard-broker-acceptance.sh
```

The script checks the fixed installation files, the active systemd service,
and then sends `wireguard.bridge.status` through the real desktop control
protocol. Its `evidence.json` records native runtime, service identity,
caller-scoped authorization and the status handshake. It rejects `GOOS`/
`GOARCH` cross-build selectors and never accepts a mock endpoint, fixture or
file-presence check as a broker identity.

To perform the installation as part of the same run, set
`AGENT_REMOTE_WIREGUARD_INSTALL=1` and provide the separate native
`AGENT_REMOTE_WIREGUARD_BROKER_BINARY`; the CLI control binary and privileged
broker binary are never conflated.

This entry point is deliberately status-only: `up_receipt`, `down_receipt`,
replay and restart remain `not_run` until a separate destructive acceptance
uses a real reviewed plan and configuration. `status-only` is review evidence,
not a completed release gate.
