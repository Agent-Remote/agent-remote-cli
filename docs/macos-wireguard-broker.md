# macOS WireGuard broker service

The desktop mutation path uses the root LaunchDaemon
`dev.agentremote.wireguard.broker`, installed from
`packaging/macos/dev.agentremote.wireguard.broker.plist`. The daemon binary
belongs at `/Library/PrivilegedHelperTools/dev.agentremote.wireguard.broker` and
the Unix socket belongs at `/var/run/agent-remote-wireguard.sock`. The plist,
binary and socket are checked for root ownership, regular-file/socket type,
link count and restrictive permissions before they are considered installed.
macOS releases use the community self-signing policy; this does not weaken the
service identity or caller checks.

Install a native community-built broker explicitly as root:

```sh
sudo BROKER_BINARY=/path/to/agent-remote-wireguard-broker \
  scripts/install-macos-wireguard-broker.sh
```

The installer refuses a missing, linked or non-executable binary and refuses to
replace linked destination paths. It installs root/wheel-owned files, reloads
the fixed LaunchDaemon and verifies `launchctl print`; it does not download,
sign, notarize or infer readiness from installation.

The client probes `launchctl` and sends a strict read-only `status` frame over
the socket. A socket or LaunchDaemon record by itself is not an authenticated
broker. The daemon binds the peer credentials, process start time and broker
instance digest before an execution permit can be issued. The current desktop
projection deliberately keeps execution `not_ready` until the per-operation
approval contract is complete, even when the status protocol responds.

Before accepting callers the daemon loads
`/var/db/agent-remote-wireguard/requests.log`; each request digest is synced
before `wg-quick` starts. Duplicate, malformed, unsafe, or full journal state
fails closed, including after a daemon restart.

Run the host-only acceptance entry point on the target Mac:

```sh
AGENT_REMOTE_CLI_BINARY=/path/to/agent-remote \
AGENT_REMOTE_WIREGUARD_EVIDENCE_DIR=/tmp/agent-remote-wireguard-native \
scripts/native-wireguard-broker-acceptance.sh
```

The resulting `evidence.json` distinguishes installation, LaunchDaemon
identity, status handshake and caller authentication from tunnel execution.
It records `up_receipt`, `down_receipt`, replay and restart as `not_run` until a
separate native acceptance uses a real reviewed configuration. Contract tests,
cross-builds and a community signature observation cannot replace this host
evidence.

The acceptance script can invoke the installer when
`AGENT_REMOTE_WIREGUARD_INSTALL=1` is set, but requires the separate
`AGENT_REMOTE_WIREGUARD_BROKER_BINARY`; a desktop CLI executable is never used
as a privileged service binary.
