# WireGuard checks and runtime observations

`wireguard.check` and `wireguard.status` are advertised with `effect: "read"` and
`credential: "none"`. Neither requires login nor creates CLI home, metadata,
credential, lock or tunnel state. Their `expected_home` must equal the selected
absolute CLI home. Every result field below is present; nullable fields use JSON
null. These are snapshots, not authorization to execute a tunnel operation.

## Configuration check

Request: `{"expected_home":"/absolute/home","config":null}`. Null or omitted config
selects `wireguard/agent-remote.conf` under home; desktop custom config must be
absolute. Human CLI and helper checks additionally accept relative paths and resolve
them against their current directory.

The result contains `home`, `platform`, `elevation`, `config` and `tools`.
`config` contains `path`, `state`, `addresses`, `dns`, `mtu`, `peer_count` and
`unsupported_directives`. Its path retains the lexical absolute input spelling;
internal safe traversal may resolve fixed macOS aliases such as `/var`.

Configuration states are `ready`, `missing`, `unreadable`, `unsafe_path`,
`insecure_permissions`, `invalid`, and `unsupported`. Only ready/unsupported return
parsed addresses/DNS and peer count. All other states return empty arrays and null
MTU/peer count. MTU is nullable, otherwise 576–65535; there are at most 64 interface
addresses, 16 DNS IPs, 1024 peers and 256 AllowedIPs per peer.

The parser accepts one Interface followed by Peer sections, blank lines, comments
and CRLF. Interface fields are PrivateKey, Address, DNS, MTU, ListenPort and FwMark;
Peer fields are PublicKey, PresharedKey, Endpoint, AllowedIPs and PersistentKeepalive.
PrivateKey and at least one Address are required; each peer requires a PublicKey and
AllowedIPs. Address, DNS and AllowedIPs may repeat within their aggregate bounds;
duplicate single-valued fields, duplicate peer keys and unknown fields are invalid.
Keys must be canonical Base64 encoding of 32 bytes; public peers additionally reject
low-order keys. DNS supports IP addresses only, not search domains.

Interface directives PreUp, PostUp, PreDown, PostDown, SaveConfig and Table produce
`unsupported`, listing only their fixed names in that order. Values never leave Rust
and are never executed. Repeated hooks are allowed; duplicate SaveConfig/Table are
invalid. This supported subset is not a complete wg-quick configuration parser.

Reading is bounded to 1 MiB. Directory traversal and the file leaf use no-follow
handles; links, reparse points, hardlinks, FIFO and nonregular files are rejected.
Unsafe file permissions are rejected before content is read. Unix requires current
ownership and no group/other access. Windows also accepts the LocalSystem read
grant used by generated WireGuard files, without relaxing credential-file ACL rules.
Private keys, PSKs, configuration text and directive values never enter results.

`tools` is ordered as `wg` followed by `wireguard` on Windows or `wg-quick` elsewhere.
Each item has `name`, `state` and nullable `path`. States are `available`, `missing`
and `not_executable`; only missing has a null path. Discovery executes no version
commands. An unusable explicit tool override does not silently fall through to
another program.

Ordinary `agent-remote wireguard check` and `agent-remote-wireguard check` use this
same service. Both accept `--dry-run` and never run a tunnel command. Human checks
exit nonzero unless configuration is ready and the platform tunnel tool is available.
The stronger syntax, file-type and permission checks intentionally replace the old
helper's existence-only check.

## Runtime status

Request: `{"expected_home":"/absolute/home"}`. The result contains `home`, `platform`,
`elevation`, `tool`, `state`, and `interfaces`. Tool discovery is shared with check.
The fixed command is `wg show all dump`, with a 10-second budget, stdout limited to
1 MiB and stderr limited to 16 KiB. No sudo/UAC retry, API request or configuration
file read occurs. All raw output is discarded at the Rust parsing boundary.

States are `observed`, `tool_missing`, `tool_not_executable`, `query_failed`,
`timed_out`, `output_too_large` and `invalid_output`. Non-observed results have empty
interfaces; an observed empty array means no interface was observed in that query.
A failed query does not mean no active tunnel, and stderr wording does not establish
permission status.

Each interface has name, nullable public_key, listen_port, fwmark and peers. Each peer
has public_key, nullable endpoint, allowed_ips, latest_handshake, received_bytes,
sent_bytes and persistent_keepalive. Public keys reject all-zero values. Private keys
and PSKs are checked for canonical 32-byte encoding and discarded.
There are at most 64 unique interfaces, 1024 total peers, 4096 total AllowedIPs and
256 AllowedIPs per peer. Duplicate peers per interface, malformed fields, orphaned
peer lines, incomplete final lines and over-limit output reject the whole observation.
Handshake seconds are 0–253402300799; zero denotes no handshake. Counters are uint64,
ports/keepalive uint16, fwmark uint32; off is normalized to zero.

Cancellation returns the standard `canceled` error. Unix SIGTERM signals cancellation
and allows bounded cleanup of the probe's private process group. Windows probes use
a Job Object to contain and terminate descendants. Killing the CLI abruptly cannot
claim remote or operating-system rollback. No raw stdout/stderr appears in errors.

`platform` is windows/macos/linux; `elevation` is elevated/standard/unknown and only
describes the current process. It does not prove tunnel access or network capability.
The ordinary human `wireguard status` helper retains its existing presentation and
sudo/UAC behavior. Desktop status uses the separate non-elevating shared API.

Tests and fixtures reside under root `tests/`. Native platform runtime evidence is
required for permissions, process cleanup and tool invocation; compilation alone does
not establish platform acceptance. Read-only check/status do not provide mutation evidence or authorize start/stop;
the implemented tunnel plan/apply contract still requires native platform acceptance.
