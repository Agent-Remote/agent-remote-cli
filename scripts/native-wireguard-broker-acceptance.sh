#!/usr/bin/env bash
# Verify the installed native WireGuard broker on the host that runs this file.
#
# This is intentionally a status-only gate by default.  It never treats a
# cross-built binary, a user process on the broker endpoint, a mock service or
# a present installer file as proof of a protected broker.  Tunnel up/down is
# a separate, destructive acceptance and must be performed by the desktop
# after a real reviewed plan.
set -euo pipefail

EVIDENCE_DIR="${AGENT_REMOTE_WIREGUARD_EVIDENCE_DIR:-${TMPDIR:-/tmp}/agent-remote-wireguard-native}"
CLI_BINARY="${AGENT_REMOTE_CLI_BINARY:-}"
BROKER_BINARY="${AGENT_REMOTE_WIREGUARD_BROKER_BINARY:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mkdir -p "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"

die() {
  printf 'native-wireguard-broker-acceptance: %s\n' "$1" >&2
  exit 2
}

command -v go >/dev/null 2>&1 || die "go is required to identify the host"
command -v python3 >/dev/null 2>&1 || die "python3 is required to parse the status response"
[[ -n "$CLI_BINARY" ]] || die "set AGENT_REMOTE_CLI_BINARY to the already-built native agent-remote binary"
[[ -f "$CLI_BINARY" && ! -L "$CLI_BINARY" && -x "$CLI_BINARY" ]] || die "AGENT_REMOTE_CLI_BINARY must be an executable regular file"
if [[ "${AGENT_REMOTE_WIREGUARD_INSTALL:-0}" == 1 ]]; then
  [[ -n "$BROKER_BINARY" && -f "$BROKER_BINARY" && ! -L "$BROKER_BINARY" && -x "$BROKER_BINARY" ]] || die "AGENT_REMOTE_WIREGUARD_BROKER_BINARY must be an executable regular file when installation is requested"
fi

goos="$(go env GOHOSTOS)"
goarch="$(go env GOHOSTARCH)"
case "$goos" in
  darwin|linux|windows) ;;
  *) die "unsupported host $goos; FreeBSD is not a release target" ;;
esac
case "$goarch" in
  amd64|arm64) ;;
  *) die "unsupported host architecture $goarch" ;;
esac

# A caller may have exported selectors for a release build.  They are not
# evidence about the process executing this script and are removed below.
if [[ -n "${GOOS:-}" || -n "${GOARCH:-}" ]]; then
  die "GOOS/GOARCH are set; run this acceptance on the target host without cross-build selectors"
fi

if [[ "${AGENT_REMOTE_WIREGUARD_INSTALL:-0}" == 1 ]]; then
  case "$goos" in
    linux) BROKER_BINARY="$BROKER_BINARY" "$SCRIPT_DIR/install-linux-wireguard-broker.sh" ;;
    darwin) BROKER_BINARY="$BROKER_BINARY" "$SCRIPT_DIR/install-macos-wireguard-broker.sh" ;;
    windows) die "use the PowerShell installer on Windows; POSIX acceptance cannot install an SCM service" ;;
  esac
fi

home="$(mktemp -d "${TMPDIR:-/tmp}/agent-remote-wireguard-home.XXXXXX")"
trap 'rm -rf "$home"' EXIT
request='{"protocol_version":1,"request_id":"native-wireguard-status","method":"wireguard.bridge.status","params":{"expected_home":"'"$home"'"}}'

status_file="$EVIDENCE_DIR/status-response.json"
set +e
printf '%s' "$request" | env -u GOOS -u GOARCH AGENT_REMOTE_HOME="$home" "$CLI_BINARY" --desktop-control >"$status_file" 2>"$EVIDENCE_DIR/status.stderr"
status_exit=$?
set -e

installation="failed"
service_identity="failed"
status_handshake="failed"
caller_authentication="failed"
install_entrypoint="unknown"
service_path="unknown"
journal_path="unknown"
journal_state="not_checked"

case "$goos" in
  linux)
    install_entrypoint="scripts/install-linux-wireguard-broker.sh (root, explicit)"
    service_path="/usr/libexec/agent-remote-wireguard-broker"
    journal_path="/var/lib/agent-remote-wireguard/requests.log"
    if [[ -f "$service_path" && ! -L "$service_path" && -x "$service_path" ]] && \
       [[ -f /etc/systemd/system/agent-remote-wireguard-broker.service && \
          -f /usr/share/dbus-1/system-services/dev.agentremote.WireGuardBroker.service && \
          -f /etc/dbus-1/system.d/dev.agentremote.wireguard.broker.conf ]]; then
      installation="passed"
      if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet agent-remote-wireguard-broker.service; then
        service_identity="passed"
      else
        service_identity="failed"
      fi
      if [[ -f "$journal_path" && ! -L "$journal_path" ]]; then journal_state="present"; fi
    fi
    ;;
  darwin)
    install_entrypoint="scripts/install-macos-wireguard-broker.sh (root, community self-signed binary)"
    service_path="/Library/PrivilegedHelperTools/dev.agentremote.wireguard.broker"
    journal_path="/var/db/agent-remote-wireguard/requests.log"
    if [[ -f "$service_path" && ! -L "$service_path" && -x "$service_path" ]] && \
       [[ -f /Library/LaunchDaemons/dev.agentremote.wireguard.broker.plist ]]; then
      installation="passed"
      if command -v launchctl >/dev/null 2>&1 && launchctl print system/dev.agentremote.wireguard.broker >/dev/null 2>&1; then
        service_identity="passed"
      else
        service_identity="failed"
      fi
      if [[ -f "$journal_path" && ! -L "$journal_path" ]]; then journal_state="present"; fi
    fi
    ;;
  windows)
    # The PowerShell entry point performs the equivalent SCM/ACL checks.  The
    # POSIX script cannot inspect Windows service identity safely.
    install_entrypoint="scripts/install.ps1 -InstallBroker (elevated SCM install)"
    service_path="%ProgramFiles%\\Agent-Remote\\bin\\agent-remote-wireguard-broker.exe"
    installation="unknown"
    service_identity="unknown"
    ;;
esac

if [[ "$status_exit" -eq 0 ]]; then
  parsed="$(python3 - "$status_file" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
    result = value.get("result")
    if value.get("type") != "result" or not isinstance(result, dict):
        raise ValueError("missing result")
    required = {"version", "home", "platform", "state", "installation", "approval", "protocol", "authentication", "execution"}
    if set(result) != required or result.get("version") != 1:
        raise ValueError("invalid bridge status shape")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
except Exception as exc:
    print(f"invalid status response: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
)" || true
  if [[ -n "$parsed" ]]; then
    printf '%s\n' "$parsed" > "$EVIDENCE_DIR/bridge-status.json"
    broker_installation="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["installation"])' "$EVIDENCE_DIR/bridge-status.json")"
    broker_state="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$EVIDENCE_DIR/bridge-status.json")"
    broker_protocol="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["protocol"])' "$EVIDENCE_DIR/bridge-status.json")"
    if [[ "$broker_installation" == installed && "$broker_state" != unsupported && "$broker_state" != unavailable && "$broker_protocol" != unsupported ]]; then
      status_handshake="passed"
    fi
    auth="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["authentication"])' "$EVIDENCE_DIR/bridge-status.json")"
    [[ "$status_handshake" == passed && "$auth" == authenticated ]] && caller_authentication="passed"
  fi
fi

up_receipt="not_run"
down_receipt="not_run"
replay_rejected="not_run"
service_restart="not_run"
execute_reason="status-only; reviewed tunnel up/down requires a real desktop plan and explicit destructive acceptance"
if [[ "${AGENT_REMOTE_WIREGUARD_NATIVE_EXECUTE:-0}" == 1 ]]; then
  up_receipt="not_run"
  down_receipt="not_run"
  execute_reason="requested but not implemented by this status-only entry point; refusing to claim execution"
fi

overall="status-only"
exit_code=0
if [[ "$installation" == failed || "$service_identity" == failed || "$status_handshake" != passed || "$caller_authentication" != passed ]]; then
  overall="failed"
  exit_code=1
fi
if [[ "$goos" == windows ]]; then
  # Windows currently has no authenticated client status handshake.  Keep the
  # result visibly incomplete even when the SCM installer is present.
  overall="failed"
  exit_code=1
fi
if [[ "${AGENT_REMOTE_WIREGUARD_NATIVE_EXECUTE:-0}" == 1 ]]; then
  overall="failed"
  exit_code=1
fi

python3 - "$EVIDENCE_DIR/evidence.json" <<PY
import json
from pathlib import Path
payload = {
  "schema_version": 1,
  "probe": "agent-remote-wireguard.native",
  "native": True,
  "cross_compilation": False,
  "runtime": {"goos": "$goos", "goarch": "$goarch"},
  "installation": {"status": "$installation", "entrypoint": "$install_entrypoint", "service_path": "$service_path"},
  "service_identity": {"status": "$service_identity"},
  "replay_journal": {"status": "$journal_state", "path": "$journal_path", "replay_rejected": "not_run", "service_restart": "not_run"},
  "status_handshake": {"status": "$status_handshake"},
  "caller_authentication": {"status": "$caller_authentication"},
  "up_receipt": {"status": "$up_receipt"},
  "down_receipt": {"status": "$down_receipt"},
  "replay_rejected": {"status": "$replay_rejected"},
  "service_restart": {"status": "$service_restart"},
  "execution": {"status": "$overall", "reason": "$execute_reason"},
}
Path(__import__('sys').argv[1]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
printf 'native-wireguard-broker-acceptance: overall=%s evidence=%s\n' "$overall" "$EVIDENCE_DIR"
exit "$exit_code"
