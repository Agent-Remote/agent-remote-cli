#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/bin" ] && [ -d "$SCRIPT_DIR/dependencies" ]; then
  PACKAGE_DIR="$SCRIPT_DIR"
else
  PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
AGENT_REMOTE_HOME="${AGENT_REMOTE_HOME:-$HOME/.config/agent-remote}"
INSTALL_BIN_DIR="${INSTALL_BIN_DIR:-$HOME/.local/bin}"
COPY_LINKS="${COPY_LINKS:-0}"

usage() {
  cat <<'EOF'
Usage: install.sh [--home PATH] [--bin-dir PATH] [--copy-links] [--no-links]

Installs the packaged agent-remote binaries and managed dependencies.

Environment:
  AGENT_REMOTE_HOME   Destination for managed binaries and state.
  INSTALL_BIN_DIR     Directory for command links or wrapper copies.
  COPY_LINKS=1        Copy commands to INSTALL_BIN_DIR instead of symlinking.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --home)
      AGENT_REMOTE_HOME="${2:?--home requires a path}"
      shift 2
      ;;
    --bin-dir)
      INSTALL_BIN_DIR="${2:?--bin-dir requires a path}"
      shift 2
      ;;
    --copy-links)
      COPY_LINKS=1
      shift
      ;;
    --no-links)
      INSTALL_BIN_DIR=""
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_file() {
  if [ ! -f "$1" ]; then
    echo "missing packaged file: $1" >&2
    exit 1
  fi
}

for binary in agent-remote fclaude agent-remote-wireguard mutagen; do
  require_file "$PACKAGE_DIR/bin/$binary"
done
require_file "$PACKAGE_DIR/dependencies/manifest.json"

mkdir -p "$AGENT_REMOTE_HOME/bin" "$AGENT_REMOTE_HOME/dependencies"
install -m 0755 "$PACKAGE_DIR/bin/agent-remote" "$AGENT_REMOTE_HOME/bin/agent-remote"
install -m 0755 "$PACKAGE_DIR/bin/fclaude" "$AGENT_REMOTE_HOME/bin/fclaude"
install -m 0755 "$PACKAGE_DIR/bin/agent-remote-wireguard" "$AGENT_REMOTE_HOME/bin/agent-remote-wireguard"
install -m 0755 "$PACKAGE_DIR/bin/mutagen" "$AGENT_REMOTE_HOME/bin/mutagen"
install -m 0644 "$PACKAGE_DIR/dependencies/manifest.json" "$AGENT_REMOTE_HOME/dependencies/manifest.json"

if [ -n "$INSTALL_BIN_DIR" ]; then
  mkdir -p "$INSTALL_BIN_DIR"
  for binary in agent-remote fclaude agent-remote-wireguard; do
    target="$INSTALL_BIN_DIR/$binary"
    rm -f "$target"
    if [ "$COPY_LINKS" = "1" ]; then
      install -m 0755 "$AGENT_REMOTE_HOME/bin/$binary" "$target"
    else
      ln -s "$AGENT_REMOTE_HOME/bin/$binary" "$target"
    fi
  done
fi

cat <<EOF
agent-remote installed.
home: $AGENT_REMOTE_HOME
commands: ${INSTALL_BIN_DIR:-not linked}

Run:
  agent-remote init
EOF
