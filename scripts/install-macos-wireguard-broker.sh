#!/bin/sh
# Install the macOS protected WireGuard broker as a root LaunchDaemon.
# This script does not sign, notarize or download a binary.  The caller must
# provide the native community-built broker explicitly.
set -eu

[ "$(uname -s)" = Darwin ] || { echo "install-macos-wireguard-broker.sh must run on macOS" >&2; exit 78; }
[ "$(id -u)" -eq 0 ] || { echo "install-macos-wireguard-broker.sh must run as root" >&2; exit 77; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
binary=${BROKER_BINARY:-"$root_dir/target/release/agent-remote-wireguard-broker"}
plist_source=${BROKER_PLIST:-"$root_dir/packaging/macos/dev.agentremote.wireguard.broker.plist"}
binary_target=/Library/PrivilegedHelperTools/dev.agentremote.wireguard.broker
plist_target=/Library/LaunchDaemons/dev.agentremote.wireguard.broker.plist

[ -f "$binary" ] && [ ! -L "$binary" ] && [ -x "$binary" ] || {
  echo "missing native executable broker binary: $binary" >&2
  exit 1
}
[ -f "$plist_source" ] && [ ! -L "$plist_source" ] || {
  echo "missing broker LaunchDaemon plist: $plist_source" >&2
  exit 1
}

for target in "$binary_target" "$plist_target"; do
  if [ -L "$target" ]; then
    echo "refusing to replace symlink: $target" >&2
    exit 1
  fi
done

install -d -o root -g wheel -m 0755 /Library/PrivilegedHelperTools /Library/LaunchDaemons
install -d -o root -g wheel -m 0700 /var/db/agent-remote-wireguard
tmp_binary=$(mktemp "/Library/PrivilegedHelperTools/.agent-remote-wireguard-broker.XXXXXX")
tmp_plist=$(mktemp "/Library/LaunchDaemons/.dev.agentremote.wireguard.broker.XXXXXX")
cleanup() { rm -f "$tmp_binary" "$tmp_plist"; }
trap cleanup EXIT HUP INT TERM
install -o root -g wheel -m 0755 "$binary" "$tmp_binary"
install -o root -g wheel -m 0644 "$plist_source" "$tmp_plist"
mv -f "$tmp_binary" "$binary_target"
mv -f "$tmp_plist" "$plist_target"

if command -v launchctl >/dev/null 2>&1; then
  launchctl bootout system/dev.agentremote.wireguard.broker >/dev/null 2>&1 || true
  launchctl bootstrap system "$plist_target"
  launchctl enable system/dev.agentremote.wireguard.broker
  launchctl print system/dev.agentremote.wireguard.broker >/dev/null
else
  echo "launchctl is required to register the broker" >&2
  exit 1
fi

echo "installed macOS Agent Remote WireGuard broker LaunchDaemon"
echo "community self-signing remains a separate release-build step"
