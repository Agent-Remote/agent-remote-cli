#!/bin/sh
set -eu

prefix=${PREFIX:-/usr}
libexec_dir=${LIBEXEC_DIR:-"$prefix/libexec"}
systemd_dir=${SYSTEMD_SYSTEM_DIR:-/etc/systemd/system}
dbus_service_dir=${DBUS_SYSTEM_SERVICE_DIR:-/usr/share/dbus-1/system-services}
dbus_conf_dir=${DBUS_SYSTEM_CONF_DIR:-/etc/dbus-1/system.d}
polkit_dir=${POLKIT_ACTION_DIR:-/usr/share/polkit-1/actions}

if [ "$(id -u)" -ne 0 ]; then
  echo "install-linux-wireguard-broker.sh must run as root" >&2
  exit 77
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
binary=${BROKER_BINARY:-"$root_dir/target/release/agent-remote-wireguard-broker"}
[ -f "$binary" ] && [ ! -L "$binary" ] && [ -x "$binary" ] || {
  echo "missing native executable broker binary: $binary" >&2
  exit 1
}

for target in \
  "$libexec_dir/agent-remote-wireguard-broker" \
  "$systemd_dir/agent-remote-wireguard-broker.service" \
  "$dbus_service_dir/dev.agentremote.WireGuardBroker.service" \
  "$dbus_conf_dir/dev.agentremote.wireguard.broker.conf" \
  "$polkit_dir/dev.agentremote.wireguard.manage.policy"; do
  if [ -L "$target" ]; then
    echo "refusing to replace symlink: $target" >&2
    exit 1
  fi
done

install -d -o root -g root -m 0755 "$libexec_dir" "$systemd_dir" \
  "$dbus_service_dir" "$dbus_conf_dir" "$polkit_dir"
install -o root -g root -m 0755 "$binary" "$libexec_dir/agent-remote-wireguard-broker"
install -o root -g root -m 0644 "$script_dir/../packaging/linux/agent-remote-wireguard-broker.service" \
  "$systemd_dir/agent-remote-wireguard-broker.service"
install -o root -g root -m 0644 "$script_dir/../packaging/linux/dev.agentremote.WireGuardBroker.service" \
  "$dbus_service_dir/dev.agentremote.WireGuardBroker.service"
install -o root -g root -m 0644 "$script_dir/../packaging/linux/dev.agentremote.wireguard.broker.conf" \
  "$dbus_conf_dir/dev.agentremote.wireguard.broker.conf"
install -o root -g root -m 0644 "$script_dir/../packaging/linux/dev.agentremote.wireguard.manage.policy" \
  "$polkit_dir/dev.agentremote.wireguard.manage.policy"

install -d -o root -g root -m 0700 /run/agent-remote-wireguard
install -d -o root -g root -m 0700 /var/lib/agent-remote-wireguard
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now agent-remote-wireguard-broker.service
fi
if command -v dbus-send >/dev/null 2>&1; then
  dbus-send --system --dest=org.freedesktop.DBus --type=method_call \
    /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig >/dev/null 2>&1 || true
fi
echo "installed agent-remote Linux WireGuard broker"
