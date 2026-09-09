#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

target="x86_64-unknown-linux-gnu"
variant="tmux-3.5a-libevent-2.1.12-stable-ncurses-6.5-libmnl-1.0.5-wg-1.0.20210914-wg-go-0.0.20250522"
cache="$work/cache/v2/$target/$variant"
mkdir -p "$cache/bin" "$cache/sources" "$cache/licenses"
printf 'cached tool\n' > "$cache/bin/tmux"
printf 'cached tool\n' > "$cache/bin/wg"
printf 'cached tool\n' > "$cache/bin/wg-quick"
printf 'stale cli\n' > "$cache/bin/agent-remote"
printf 'cached source\n' > "$cache/sources/tmux.tar.gz"
printf 'cached license\n' > "$cache/licenses/tmux-COPYING"
touch "$cache/.complete"

mkdir -p "$work/output/bin" "$work/output/sources" "$work/output/licenses"
printf 'fresh cli\n' > "$work/output/bin/agent-remote"
MANAGED_TOOLS_CACHE_DIR="$work/cache" "$repo_root/scripts/build-managed-tools.sh" \
  "$target" "$work/output/bin" "$work/output/sources" "$work/output/licenses"

cmp "$cache/bin/tmux" "$work/output/bin/tmux"
cmp "$cache/sources/tmux.tar.gz" "$work/output/sources/tmux.tar.gz"
cmp "$cache/licenses/tmux-COPYING" "$work/output/licenses/tmux-COPYING"
cmp <(printf 'fresh cli\n') "$work/output/bin/agent-remote"

echo "managed tools cache tests passed"
