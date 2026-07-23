#!/usr/bin/env bash
set -euo pipefail

default_version() {
  sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1
}

VERSION="${VERSION:-$(default_version)}"
OUT_DIR="${OUT_DIR:-dist}"
TARGETS="${TARGETS:-x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin}"
MUTAGEN_VERSION="${MUTAGEN_VERSION:-0.18.1}"
TMUX_VERSION="${TMUX_VERSION:-3.5a}"
WIREGUARD_TOOLS_VERSION="${WIREGUARD_TOOLS_VERSION:-1.0.20210914}"
WIREGUARD_GO_VERSION="${WIREGUARD_GO_VERSION:-0.0.20250522}"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

mutagen_asset() {
  case "$1" in
    x86_64-unknown-linux-gnu) echo "mutagen_linux_amd64_v${MUTAGEN_VERSION}.tar.gz" ;;
    aarch64-unknown-linux-gnu) echo "mutagen_linux_arm64_v${MUTAGEN_VERSION}.tar.gz" ;;
    x86_64-apple-darwin) echo "mutagen_darwin_amd64_v${MUTAGEN_VERSION}.tar.gz" ;;
    aarch64-apple-darwin) echo "mutagen_darwin_arm64_v${MUTAGEN_VERSION}.tar.gz" ;;
    *) echo "unsupported target $1" >&2; exit 1 ;;
  esac
}

download_mutagen() {
  local target="$1"
  local dest="$2"
  local asset
  asset="$(mutagen_asset "$target")"
  local url="https://github.com/mutagen-io/mutagen/releases/download/v${MUTAGEN_VERSION}/${asset}"
  local tmp
  tmp="$(mktemp -d)"
  curl --fail --show-error --location \
    --retry 5 --retry-all-errors --retry-delay 5 \
    "$url" -o "$tmp/mutagen.tar.gz"
  tar -xzf "$tmp/mutagen.tar.gz" -C "$tmp"
  install -m 0755 "$tmp/mutagen" "$dest"
  install -m 0644 "$tmp/mutagen-agents.tar.gz" "$(dirname "$dest")/mutagen-agents.tar.gz"
  rm -rf "$tmp"
}

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

for target in $TARGETS; do
  AGENT_REMOTE_VERSION="$VERSION" cargo build --release --target "$target"
  package="agent-remote-cli-${VERSION}-${target}"
  work="$OUT_DIR/$package"
  mkdir -p "$work/bin" "$work/dependencies/sources" "$work/dependencies/licenses"
  install -m 0755 "target/$target/release/agent-remote" "$work/bin/agent-remote"
  install -m 0755 "target/$target/release/fclaude" "$work/bin/fclaude"
  install -m 0755 "target/$target/release/agent-remote-wireguard" "$work/bin/agent-remote-wireguard"
  install -m 0755 scripts/mutagen-scp "$work/bin/scp"
  download_mutagen "$target" "$work/bin/mutagen"
  scripts/build-managed-tools.sh "$target" "$work/bin" "$work/dependencies/sources" "$work/dependencies/licenses"
  cp README.md README.zh-CN.md CHANGELOG.md LICENSE THIRD_PARTY_NOTICES.md "$work/"
  install -m 0755 scripts/install.sh "$work/install.sh"
  cat > "$work/dependencies/manifest.json" <<EOF
{
  "schema_version": 1,
  "dependencies": [
    {
      "name": "mutagen",
      "required_version": "v${MUTAGEN_VERSION}",
      "binary": "bin/mutagen",
      "source": "https://github.com/mutagen-io/mutagen/releases/download/v${MUTAGEN_VERSION}",
      "license": "MIT, with SSPL notice required for official v0.17+ builds",
      "license_notice": "See THIRD_PARTY_NOTICES.md and the exact packaged Mutagen artifact notice"
    },
    {
      "name": "wireguard-helper",
      "required_version": "${VERSION}",
      "binary": "bin/agent-remote-wireguard",
      "source": "agent-remote-cli release artifact",
      "license": "GPL-3.0-only",
      "license_notice": "See THIRD_PARTY_NOTICES.md"
    },
    {
      "name": "tmux",
      "required_version": "${TMUX_VERSION}",
      "binary": "bin/tmux",
      "source": "dependencies/sources/tmux-${TMUX_VERSION}.tar.gz",
      "license": "ISC",
      "license_notice": "See dependencies/licenses/tmux-COPYING",
      "binary_sha256": "$(sha256_file "$work/bin/tmux")"
    },
    {
      "name": "wireguard-tools",
      "required_version": "${WIREGUARD_TOOLS_VERSION}",
      "binary": "bin/wg",
      "source": "dependencies/sources/wireguard-tools-${WIREGUARD_TOOLS_VERSION}.tar.xz",
      "license": "GPL-2.0-only",
      "license_notice": "See dependencies/licenses/wireguard-tools-COPYING",
      "binary_sha256": "$(sha256_file "$work/bin/wg")"
    }
  ]
}
EOF
  python3 - "$work/dependencies/manifest.json" "$work/dependencies/sources" "$work/bin/wg-quick" "$work/bin/mutagen-agents.tar.gz" "$work/bin/scp" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
source_dir = pathlib.Path(sys.argv[2])
wg_quick_path = pathlib.Path(sys.argv[3])
mutagen_agents_path = pathlib.Path(sys.argv[4])
scp_wrapper_path = pathlib.Path(sys.argv[5])

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

with manifest_path.open(encoding="utf-8") as source:
    manifest = json.load(source)
manifest["managed_files"] = {
    "bin/wg-quick": {"sha256": sha256(wg_quick_path)},
    "bin/mutagen-agents.tar.gz": {"sha256": sha256(mutagen_agents_path)},
    "bin/scp": {"sha256": sha256(scp_wrapper_path)},
}
manifest["source_archives"] = [
    {"file": f"dependencies/sources/{path.name}", "sha256": sha256(path)}
    for path in sorted(source_dir.iterdir())
    if path.is_file()
]
with manifest_path.open("w", encoding="utf-8") as destination:
    json.dump(manifest, destination, indent=2)
    destination.write("\n")
PY
  if [[ "$target" == *apple-darwin ]]; then
    python3 - "$work/dependencies/manifest.json" "$work/bin/wireguard-go" "$WIREGUARD_GO_VERSION" <<'PY'
import hashlib
import json
import sys

manifest_path, binary_path, version = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as source:
    manifest = json.load(source)
with open(binary_path, "rb") as source:
    digest = hashlib.sha256(source.read()).hexdigest()
manifest["dependencies"].append({
    "name": "wireguard-go",
    "required_version": version,
    "binary": "bin/wireguard-go",
    "source": f"dependencies/sources/wireguard-go-{version}.tar.gz",
    "license": "MIT",
    "license_notice": "See dependencies/licenses/wireguard-go-LICENSE",
    "binary_sha256": digest,
})
with open(manifest_path, "w", encoding="utf-8") as destination:
    json.dump(manifest, destination, indent=2)
    destination.write("\n")
PY
  fi
  tar -C "$OUT_DIR" -czf "$OUT_DIR/$package.tar.gz" "$package"
done

echo "release artifacts written to $OUT_DIR"
