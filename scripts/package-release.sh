#!/usr/bin/env bash
set -euo pipefail

default_version() {
  sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1
}

VERSION="${VERSION:-$(default_version)}"
OUT_DIR="${OUT_DIR:-dist}"
TARGETS="${TARGETS:-x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin}"
MUTAGEN_VERSION="${MUTAGEN_VERSION:-0.18.1}"

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
  rm -rf "$tmp"
}

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

for target in $TARGETS; do
  AGENT_REMOTE_VERSION="$VERSION" cargo build --release --target "$target"
  package="agent-remote-cli-${VERSION}-${target}"
  work="$OUT_DIR/$package"
  mkdir -p "$work/bin" "$work/dependencies"
  install -m 0755 "target/$target/release/agent-remote" "$work/bin/agent-remote"
  install -m 0755 "target/$target/release/fclaude" "$work/bin/fclaude"
  install -m 0755 "target/$target/release/agent-remote-wireguard" "$work/bin/agent-remote-wireguard"
  download_mutagen "$target" "$work/bin/mutagen"
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
      "license": "GPL-2.0-only for wireguard-tools; platform implementations may vary",
      "license_notice": "See THIRD_PARTY_NOTICES.md"
    }
  ]
}
EOF
  tar -C "$OUT_DIR" -czf "$OUT_DIR/$package.tar.gz" "$package"
done

echo "release artifacts written to $OUT_DIR"
