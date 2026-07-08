#!/usr/bin/env bash
set -euo pipefail

REPO="${AGENT_REMOTE_REPO:-Agent-Remote/agent-remote-cli}"
VERSION="${AGENT_REMOTE_VERSION:-latest}"
AGENT_REMOTE_HOME="${AGENT_REMOTE_HOME:-$HOME/.config/agent-remote}"
INSTALL_BIN_DIR="${INSTALL_BIN_DIR:-$HOME/.local/bin}"
COPY_LINKS="${COPY_LINKS:-0}"
OS_OVERRIDE="${AGENT_REMOTE_OS:-}"
ARCH_OVERRIDE="${AGENT_REMOTE_ARCH:-}"
TARGET_OVERRIDE="${AGENT_REMOTE_TARGET:-}"
TMP_DIR="${TMPDIR:-/tmp}"
KEEP_TEMP="${KEEP_TEMP:-0}"

resolve_script_dir() {
  if [ -n "${BASH_SOURCE+x}" ] && [ "${#BASH_SOURCE[@]}" -gt 0 ]; then
    local source="${BASH_SOURCE[0]:-}"
    if [ -n "$source" ] && [ -e "$source" ]; then
      cd "$(dirname "$source")" && pwd
      return
    fi
  fi
  printf ''
}

SCRIPT_DIR="$(resolve_script_dir)"

usage() {
  cat <<'EOF'
Usage:
  install.sh [options]
  curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | bash

Installs the latest agent-remote CLI release by default. When executed from an
extracted release archive, installs the packaged files directly.

Options:
  --version VERSION     Release version, for example 0.0.3 or v0.0.3.
  --repo OWNER/REPO     GitHub repository to download from.
  --home PATH           Destination for managed binaries and local state.
  --bin-dir PATH        Directory for command links or wrapper copies.
  --target TARGET       Exact release target, for example aarch64-apple-darwin.
  --os OS               Override detected OS: linux or darwin.
  --arch ARCH           Override detected arch: amd64, x86_64, arm64, aarch64.
  --copy-links          Copy commands to --bin-dir instead of symlinking.
  --no-links            Do not create command links.
  --keep-temp           Keep downloaded archive and extraction directory.
  -h, --help            Show this help.

Environment:
  AGENT_REMOTE_VERSION  Same as --version.
  AGENT_REMOTE_REPO     Same as --repo.
  AGENT_REMOTE_HOME     Same as --home.
  INSTALL_BIN_DIR       Same as --bin-dir.
  AGENT_REMOTE_TARGET   Same as --target.
  AGENT_REMOTE_OS       Same as --os.
  AGENT_REMOTE_ARCH     Same as --arch.
  COPY_LINKS=1          Same as --copy-links.
  KEEP_TEMP=1           Same as --keep-temp.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="${2:?--version requires a value}"
      shift 2
      ;;
    --repo)
      REPO="${2:?--repo requires OWNER/REPO}"
      shift 2
      ;;
    --home)
      AGENT_REMOTE_HOME="${2:?--home requires a path}"
      shift 2
      ;;
    --bin-dir)
      INSTALL_BIN_DIR="${2:?--bin-dir requires a path}"
      shift 2
      ;;
    --target)
      TARGET_OVERRIDE="${2:?--target requires a value}"
      shift 2
      ;;
    --os)
      OS_OVERRIDE="${2:?--os requires a value}"
      shift 2
      ;;
    --arch)
      ARCH_OVERRIDE="${2:?--arch requires a value}"
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
    --keep-temp)
      KEEP_TEMP=1
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

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_file() {
  if [ ! -f "$1" ]; then
    echo "missing packaged file: $1" >&2
    exit 1
  fi
}

resolve_version() {
  if [ "$VERSION" != "latest" ]; then
    VERSION="${VERSION#v}"
    return
  fi
  need_cmd curl
  local tag
  tag="$(curl --fail --show-error --silent --location "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)"
  if [ -z "$tag" ]; then
    echo "failed to resolve latest release for $REPO" >&2
    exit 1
  fi
  VERSION="${tag#v}"
}

detect_target() {
  if [ -n "$TARGET_OVERRIDE" ]; then
    echo "$TARGET_OVERRIDE"
    return
  fi

  local os arch
  os="${OS_OVERRIDE:-$(uname -s)}"
  arch="${ARCH_OVERRIDE:-$(uname -m)}"

  case "$(printf '%s' "$os" | tr '[:upper:]' '[:lower:]')" in
    linux) os_part="unknown-linux-gnu" ;;
    darwin) os_part="apple-darwin" ;;
    *)
      echo "unsupported OS: $os" >&2
      exit 1
      ;;
  esac

  case "$(printf '%s' "$arch" | tr '[:upper:]' '[:lower:]')" in
    x86_64|amd64) arch_part="x86_64" ;;
    arm64|aarch64) arch_part="aarch64" ;;
    *)
      echo "unsupported architecture: $arch" >&2
      exit 1
      ;;
  esac

  echo "${arch_part}-${os_part}"
}

install_packaged() {
  local package_dir="$1"
  for binary in agent-remote fclaude agent-remote-wireguard mutagen; do
    require_file "$package_dir/bin/$binary"
  done
  require_file "$package_dir/dependencies/manifest.json"

  mkdir -p "$AGENT_REMOTE_HOME/bin" "$AGENT_REMOTE_HOME/dependencies"
  install -m 0755 "$package_dir/bin/agent-remote" "$AGENT_REMOTE_HOME/bin/agent-remote"
  install -m 0755 "$package_dir/bin/fclaude" "$AGENT_REMOTE_HOME/bin/fclaude"
  install -m 0755 "$package_dir/bin/agent-remote-wireguard" "$AGENT_REMOTE_HOME/bin/agent-remote-wireguard"
  install -m 0755 "$package_dir/bin/mutagen" "$AGENT_REMOTE_HOME/bin/mutagen"
  install -m 0644 "$package_dir/dependencies/manifest.json" "$AGENT_REMOTE_HOME/dependencies/manifest.json"

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
}

download_and_install() {
  need_cmd curl
  need_cmd tar
  resolve_version
  local target package url work archive
  target="$(detect_target)"
  package="agent-remote-cli-${VERSION}-${target}"
  url="https://github.com/${REPO}/releases/download/v${VERSION}/${package}.tar.gz"
  work="$(mktemp -d "${TMP_DIR%/}/agent-remote-cli-install.XXXXXX")"
  archive="$work/${package}.tar.gz"

  echo "Downloading $url"
  curl --fail --show-error --location --retry 5 --retry-all-errors --retry-delay 3 "$url" -o "$archive"
  tar -xzf "$archive" -C "$work"
  install_packaged "$work/$package"

  if [ "$KEEP_TEMP" = "1" ]; then
    echo "kept temporary directory: $work"
  else
    rm -rf "$work"
  fi
}

if [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/bin" ] && [ -d "$SCRIPT_DIR/dependencies" ]; then
  install_packaged "$SCRIPT_DIR"
elif [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/../bin" ] && [ -d "$SCRIPT_DIR/../dependencies" ]; then
  install_packaged "$(cd "$SCRIPT_DIR/.." && pwd)"
else
  download_and_install
fi

cat <<EOF
agent-remote CLI installed.
home: $AGENT_REMOTE_HOME
commands: ${INSTALL_BIN_DIR:-not linked}

Run:
  agent-remote init
EOF
