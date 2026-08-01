#!/usr/bin/env bash
set -euo pipefail

PACKAGE_DIR="${1:?package directory is required}"
INSTALL_HOME="${2:?install home is required}"
LINK_DIR="${3:?link directory is required}"
EXPECTED_VERSION="${4:?expected version is required}"

require_file() {
  if [ ! -f "$1" ]; then
    echo "missing file: $1" >&2
    exit 1
  fi
}

require_executable() {
  require_file "$1"
  if [ ! -x "$1" ]; then
    echo "file is not executable: $1" >&2
    exit 1
  fi
}

for binary in agent-remote fclaude agent-remote-wireguard mutagen scp ssh tmux wg wg-quick; do
  require_executable "$PACKAGE_DIR/bin/$binary"
  require_executable "$INSTALL_HOME/bin/$binary"
done
require_file "$PACKAGE_DIR/bin/mutagen-agents.tar.gz"
require_file "$INSTALL_HOME/bin/mutagen-agents.tar.gz"

if [ "$(uname -s)" = "Darwin" ]; then
  require_executable "$PACKAGE_DIR/bin/wireguard-go"
  require_executable "$INSTALL_HOME/bin/wireguard-go"
fi

for command in agent-remote fclaude agent-remote-wireguard; do
  if [ ! -L "$LINK_DIR/$command" ]; then
    echo "missing command symlink: $LINK_DIR/$command" >&2
    exit 1
  fi
done

python3 - "$PACKAGE_DIR" "$INSTALL_HOME" <<'PY'
import hashlib
import json
import pathlib
import sys

package = pathlib.Path(sys.argv[1])
installed = pathlib.Path(sys.argv[2])
manifest_path = package / "dependencies/manifest.json"
with manifest_path.open(encoding="utf-8") as source:
    manifest = json.load(source)

required = {"mutagen", "wireguard-helper", "scp-proxy", "ssh-proxy", "tmux", "wireguard-tools"}
names = {dependency["name"] for dependency in manifest["dependencies"]}
missing = required - names
if missing:
    raise SystemExit(f"manifest is missing dependencies: {sorted(missing)}")

def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

for dependency in manifest["dependencies"]:
    binary = package / dependency["binary"]
    if not binary.is_file():
        raise SystemExit(f"manifest binary is missing: {binary}")
    if expected := dependency.get("binary_sha256"):
        if sha256(binary) != expected:
            raise SystemExit(f"binary checksum mismatch: {binary}")
    source = dependency.get("source", "")
    if source.startswith("dependencies/") and not (package / source).is_file():
        raise SystemExit(f"manifest source is missing: {source}")
    notice = dependency.get("license_notice", "")
    marker = "See dependencies/"
    if notice.startswith(marker):
        relative = notice.removeprefix("See ")
        if not (package / relative).is_file():
            raise SystemExit(f"manifest license is missing: {relative}")

for relative, metadata in manifest.get("managed_files", {}).items():
    path = package / relative
    if not path.is_file() or sha256(path) != metadata["sha256"]:
        raise SystemExit(f"managed file checksum mismatch: {relative}")

for archive in manifest.get("source_archives", []):
    path = package / archive["file"]
    if not path.is_file() or sha256(path) != archive["sha256"]:
        raise SystemExit(f"source archive checksum mismatch: {archive['file']}")

package_dependencies = package / "dependencies"
installed_dependencies = installed / "dependencies"
package_files = sorted(
    path.relative_to(package_dependencies) for path in package_dependencies.rglob("*") if path.is_file()
)
installed_files = sorted(
    path.relative_to(installed_dependencies) for path in installed_dependencies.rglob("*") if path.is_file()
)
if package_files != installed_files:
    raise SystemExit("installed dependency file list does not match the package")
for relative in package_files:
    if sha256(package_dependencies / relative) != sha256(installed_dependencies / relative):
        raise SystemExit(f"installed dependency differs from package: {relative}")
PY

"$INSTALL_HOME/bin/agent-remote" --version | grep -F "$EXPECTED_VERSION"
"$INSTALL_HOME/bin/fclaude" --version | grep -F "$EXPECTED_VERSION"
"$INSTALL_HOME/bin/agent-remote-wireguard" --version | grep -F "$EXPECTED_VERSION"
"$INSTALL_HOME/bin/mutagen" version
"$INSTALL_HOME/bin/tmux" -V
"$INSTALL_HOME/bin/wg" --version
if [ "$(uname -s)" = "Darwin" ]; then
  "$INSTALL_HOME/bin/wireguard-go" --version
fi

managed_mutagen() {
  AGENT_REMOTE_HOME="$INSTALL_HOME" \
    MUTAGEN_SSH_PATH="$INSTALL_HOME/bin" \
    PATH="$INSTALL_HOME/bin:$PATH" \
    "$INSTALL_HOME/bin/mutagen" "$@"
}

managed_mutagen daemon start
"$PACKAGE_DIR/install.sh" --home "$INSTALL_HOME" --bin-dir "$LINK_DIR"
if ! managed_mutagen daemon stop; then
  echo "installer did not restore the managed Mutagen daemon" >&2
  exit 1
fi

echo "Unix install smoke test passed"
