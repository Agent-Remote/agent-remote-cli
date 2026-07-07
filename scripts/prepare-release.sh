#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <version>" >&2
  echo "Example: $0 0.0.2" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

VERSION="${1#v}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid semantic version: $1" >&2
  exit 2
fi

python3 - "$VERSION" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

version = sys.argv[1]

cargo = Path("Cargo.toml")
text = cargo.read_text()
text = re.sub(r'(?m)^version = "[^"]+"$', f'version = "{version}"', text, count=1)
cargo.write_text(text)

readme = Path("README.md")
if readme.exists():
    text = readme.read_text()
    text = re.sub(
        r"VERSION=[0-9A-Za-z.+-]+ scripts/package-release\.sh",
        f"VERSION={version} scripts/package-release.sh",
        text,
    )
    readme.write_text(text)

readme_cn = Path("README.zh-CN.md")
if readme_cn.exists():
    text = readme_cn.read_text()
    text = re.sub(
        r"VERSION=[0-9A-Za-z.+-]+ scripts/package-release\.sh",
        f"VERSION={version} scripts/package-release.sh",
        text,
    )
    readme_cn.write_text(text)
PY

cargo metadata --format-version=1 --no-deps >/dev/null

scripts/update-changelog.sh "$VERSION"

echo "Prepared agent-remote-cli v${VERSION}"
