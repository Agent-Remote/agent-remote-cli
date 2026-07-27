#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

chmod +x "$repo_root/.githooks/pre-commit"
chmod +x "$repo_root/.githooks/commit-msg"
chmod +x "$repo_root/.githooks/pre-push"
chmod +x "$repo_root/scripts/run-quality-checks.sh"

git -C "$repo_root" config core.hooksPath .githooks

echo "Installed git hooks from .githooks"
