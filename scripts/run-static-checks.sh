#!/usr/bin/env bash
set -euo pipefail

bash -n scripts/*.sh tests/*.sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
ruby tests/release_workflow_contract_test.rb
tests/managed_tools_cache_test.sh
git diff --check
