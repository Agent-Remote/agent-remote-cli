#!/usr/bin/env bash
set -euo pipefail

bash -n scripts/*.sh tests/*.sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test -- --test-threads=1
ruby tests/release_workflow_contract_test.rb
git diff --check
