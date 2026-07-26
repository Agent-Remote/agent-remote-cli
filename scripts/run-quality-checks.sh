#!/usr/bin/env bash
set -euo pipefail

bash -n scripts/*.sh tests/*.sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
