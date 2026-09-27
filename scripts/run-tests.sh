#!/usr/bin/env bash
set -euo pipefail

# Nextest schedules tests across binaries and isolates process-global state.
# Keep Cargo's harness as a complete fallback for fresh developer checkouts.
if command -v cargo-nextest >/dev/null 2>&1; then
  cargo nextest run --workspace --test-threads 8 --no-fail-fast
  cargo test --workspace --doc
else
  cargo test --workspace -- --test-threads=4
fi
