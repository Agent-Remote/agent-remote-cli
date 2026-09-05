#!/usr/bin/env bash
set -euo pipefail

scripts/run-static-checks.sh
cargo test -- --test-threads=1
