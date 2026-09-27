#!/usr/bin/env bash
set -euo pipefail

scripts/run-static-checks.sh
scripts/run-tests.sh
