#!/usr/bin/env bash
set -euo pipefail

# Gate P1: Executable gate and evidence harness

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate P1: Proof harness and gate runner tests"
cargo test -p luad-oracle --test test_gate_harness -- --nocapture

echo "==> Gate P1 passed successfully"
