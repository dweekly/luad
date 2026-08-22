#!/usr/bin/env bash
set -euo pipefail

# Gate R1: Executable proof harness with full adversarial probes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"

cd "${ROOT_DIR}"

echo "==> Running Gate R1: Proof harness and adversarial probe tests"
echo "==> Output result directory: ${RESULT_DIR}"

cargo test -p luad-oracle --test test_gate_harness -- --nocapture

echo "==> Gate R1 passed successfully"
