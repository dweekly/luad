#!/usr/bin/env bash
set -euo pipefail

# Gate R1: Executable proof harness and adversarial probes gate runner

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"
SPEC_FILE="${ROOT_DIR}/tests/gates/gate-proof-harness.json}"

cd "${ROOT_DIR}"

echo "==> Running Gate R1: Executable proof harness"
echo "==> Spec file: tests/gates/gate-proof-harness.json"
echo "==> Output result directory: ${RESULT_DIR}"

mkdir -p "${RESULT_DIR}"

cargo run -p luad-oracle --bin run_gate -- \
  --spec "${ROOT_DIR}/tests/gates/gate-proof-harness.json" \
  --out-dir "${RESULT_DIR}"

if [[ ! -f "${RESULT_DIR}/gate-result.json" ]]; then
  echo "Error: GateResult artifact was not generated at ${RESULT_DIR}/gate-result.json"
  exit 1
fi

echo "==> Gate R1 passed successfully. Result verified at ${RESULT_DIR}/gate-result.json"
