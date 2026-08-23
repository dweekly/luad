#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"
SPEC_FILE="${ROOT_DIR}/tests/gates/gate-validation-null-hypothesis.json"

cd "${ROOT_DIR}"
echo "==> Running Gate V1: Validation Null Hypothesis"
mkdir -p "${RESULT_DIR}"

cargo run -p luad-oracle --bin run_gate -- \
  --spec "${SPEC_FILE}" \
  --out-dir "${RESULT_DIR}" \
  --require-clean

echo "==> Gate V1 passed successfully. Result in ${RESULT_DIR}"
