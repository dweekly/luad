#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"
SPEC_FILE="${ROOT_DIR}/tests/gates/gate-validator-closure-capture-span-lua51.json"

cd "${ROOT_DIR}"
mkdir -p "${RESULT_DIR}"
cargo run -p luad-oracle --bin run_gate -- \
  --spec "${SPEC_FILE}" \
  --out-dir "${RESULT_DIR}" \
  --require-clean

echo "==> Gate gate-validator-closure-capture-span-lua51 passed. Result in ${RESULT_DIR}"
