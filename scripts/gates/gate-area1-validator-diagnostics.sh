#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"
SPEC_FILE="${ROOT_DIR}/tests/gates/gate-area1-validator-diagnostics.json"

cd "${ROOT_DIR}"
mkdir -p "${RESULT_DIR}"
cargo run -p luad-oracle --bin run_gate -- \
  --spec "${SPEC_FILE}" \
  --out-dir "${RESULT_DIR}" \
  --require-clean \
  --record-probes

for artifact in gate-spec.json gate-result.json probe-rejections.json stdout.log; do
  test -f "${RESULT_DIR}/${artifact}"
done

echo "==> Area 1 validator and diagnostic closure passed. Result in ${RESULT_DIR}"
