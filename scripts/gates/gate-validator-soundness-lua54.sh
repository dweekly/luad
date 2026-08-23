#!/usr/bin/env bash
set -euo pipefail

# Gate V1: Validator soundness and complete test coverage for Lua 5.4

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"
SPEC_FILE="${ROOT_DIR}/tests/gates/gate-validator-soundness-lua54.json"

cd "${ROOT_DIR}"

echo "==> Running Gate V1: Validator soundness and complete diagnostic test coverage for Lua 5.4"
echo "==> Spec file: tests/gates/gate-validator-soundness-lua54.json"
echo "==> Output result directory: ${RESULT_DIR}"

mkdir -p "${RESULT_DIR}"

cargo run -p luad-oracle --bin run_gate -- \
  --spec "${SPEC_FILE}" \
  --out-dir "${RESULT_DIR}" \
  --require-clean \
  --record-probes

for artifact in "gate-spec.json" "gate-result.json" "probe-rejections.json" "stdout.log"; do
  if [[ ! -f "${RESULT_DIR}/${artifact}" ]]; then
    echo "Error: Required artifact was not generated at ${RESULT_DIR}/${artifact}"
    exit 1
  fi
done

echo "==> Gate V1 passed successfully. Full proof package verified in ${RESULT_DIR}"
