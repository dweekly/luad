#!/usr/bin/env bash
set -euo pipefail

# Gate F1 (LNUM): Lua 5.1 LNUM vendor profile verification

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"
SPEC_FILE="${ROOT_DIR}/tests/gates/gate-profile-lua51-lnum.json"

cd "${ROOT_DIR}"

echo "==> Running Gate F1 (LNUM): Lua 5.1 LNUM profile and cross-profile failure verification"
echo "==> Spec file: tests/gates/gate-profile-lua51-lnum.json"
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

echo "==> Gate F1 (LNUM) passed successfully. Full proof package verified in ${RESULT_DIR}"
