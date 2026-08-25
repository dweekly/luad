#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"

GATES=(
  gate-proof-harness
  gate-layout-lua51-stock
  gate-profile-lua51-lnum
  gate-cli-selection-contract
  gate-public-disasm-lua51
  gate-validation-null-hypothesis
  gate-validator-reference-operands-lua51
  gate-validator-register-a-lua51
  gate-validator-register-b-lua51
  gate-validator-register-c-lua51
  gate-validator-rk-b-lua51
  gate-validator-rk-c-lua51
  gate-validator-nested-rk-owner-lua51
  gate-validator-self-span-lua51
  gate-validator-numeric-for-span-lua51
  gate-validator-tforloop-span-lua51
  gate-validator-closure-capture-span-lua51
  gate-validator-count-spans-lua51
  gate-closure-prototype-identity-lua51
  gate-diagnostic-catalog
  gate-area1-validator-diagnostics
)

mkdir -p "${RESULT_DIR}"
for gate in "${GATES[@]}"; do
  bash "${ROOT_DIR}/scripts/gates/${gate}.sh" "${RESULT_DIR}/${gate}"
done

echo "==> Area 1 critical path passed. Results in ${RESULT_DIR}"
