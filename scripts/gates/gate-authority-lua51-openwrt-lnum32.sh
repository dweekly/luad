#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"
AUTHORITY_ROOT="${RESULT_DIR}/authority"

cd "${ROOT_DIR}"
mkdir -p "${RESULT_DIR}"
scripts/build_lua51_openwrt_lnum32.sh "${AUTHORITY_ROOT}" --reproduce
export LUAD_LNUM32_LUAC="${AUTHORITY_ROOT}/lua-5.1.5/src/luac-host"
cargo run -p luad-oracle --bin run_gate -- \
  --spec tests/gates/gate-authority-lua51-openwrt-lnum32.json \
  --out-dir "${RESULT_DIR}" --require-clean --record-probes
