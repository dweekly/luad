#!/usr/bin/env bash
set -euo pipefail

# Candidate qualification gate for reproducible Lua 5.1 LNUM32 candidate

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"
SPEC_FILE="${ROOT_DIR}/tests/gates/gate-candidate-lua51-lnum32.json"
AUTHORITY_ROOT="${RESULT_DIR}/authority"

cd "${ROOT_DIR}"

echo "==> Running Gate: Lua 5.1 LNUM32 candidate qualification"
echo "==> Spec file: tests/gates/gate-candidate-lua51-lnum32.json"
echo "==> Output result directory: ${RESULT_DIR}"

mkdir -p "${RESULT_DIR}"

# Build candidate tool and export candidate tool location
cargo build -p luad-oracle --bin luad-candidate
export LUAD_CANDIDATE_TOOL="${ROOT_DIR}/target/debug/luad-candidate"

# Qualify an extracted deterministic archive instead of a workspace binary.
cargo build --release -p luad-cli --bin luad
PACKAGE_DIR="$(mktemp -d)"
printf '{"version":"0.1.0","source_commit":"%s"}\n' "$(git rev-parse HEAD)" \
  > "${PACKAGE_DIR}/VERSION.json"
"${LUAD_CANDIDATE_TOOL}" pack \
  --spec "${ROOT_DIR}/tests/candidates/lua51-lnum32-rc1.json" \
  --binary "${ROOT_DIR}/target/release/luad" \
  --license "${ROOT_DIR}/LICENSE" \
  --version-info "${PACKAGE_DIR}/VERSION.json" \
  --out-archive "${PACKAGE_DIR}/candidate.tar.gz" \
  --out-ledger "${PACKAGE_DIR}/ledger.json"
mkdir -p "${PACKAGE_DIR}/extracted"
tar -xzf "${PACKAGE_DIR}/candidate.tar.gz" -C "${PACKAGE_DIR}/extracted"
export LUAD_CANDIDATE_BIN="${PACKAGE_DIR}/extracted/bin/luad"

scripts/build_lua51_openwrt_lnum32.sh "${AUTHORITY_ROOT}" --reproduce
export LUAD_LNUM32_LUAC="${AUTHORITY_ROOT}/lua-5.1.5/src/luac-host"

export CARGO_TERM_COLOR=never
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

if [[ -f "${RESULT_DIR}/release-manifest.json" ]]; then
  echo "Error: Non-promotion candidate gate must not produce release-manifest.json"
  exit 1
fi

echo "==> Gate passed successfully. Candidate verification package recorded in ${RESULT_DIR}"
