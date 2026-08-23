#!/usr/bin/env bash
set -euo pipefail

# Canonical sprint gate: per-file export fact bounds (gate-batch-export-bounds).
#
# Specification: tests/gates/gate-batch-export-bounds.json
# Contract:      docs/NEXT-SPRINT.md
#
# This gate is an evidence gate, not a promotion gate. It requires a clean worktree and
# a complete proof package, and it explicitly refuses to emit or accept a release
# manifest: the sprint promotes no dialect, profile, or capability tier.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULT_DIR="${1:-$(mktemp -d)}"
SPEC_FILE="${ROOT_DIR}/tests/gates/gate-batch-export-bounds.json"

cd "${ROOT_DIR}"

echo "==> Running Gate: per-file export fact bounds (gate-batch-export-bounds)"
echo "==> Spec file: tests/gates/gate-batch-export-bounds.json"
echo "==> Output result directory: ${RESULT_DIR}"

if [[ ! -f "${SPEC_FILE}" ]]; then
  echo "Error: Gate specification is missing at ${SPEC_FILE}"
  exit 1
fi

# Clean-revision requirement, enforced before any evidence is produced.
if [[ -n "$(git -C "${ROOT_DIR}" status --porcelain)" ]]; then
  echo "Error: gate-batch-export-bounds requires a clean Git worktree."
  git -C "${ROOT_DIR}" status --porcelain
  exit 1
fi

GIT_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
echo "==> Clean revision: ${GIT_COMMIT}"

# Pinned public fixtures must be present and unmodified. Absence is a hard failure and
# never a skip; the runner re-verifies these hashes from the specification as well.
while read -r expected_sha fixture_path; do
  [[ -z "${expected_sha}" ]] && continue
  if [[ ! -f "${ROOT_DIR}/${fixture_path}" ]]; then
    echo "Error: Required fixture is missing: ${fixture_path}"
    exit 1
  fi
  actual_sha="$(shasum -a 256 "${ROOT_DIR}/${fixture_path}" | awk '{print $1}')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "Error: Fixture ${fixture_path} has SHA-256 ${actual_sha}, expected ${expected_sha}"
    exit 1
  fi
done <<'FIXTURES'
62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e tests/fixtures/precompiled/lua51/closures.luac
8376be37ec3042d3b0a87aa39db7d7396fb54ae390abe346d885e1527d23e353 tests/fixtures/precompiled/lua51_lnum32/hello.luac
a171c4c88ec40b1c871a57a888f66d7a93144e1d742f4071af286c9dc7b93575 tests/fixtures/precompiled/lua54/hello.luac
9806c9692fd2e55f737c0af5b9cfb96fd543383a2f4decc715c8c30a861ede0f tests/fixtures/precompiled/lua54/hello_stripped.luac
FIXTURES

mkdir -p "${RESULT_DIR}"

cargo run -p luad-oracle --bin run_gate -- \
  --spec "${SPEC_FILE}" \
  --out-dir "${RESULT_DIR}" \
  --require-clean \
  --record-probes

# Complete proof package. A release manifest is a promotion artifact and is deliberately
# not part of this package.
for artifact in "gate-spec.json" "gate-result.json" "probe-rejections.json" "stdout.log" "stderr.log"; do
  if [[ ! -f "${RESULT_DIR}/${artifact}" ]]; then
    echo "Error: Required artifact was not generated at ${RESULT_DIR}/${artifact}"
    exit 1
  fi
done

if [[ -e "${RESULT_DIR}/release-manifest.json" ]]; then
  echo "Error: gate-batch-export-bounds must not produce a release manifest; this sprint"
  echo "       promotes no dialect, profile, or capability tier."
  exit 1
fi

RESULT_FILE="${RESULT_DIR}/gate-result.json"

if ! grep -q '"gate_id": "gate-batch-export-bounds"' "${RESULT_FILE}"; then
  echo "Error: Result artifact does not belong to gate-batch-export-bounds"
  exit 1
fi
if ! grep -q "\"git_commit\": \"${GIT_COMMIT}\"" "${RESULT_FILE}"; then
  echo "Error: Result artifact was not produced from the clean revision ${GIT_COMMIT}"
  exit 1
fi
for invariant in \
  '"success": true' \
  '"dirty": false' \
  '"exit_code": 0' \
  '"failed_count": 0' \
  '"ignored_count": 0' \
  '"missing_expected_tests": \[\]'; do
  if ! grep -q "${invariant}" "${RESULT_FILE}"; then
    echo "Error: Result artifact violates required invariant: ${invariant}"
    exit 1
  fi
done
if grep -q '"passed_count": 0' "${RESULT_FILE}"; then
  echo "Error: Result artifact records zero passing tests"
  exit 1
fi

# Every enumerated acceptance test must appear in the recorded execution log, so a
# filtered or renamed test cannot pass as a green gate. Names are read from the
# expected_tests array only: command_argv also carries the --test target name
# 'test_batch_export_bounds', which is a test binary and never a libtest test name.
EXPECTED_TEST_COUNT=20
found_test_count=0
missing_in_log=0
while read -r test_name; do
  if [[ -n "${test_name}" ]]; then
    found_test_count=$((found_test_count + 1))
    if ! grep -q "test ${test_name} \.\.\. ok" "${RESULT_DIR}/stdout.log"; then
      echo "Error: Acceptance test did not run to completion: ${test_name}"
      missing_in_log=1
    fi
  fi
done < <(grep -A 1000 '"expected_tests"' "${SPEC_FILE}" |
  grep -m 1 -B 1000 '^  \]' |
  grep -o '"test_[a-z0-9_]*"' | tr -d '"')
if [[ "${missing_in_log}" -ne 0 ]]; then
  exit 1
fi

# Non-vacuity: an empty, truncated, or unparsed enumeration must fail the gate rather
# than satisfy the loop above with zero iterations.
if [[ "${found_test_count}" -ne "${EXPECTED_TEST_COUNT}" ]]; then
  echo "Error: Expected ${EXPECTED_TEST_COUNT} enumerated acceptance tests in ${SPEC_FILE},"
  echo "       parsed ${found_test_count}. The gate refuses to pass on a partial suite."
  exit 1
fi

if grep -qE 'test result: FAILED|[1-9][0-9]* failed|[1-9][0-9]* ignored|[1-9][0-9]* filtered out' \
  "${RESULT_DIR}/stdout.log"; then
  echo "Error: Acceptance run reported failed, ignored, or filtered tests"
  exit 1
fi

echo "==> Gate 'gate-batch-export-bounds' passed. Proof package verified in ${RESULT_DIR}"
