#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="dweekly/luad"
REPOSITORY_URL="https://github.com/dweekly/luad"
MAX_JSON_BYTES=1048576
MAX_SOURCE_ARCHIVE_BYTES=67108864
MAX_SOURCE_MEMBER_LIST_BYTES=8388608
ACTIVE_PROBE_TAG=""
TEMP_ROOT=""

die() {
  echo "release-publication: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/release-publication.sh rehearse <40-digit-source-revision> <ci-run-id>
  scripts/release-publication.sh withdraw <publication-rehearsal-tag> <40-digit-source-revision>
EOF
  exit 2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

bounded_bytes() {
  local path="$1"
  local label="$2"
  local limit="$3"
  local size
  size="$(wc -c <"${path}" | tr -d '[:space:]')"
  [[ "${size}" =~ ^[0-9]+$ ]] || die "could not measure ${label}"
  (( size <= limit )) || die "${label} exceeds ${limit} bytes"
}

bounded_file() {
  bounded_bytes "$1" "$2" "${MAX_JSON_BYTES}"
}

api_json() {
  local output="$1"
  local endpoint="$2"
  shift 2
  gh api "${endpoint}" "$@" >"${output}"
  bounded_file "${output}" "GitHub API response"
}

is_http_404() {
  grep -Eq '\(HTTP 404\)|gh: HTTP 404([[:space:]]|$)' "$1"
}

api_presence() {
  local endpoint="$1"
  local output="$2"
  local error="$3"
  if gh api "${endpoint}" >"${output}" 2>"${error}"; then
    bounded_file "${output}" "GitHub API response"
    return 0
  fi
  if is_http_404 "${error}"; then
    return 1
  fi
  cat "${error}" >&2
  die "GitHub API query failed for ${endpoint}"
}

release_exists() {
  api_presence "repos/${REPOSITORY}/releases/tags/$1" \
    "${TEMP_ROOT}/presence-release.json" "${TEMP_ROOT}/presence-release.err"
}

tag_exists() {
  api_presence "repos/${REPOSITORY}/git/ref/tags/$1" \
    "${TEMP_ROOT}/presence-tag.json" "${TEMP_ROOT}/presence-tag.err"
}

expect_api_absent() {
  local endpoint="$1"
  local label="$2"
  local output="${TEMP_ROOT}/absent-output"
  local error="${TEMP_ROOT}/absent-error"
  if gh api "${endpoint}" >"${output}" 2>"${error}"; then
    die "${label} unexpectedly exists"
  fi
  is_http_404 "${error}" || {
    cat "${error}" >&2
    die "could not prove ${label} absent"
  }
}

assert_identity_absent() {
  local tag="$1"
  if release_exists "${tag}"; then
    die "release already exists: ${tag}"
  fi
  if tag_exists "${tag}"; then
    die "tag already exists: ${tag}"
  fi
}

prove_identity_absent() {
  local tag="$1"
  expect_api_absent "repos/${REPOSITORY}/releases/tags/${tag}" "release ${tag}"
  expect_api_absent "repos/${REPOSITORY}/git/ref/tags/${tag}" "tag ${tag}"
  expect_api_absent "repos/${REPOSITORY}/tarball/${tag}" "tar source archive for ${tag}"
  expect_api_absent "repos/${REPOSITORY}/zipball/${tag}" "zip source archive for ${tag}"
}

delete_tag_if_present() {
  local tag="$1"
  if tag_exists "${tag}"; then
    gh api --method DELETE \
      "repos/${REPOSITORY}/git/refs/tags/${tag}" >/dev/null
  fi
}

delete_release_and_tag() {
  local tag="$1"
  gh release delete "${tag}" --repo "${REPOSITORY}" --yes
  delete_tag_if_present "${tag}"
}

cleanup_active_probe() {
  local status=$?
  trap - EXIT
  if (( status != 0 )) && [[ -n "${ACTIVE_PROBE_TAG}" ]]; then
    set +e
    gh release delete "${ACTIVE_PROBE_TAG}" --repo "${REPOSITORY}" \
      --yes >/dev/null 2>&1
    gh api --method DELETE \
      "repos/${REPOSITORY}/git/refs/tags/${ACTIVE_PROBE_TAG}" \
      >/dev/null 2>&1
    set -e
    if gh api "repos/${REPOSITORY}/releases/tags/${ACTIVE_PROBE_TAG}" \
        >/dev/null 2>"${TEMP_ROOT}/trap-release.err" || \
       ! is_http_404 "${TEMP_ROOT}/trap-release.err" || \
       gh api "repos/${REPOSITORY}/git/ref/tags/${ACTIVE_PROBE_TAG}" \
        >/dev/null 2>"${TEMP_ROOT}/trap-tag.err" || \
       ! is_http_404 "${TEMP_ROOT}/trap-tag.err" || \
       gh api "repos/${REPOSITORY}/tarball/${ACTIVE_PROBE_TAG}" \
        >/dev/null 2>"${TEMP_ROOT}/trap-tar.err" || \
       ! is_http_404 "${TEMP_ROOT}/trap-tar.err" || \
       gh api "repos/${REPOSITORY}/zipball/${ACTIVE_PROBE_TAG}" \
        >/dev/null 2>"${TEMP_ROOT}/trap-zip.err" || \
       ! is_http_404 "${TEMP_ROOT}/trap-zip.err"; then
      echo "release-publication: cleanup could not prove probe absent: ${ACTIVE_PROBE_TAG}" >&2
    fi
  fi
  [[ -z "${TEMP_ROOT}" ]] || rm -rf "${TEMP_ROOT}"
  exit "${status}"
}

validate_revision() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || \
    die "source revision must be exactly 40 lowercase hexadecimal digits"
}

validate_run_id() {
  [[ "$1" =~ ^[1-9][0-9]{0,19}$ ]] || die "CI run ID must be a positive decimal integer"
}

workspace_version() {
  local version
  version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
  [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
    die "workspace version is not a safe three-part numeric version"
  printf '%s\n' "${version}"
}

preflight_repository() {
  local revision="$1"
  local repository_json="${TEMP_ROOT}/repository.json"
  local head remote_url remote_main selected_ref selected_repository selected_workspace

  selected_ref="${GITHUB_REF:-refs/heads/$(git symbolic-ref --quiet --short HEAD)}"
  selected_repository="${GITHUB_REPOSITORY:-${REPOSITORY}}"
  selected_workspace="${GITHUB_WORKSPACE:-$(pwd -P)}"
  [[ "${selected_ref}" == "refs/heads/main" ]] || \
    die "workflow must be dispatched from refs/heads/main"
  [[ "${selected_repository}" == "${REPOSITORY}" ]] || \
    die "GITHUB_REPOSITORY must be ${REPOSITORY}"
  [[ -n "${selected_workspace}" && -d "${selected_workspace}" ]] || \
    die "GITHUB_WORKSPACE must name the current repository"
  [[ "$(cd "${selected_workspace}" && pwd -P)" == "$(pwd -P)" ]] || \
    die "GITHUB_WORKSPACE must be the current repository"
  export GITHUB_REF="${selected_ref}"
  export GITHUB_REPOSITORY="${selected_repository}"
  GITHUB_WORKSPACE="$(pwd -P)"
  export GITHUB_WORKSPACE

  head="$(git rev-parse HEAD)"
  [[ "${head}" == "${revision}" ]] || die "checkout revision does not match supplied revision"
  [[ -z "$(git status --porcelain --untracked-files=normal)" ]] || \
    die "checkout must be clean"
  remote_url="$(git remote get-url origin)"
  [[ "${remote_url}" == "${REPOSITORY_URL}" || \
     "${remote_url}" == "${REPOSITORY_URL}.git" ]] || \
    die "origin must be the canonical HTTPS repository"

  api_json "${repository_json}" "repos/${REPOSITORY}"
  jq -e --arg name "${REPOSITORY}" --arg url "${REPOSITORY_URL}" \
    '.full_name == $name and .html_url == $url' "${repository_json}" >/dev/null || \
    die "GitHub repository identity mismatch"
  remote_main="$(gh api "repos/${REPOSITORY}/commits/main" --jq .sha)"
  [[ "${remote_main}" == "${revision}" ]] || \
    die "supplied revision is not remote main"
}

verify_ci_run() {
  local revision="$1"
  local run_id="$2"
  local run_json="${TEMP_ROOT}/run.json"
  local jobs_expected="${TEMP_ROOT}/expected-jobs.txt"
  local jobs_actual="${TEMP_ROOT}/actual-jobs.txt"
  local artifacts_json="${TEMP_ROOT}/artifacts.json"

  gh run view "${run_id}" --repo "${REPOSITORY}" \
    --json event,headBranch,headSha,status,conclusion,workflowName,jobs >"${run_json}"
  bounded_file "${run_json}" "CI run response"
  jq -e --arg revision "${revision}" \
    '.event == "push" and .headBranch == "main" and .headSha == $revision and
     .status == "completed" and .conclusion == "success" and .workflowName == "CI"' \
    "${run_json}" >/dev/null || die "CI run identity or conclusion is not accepted"

  printf '%s\n' \
    'Dependency Audit' \
    'Hostile Input Fuzz Smoke (Linux)' \
    'MSRV (macos-latest)' \
    'MSRV (ubuntu-latest)' \
    'Release Archive Build (linux-x86_64, replica one)' \
    'Release Archive Build (linux-x86_64, replica two)' \
    'Release Archive Build (macos-aarch64, replica one)' \
    'Release Archive Build (macos-aarch64, replica two)' \
    'Release Archives' \
    'Release Bundle' \
    'Release SBOM' \
    'Test (macos-latest)' \
    'Test (ubuntu-latest)' | LC_ALL=C sort >"${jobs_expected}"
  jq -r '.jobs[] | select(.status == "completed" and .conclusion == "success") | .name' \
    "${run_json}" | LC_ALL=C sort >"${jobs_actual}"
  cmp "${jobs_expected}" "${jobs_actual}" >/dev/null || \
    die "CI run does not have exactly one successful result for every required job"
  [[ "$(jq '.jobs | length' "${run_json}")" == "13" ]] || \
    die "CI run contains missing, duplicate, or extra jobs"

  gh api "repos/${REPOSITORY}/actions/runs/${run_id}/artifacts?per_page=100" \
    --paginate --slurp >"${artifacts_json}"
  bounded_file "${artifacts_json}" "CI artifacts response"
  jq -e '[.[].artifacts[] | select(.name == "release-bundle")] as $matches |
    ($matches | length) == 1 and
    ($matches[0].expired == false) and
    ($matches[0].archive_download_url |
      startswith("https://api.github.com/repos/dweekly/luad/actions/artifacts/"))' \
    "${artifacts_json}" >/dev/null || \
    die "CI run must expose exactly one unexpired release-bundle artifact"
}

expected_asset_names() {
  local version="$1"
  printf '%s\n' \
    SHA256SUMS \
    evidence-index.json \
    "luad-${version}-linux-x86_64.tar.gz" \
    "luad-${version}-macos-aarch64.tar.gz" \
    "luad-${version}.cdx.json" | LC_ALL=C sort
}

assert_exact_assets() {
  local directory="$1"
  local version="$2"
  local expected="${TEMP_ROOT}/expected-assets.txt"
  local actual="${TEMP_ROOT}/actual-assets.txt"
  expected_asset_names "${version}" >"${expected}"
  find "${directory}" -mindepth 1 -maxdepth 1 -exec basename {} \; \
    | LC_ALL=C sort >"${actual}"
  cmp "${expected}" "${actual}" >/dev/null || return 1
  while IFS= read -r name; do
    [[ -f "${directory}/${name}" && ! -L "${directory}/${name}" ]] || return 1
  done <"${expected}"
}

verify_bundle_directory() {
  local directory="$1"
  local version="$2"
  local revision="$3"
  local result="${TEMP_ROOT}/bundle-verification.json"

  assert_exact_assets "${directory}" "${version}" || return 1
  [[ "$(wc -l <"${directory}/SHA256SUMS" | tr -d '[:space:]')" == "4" ]] || return 1
  (cd "${directory}" && sha256sum --check --strict SHA256SUMS >/dev/null) || return 1
  jq -e --arg version "${version}" --arg revision "${revision}" \
    '.version == $version and .source_revision == $revision and
     .dirty == false and .promoted_targets == []' \
    "${directory}/evidence-index.json" >/dev/null || return 1
  cargo run --quiet --locked -p luad-oracle --bin luad-release -- \
    verify-bundle --repository "${GITHUB_WORKSPACE}" --bundle-dir "${directory}" \
    >"${result}" || return 1
  bounded_file "${result}" "release bundle verifier result"
  jq -e --arg version "${version}" --arg revision "${revision}" \
    '.version == $version and .source_revision == $revision and (.files | length) == 5' \
    "${result}" >/dev/null || return 1
}

verify_downloaded_bytes() {
  local accepted="$1"
  local downloaded="$2"
  local version="$3"
  local revision="$4"
  local name

  assert_exact_assets "${downloaded}" "${version}" || return 1
  while IFS= read -r name; do
    cmp "${accepted}/${name}" "${downloaded}/${name}" >/dev/null || return 1
  done < <(expected_asset_names "${version}")
  verify_bundle_directory "${downloaded}" "${version}" "${revision}"
}

latest_identity() {
  local output="${TEMP_ROOT}/latest.json"
  local error="${TEMP_ROOT}/latest.err"
  if gh api "repos/${REPOSITORY}/releases/latest" >"${output}" 2>"${error}"; then
    bounded_file "${output}" "latest release response"
    jq -er '.tag_name' "${output}"
    return
  fi
  if is_http_404 "${error}"; then
    printf '%s\n' '__no_latest_release__'
    return
  fi
  cat "${error}" >&2
  die "could not resolve latest release pointer"
}

verify_tag_target() {
  local tag="$1"
  local revision="$2"
  local output="${TEMP_ROOT}/tag.json"
  api_json "${output}" "repos/${REPOSITORY}/git/ref/tags/${tag}"
  jq -e --arg revision "${revision}" \
    '.object.type == "commit" and .object.sha == $revision' "${output}" >/dev/null || \
    die "tag ${tag} does not resolve directly to the accepted revision"
}

verify_source_archive_root() {
  local archive="$1"
  local kind="$2"
  local revision="$3"
  local expected="dweekly-luad-${revision}/"
  local members="${TEMP_ROOT}/source-members-${kind}.txt"

  [[ -s "${archive}" ]] || die "${kind} source archive is empty"
  bounded_bytes "${archive}" "${kind} source archive" "${MAX_SOURCE_ARCHIVE_BYTES}"
  case "${kind}" in
    tar)
      tar -tzf "${archive}" >"${members}"
      ;;
    zip)
      unzip -Z1 "${archive}" >"${members}"
      ;;
    *)
      die "unknown source archive kind"
      ;;
  esac
  bounded_bytes "${members}" "${kind} source archive member list" \
    "${MAX_SOURCE_MEMBER_LIST_BYTES}"
  [[ -s "${members}" ]] || die "${kind} source archive contains no members"
  awk -v root="${expected}" 'index($0, root) != 1 { exit 1 }' "${members}" || \
    die "${kind} source archive is not rooted at ${expected}"
}

download_and_verify_source() {
  local tag="$1"
  local revision="$2"
  local directory="$3"
  mkdir -p "${directory}"
  gh release download "${tag}" --repo "${REPOSITORY}" --archive tar.gz \
    --output "${directory}/source.tar.gz"
  gh release download "${tag}" --repo "${REPOSITORY}" --archive zip \
    --output "${directory}/source.zip"
  verify_source_archive_root "${directory}/source.tar.gz" tar "${revision}"
  verify_source_archive_root "${directory}/source.zip" zip "${revision}"
}

release_assets() {
  local accepted="$1"
  local version="$2"
  printf '%s\n' \
    "${accepted}/SHA256SUMS" \
    "${accepted}/evidence-index.json" \
    "${accepted}/luad-${version}-linux-x86_64.tar.gz" \
    "${accepted}/luad-${version}-macos-aarch64.tar.gz" \
    "${accepted}/luad-${version}.cdx.json"
}

create_release() {
  local tag="$1"
  local title="$2"
  local notes="$3"
  local accepted="$4"
  local version="$5"
  shift 5
  local assets=()
  local path
  while IFS= read -r path; do
    assets+=("${path}")
  done < <(release_assets "${accepted}" "${version}")
  gh release create "${tag}" "${assets[@]}" --repo "${REPOSITORY}" \
    --target "${REVISION}" --title "${title}" --notes-file "${notes}" "$@" \
    >/dev/null
}

verify_release_metadata() {
  local tag="$1"
  local title="$2"
  local notes="$3"
  local revision="$4"
  local version="$5"
  local metadata="${TEMP_ROOT}/release-${tag}.json"
  local body="${TEMP_ROOT}/release-${tag}.body"
  local expected="${TEMP_ROOT}/release-${tag}.assets.expected"
  local actual="${TEMP_ROOT}/release-${tag}.assets.actual"

  api_json "${metadata}" "repos/${REPOSITORY}/releases/tags/${tag}"
  jq -e --arg tag "${tag}" --arg title "${title}" --arg revision "${revision}" \
    --arg url "${REPOSITORY_URL}/releases/tag/${tag}" \
    '.tag_name == $tag and .name == $title and .target_commitish == $revision and
     .draft == false and .prerelease == true and .html_url == $url' \
    "${metadata}" >/dev/null || die "release metadata mismatch for ${tag}"
  jq -rj '.body' "${metadata}" >"${body}"
  cmp "${notes}" "${body}" >/dev/null || die "release notes mismatch for ${tag}"
  expected_asset_names "${version}" >"${expected}"
  jq -r '.assets[].name' "${metadata}" | LC_ALL=C sort >"${actual}"
  cmp "${expected}" "${actual}" >/dev/null || die "release asset set mismatch for ${tag}"
}

download_release_assets() {
  local tag="$1"
  local destination="$2"
  mkdir -p "${destination}"
  gh release download "${tag}" --repo "${REPOSITORY}" --dir "${destination}"
}

verify_published_release() {
  local tag="$1"
  local title="$2"
  local notes="$3"
  local accepted="$4"
  local version="$5"
  local revision="$6"
  local download="${TEMP_ROOT}/download-${tag}"
  local source="${TEMP_ROOT}/source-${tag}"

  verify_release_metadata "${tag}" "${title}" "${notes}" "${revision}" "${version}"
  verify_tag_target "${tag}" "${revision}"
  download_release_assets "${tag}" "${download}"
  verify_downloaded_bytes "${accepted}" "${download}" "${version}" "${revision}" || \
    die "fresh release asset verification failed for ${tag}"
  download_and_verify_source "${tag}" "${revision}" "${source}"
}

delete_and_prove_probe_absent() {
  local tag="$1"
  delete_release_and_tag "${tag}"
  prove_identity_absent "${tag}"
  ACTIVE_PROBE_TAG=""
}

write_probe_notes() {
  local output="$1"
  local label="$2"
  cat >"${output}" <<EOF
NOT A PRODUCT RELEASE — ${label}.

This names no supported Lua target and must not be used as a stable release.
EOF
}

write_retained_notes() {
  local output="$1"
  local version="$2"
  local revision="$3"
  local run_id="$4"
  local tag="$5"
  local accepted="$6"
  {
    printf '%s\n\n' 'NOT A PRODUCT RELEASE — publication mechanics rehearsal only.'
    printf '%s\n\n' "Version: \`${version}\`"
    printf '%s\n\n' "Source revision: \`${revision}\`"
    printf 'Accepted CI run: %s/actions/runs/%s\n\n' "${REPOSITORY_URL}" "${run_id}"
    printf '%s\n\n' 'Checksums:'
    printf '%s\n' '```text'
    cat "${accepted}/SHA256SUMS"
    printf '%s\n\n' '```'
    printf '%s\n\n' "Supported targets: \`none\`"
    printf '%s\n\n' "Signing: \`not signed\`"
    printf '%s\n' \
      "Withdraw with: \`scripts/release-publication.sh withdraw ${tag} ${revision}\`"
  } >"${output}"
}

run_failure_probe() {
  local accepted="$1"
  local version="$2"
  local revision="$3"
  local tag="$4"
  local probe="${TEMP_ROOT}/failure-probe-bundle"
  local notes="${TEMP_ROOT}/failure-probe-notes.md"
  local download="${TEMP_ROOT}/failure-probe-download"

  cp -R "${accepted}" "${probe}"
  printf '\000' | dd of="${probe}/luad-${version}-linux-x86_64.tar.gz" \
    bs=1 seek=0 count=1 conv=notrunc status=none
  write_probe_notes "${notes}" 'corrupted draft cleanup probe'
  ACTIVE_PROBE_TAG="${tag}"
  create_release "${tag}" "luad publication failure probe" "${notes}" \
    "${probe}" "${version}" --draft --prerelease --latest=false
  download_release_assets "${tag}" "${download}"
  if verify_downloaded_bytes "${accepted}" "${download}" "${version}" "${revision}"; then
    die "corrupted draft unexpectedly passed fresh verification"
  fi
  delete_and_prove_probe_absent "${tag}"
}

run_withdrawal_probe() {
  local accepted="$1"
  local version="$2"
  local revision="$3"
  local tag="$4"
  local notes="${TEMP_ROOT}/withdrawal-probe-notes.md"

  write_probe_notes "${notes}" 'valid withdrawal probe'
  ACTIVE_PROBE_TAG="${tag}"
  create_release "${tag}" "luad publication withdrawal probe" "${notes}" \
    "${accepted}" "${version}" --prerelease --latest=false
  verify_published_release "${tag}" "luad publication withdrawal probe" "${notes}" \
    "${accepted}" "${version}" "${revision}"
  delete_and_prove_probe_absent "${tag}"
}

rehearse() {
  local revision="$1"
  local run_id="$2"
  local version retained_tag failure_tag withdrawal_tag
  local accepted notes title latest_before latest_after

  validate_revision "${revision}"
  validate_run_id "${run_id}"
  REVISION="${revision}"
  preflight_repository "${revision}"
  verify_ci_run "${revision}" "${run_id}"
  version="$(workspace_version)"
  retained_tag="publication-rehearsal-${version}-${revision:0:12}"
  failure_tag="publication-failure-probe-${version}-${revision:0:12}"
  withdrawal_tag="publication-withdrawal-probe-${version}-${revision:0:12}"
  accepted="${TEMP_ROOT}/accepted-release-bundle"
  notes="${TEMP_ROOT}/retained-notes.md"
  title="luad ${version} publication rehearsal (${revision:0:12})"

  mkdir -p "${accepted}"
  gh run download "${run_id}" --repo "${REPOSITORY}" --name release-bundle --dir "${accepted}"
  verify_bundle_directory "${accepted}" "${version}" "${revision}" || \
    die "accepted release-bundle artifact failed verification"
  write_retained_notes "${notes}" "${version}" "${revision}" "${run_id}" \
    "${retained_tag}" "${accepted}"

  assert_identity_absent "${failure_tag}"
  assert_identity_absent "${withdrawal_tag}"
  latest_before="$(latest_identity)"

  if release_exists "${retained_tag}"; then
    tag_exists "${retained_tag}" || die "retained release exists without its tag"
    verify_published_release "${retained_tag}" "${title}" "${notes}" \
      "${accepted}" "${version}" "${revision}"
    latest_after="$(latest_identity)"
    [[ "${latest_after}" == "${latest_before}" ]] || \
      die "retained rehearsal changed the latest release pointer"
    printf '%s\n' "${REPOSITORY_URL}/releases/tag/${retained_tag}"
    return
  fi
  tag_exists "${retained_tag}" && die "retained tag exists without its release"

  run_failure_probe "${accepted}" "${version}" "${revision}" "${failure_tag}"
  [[ "$(latest_identity)" == "${latest_before}" ]] || \
    die "failure probe changed the latest release pointer"
  run_withdrawal_probe "${accepted}" "${version}" "${revision}" "${withdrawal_tag}"
  [[ "$(latest_identity)" == "${latest_before}" ]] || \
    die "withdrawal probe changed the latest release pointer"

  create_release "${retained_tag}" "${title}" "${notes}" \
    "${accepted}" "${version}" --prerelease --latest=false
  verify_published_release "${retained_tag}" "${title}" "${notes}" \
    "${accepted}" "${version}" "${revision}"
  latest_after="$(latest_identity)"
  [[ "${latest_after}" == "${latest_before}" ]] || \
    die "retained rehearsal changed the latest release pointer"
  printf '%s\n' "${REPOSITORY_URL}/releases/tag/${retained_tag}"
}

withdraw() {
  local tag="$1"
  local revision="$2"
  local current_revision metadata

  validate_revision "${revision}"
  REVISION="${revision}"
  current_revision="$(git rev-parse HEAD)"
  validate_revision "${current_revision}"
  preflight_repository "${current_revision}"
  [[ "${tag}" =~ ^publication-rehearsal-[0-9]+\.[0-9]+\.[0-9]+-${revision:0:12}$ ]] || \
    die "withdrawal tag does not match the named rehearsal revision"
  release_exists "${tag}" || die "retained rehearsal release is absent"
  verify_tag_target "${tag}" "${revision}"
  metadata="${TEMP_ROOT}/withdrawal-release.json"
  api_json "${metadata}" "repos/${REPOSITORY}/releases/tags/${tag}"
  jq -e --arg tag "${tag}" --arg revision "${revision}" \
    '.tag_name == $tag and .target_commitish == $revision and
     .draft == false and .prerelease == true' "${metadata}" >/dev/null || \
    die "withdrawal target is not the exact retained rehearsal"
  delete_release_and_tag "${tag}"
  prove_identity_absent "${tag}"
}

main() {
  (( $# >= 1 )) || usage
  require_command gh
  require_command jq
  require_command git
  require_command cargo
  require_command cmp
  require_command sha256sum
  require_command tar
  require_command unzip
  TEMP_ROOT="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/luad-release-publication.XXXXXX")"
  trap cleanup_active_probe EXIT

  case "$1" in
    rehearse)
      (( $# == 3 )) || usage
      rehearse "$2" "$3"
      ;;
    withdraw)
      (( $# == 3 )) || usage
      withdraw "$2" "$3"
      ;;
    *)
      usage
      ;;
  esac
  ACTIVE_PROBE_TAG=""
  trap - EXIT
  rm -rf "${TEMP_ROOT}"
}

main "$@"
