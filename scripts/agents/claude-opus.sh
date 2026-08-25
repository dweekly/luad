#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/agents/claude-opus.sh design-review PROMPT_FILE
  scripts/agents/claude-opus.sh review-fresh PROMPT_FILE
  scripts/agents/claude-opus.sh review-start PROMPT_FILE
  scripts/agents/claude-opus.sh review-resume SESSION_ID PROMPT_FILE
  scripts/agents/claude-opus.sh acceptance-start PROMPT_FILE
  scripts/agents/claude-opus.sh acceptance-resume SESSION_ID PROMPT_FILE

Runs Claude Opus through the logged-in claude.ai subscription. Console API
credentials are removed from the child environment so they cannot silently
override the subscription. Every stage is a bounded, tool-free review over the
self-contained prompt packet. Output is one Claude Code JSON result carrying the
structured verdict and cumulative session usage. Set LUAD_CLAUDE_DEBUG_FILE to
choose the detailed CLI debug log. The default wall-time ceiling is 600 seconds;
set LUAD_CLAUDE_REVIEW_TIMEOUT_SECONDS to a positive integer to change it.

review-fresh       Independent one-shot review with no persisted session.
review-start       Start a persistent, bounded review of a curated packet.
review-resume      Ask at most one bounded follow-up in that session.
design-review      Critique a self-contained design without repository tools.
acceptance-start   Review a self-contained acceptance design.
acceptance-resume  Ask at most one bounded acceptance follow-up.

Claude does not inspect or edit the repository. The steward supplies exact context,
applies decisions, and runs all verification.
EOF
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
fi

stage=${1:-}
case "$stage" in
  design-review)
    prompt_file=${2:-}
    session_args=(--no-session-persistence)
    ;;
  review-fresh)
    prompt_file=${2:-}
    session_args=(--no-session-persistence)
    ;;
  review-start)
    prompt_file=${2:-}
    session_args=()
    ;;
  review-resume)
    session_id=${2:-}
    prompt_file=${3:-}
    if [[ ! "$session_id" =~ ^[a-zA-Z0-9-]+$ ]]; then
      echo "invalid Claude session ID" >&2
      exit 2
    fi
    session_args=(--resume "$session_id")
    ;;
  acceptance-start)
    prompt_file=${2:-}
    session_args=()
    ;;
  acceptance-resume)
    session_id=${2:-}
    prompt_file=${3:-}
    if [[ ! "$session_id" =~ ^[a-zA-Z0-9-]+$ ]]; then
      echo "invalid Claude session ID" >&2
      exit 2
    fi
    session_args=(--resume "$session_id")
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if [[ -z "$prompt_file" || ! -f "$prompt_file" ]]; then
  usage >&2
  exit 2
fi

if ! command -v claude >/dev/null 2>&1; then
  echo "claude is not installed or not on PATH" >&2
  exit 127
fi

auth_json=$(env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_BASE_URL \
  claude auth status --json)
if ! grep -Eq '"authMethod"[[:space:]]*:[[:space:]]*"claude.ai"' <<<"$auth_json"; then
  echo "Claude subscription authentication is unavailable; refusing API-key fallback" >&2
  exit 1
fi

prompt=$(<"$prompt_file")
prompt=$'This is a single bounded no-tools review. Analyze only the supplied packet. Do not claim to inspect a repository, invoke tools, delegate work, edit files, or invent missing implementation details. A blocking finding must cite supplied evidence and describe a reproducible failure mode. Treat missing context as an explicit ambiguity. Return one verdict and stop.\n\n'"$prompt"
reviewer_system='You are an independent software evidence reviewer. Analyze only the supplied packet. Do not inspect repositories, invoke tools other than the required structured-output response, delegate work, or propose unrelated improvements. A blocking finding must identify a reproducible failure of the stated claim. Return exactly one structured verdict.'
started_at=$(date +%s)
debug_file=${LUAD_CLAUDE_DEBUG_FILE:-/tmp/luad-claude-${started_at}.debug.log}
prompt_sha256=$(shasum -a 256 "$prompt_file" | awk '{print $1}')

finish() {
  status=$?
  finished_at=$(date +%s)
  echo "claude_prompt_sha256=$prompt_sha256" >&2
  echo "claude_wall_seconds=$((finished_at - started_at))" >&2
  echo "claude_debug_file=$debug_file" >&2
  exit "$status"
}
trap finish EXIT

review_schema='{"type":"object","additionalProperties":false,"properties":{"verdict":{"type":"string","enum":["accept","reject","needs-information"]},"blocking_findings":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string"},"failure_mode":{"type":"string"},"required_correction":{"type":"string"}},"required":["path","failure_mode","required_correction"]}},"residual_risks":{"type":"array","items":{"type":"string"}}},"required":["verdict","blocking_findings","residual_risks"]}'
common=(
  -p "$prompt"
  --model opus
  --name luad-bounded-review
  --safe-mode
  --system-prompt "$reviewer_system"
  --autocompact 1M
  --strict-mcp-config
  --mcp-config '{"mcpServers":{}}'
  --disable-slash-commands
  --no-chrome
  --prompt-suggestions false
  --debug-file "$debug_file"
  --verbose
  --output-format json
  --json-schema "$review_schema"
)
clean_env=(env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_BASE_URL)

review_timeout_seconds=${LUAD_CLAUDE_REVIEW_TIMEOUT_SECONDS:-600}
if [[ ! "$review_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "LUAD_CLAUDE_REVIEW_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 2
fi
if command -v timeout >/dev/null 2>&1; then
  timeout_command=timeout
elif command -v gtimeout >/dev/null 2>&1; then
  timeout_command=gtimeout
else
  echo "GNU timeout is required for bounded Claude review stages" >&2
  exit 127
fi

run_bounded_review() {
  effort=$1
  shift
  "$timeout_command" --foreground --signal=INT --kill-after=5 "$review_timeout_seconds" \
    "${clean_env[@]}" claude "${common[@]}" --effort "$effort" "$@"
}

case "$stage" in
  design-review)
    run_bounded_review medium "${session_args[@]}" \
      --tools "" \
      --permission-mode plan
    ;;
  review-fresh|review-start|review-resume)
    run_bounded_review high "${session_args[@]}" \
      --tools "" \
      --permission-mode plan
    ;;
  acceptance-start|acceptance-resume)
    run_bounded_review high "${session_args[@]}" \
      --tools "" \
      --permission-mode plan
    ;;
esac
