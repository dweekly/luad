#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/agents/claude-opus.sh design-review PROMPT_FILE
  scripts/agents/claude-opus.sh review-fresh PROMPT_FILE
  scripts/agents/claude-opus.sh acceptance-start PROMPT_FILE
  scripts/agents/claude-opus.sh acceptance-resume SESSION_ID PROMPT_FILE

Runs Claude Opus through the logged-in claude.ai subscription. Console API
credentials are removed from the child environment so they cannot silently
override the subscription. Output is streaming Claude Code NDJSON; the final
`result` event carries cumulative session usage. Set LUAD_CLAUDE_DEBUG_FILE to
choose the detailed CLI debug log. Read-only review stages use medium effort and
a 180-second wall-time ceiling by default; set LUAD_CLAUDE_REVIEW_TIMEOUT_SECONDS
to a positive integer to change that ceiling.

review-fresh       Independent read-only review with no persisted session.
design-review      Critique a self-contained design without repository tools.
acceptance-start   Start a persistent acceptance-author session.
acceptance-resume  Inject a checkpoint into that same session.

Acceptance sessions permit repository reads and file edits but no shell. The
steward runs focused tests after each durable edit checkpoint.
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
if [[ "$stage" == "design-review" ]]; then
  prompt=$'This is a no-tools review. Analyze only the supplied prompt. Do not claim to inspect a repository, invoke tools, delegate work, or invent missing implementation details. Treat missing context as an explicit ambiguity.\n\n'"$prompt"
fi
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

common=(
  -p "$prompt"
  --model opus
  --safe-mode
  --autocompact 1M
  --strict-mcp-config
  --mcp-config '{"mcpServers":{}}'
  --disable-slash-commands
  --no-chrome
  --prompt-suggestions false
  --debug-file "$debug_file"
  --verbose
  --output-format stream-json
)
clean_env=(env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_BASE_URL)

review_timeout_seconds=${LUAD_CLAUDE_REVIEW_TIMEOUT_SECONDS:-180}
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
  "$timeout_command" --foreground --signal=INT --kill-after=5 "$review_timeout_seconds" \
    "${clean_env[@]}" claude "${common[@]}" --effort medium "$@"
}

case "$stage" in
  design-review)
    run_bounded_review "${session_args[@]}" \
      --tools "" \
      --permission-mode plan
    ;;
  review-fresh)
    run_bounded_review "${session_args[@]}" \
      --tools "Read,Glob,Grep" \
      --permission-mode plan \
      --allowedTools "Read,Glob,Grep"
    ;;
  acceptance-start|acceptance-resume)
    allowed="Read,Glob,Grep,Edit,Write"
    "${clean_env[@]}" claude "${common[@]}" --effort high "${session_args[@]}" \
      --tools "Read,Glob,Grep,Edit,Write" \
      --permission-mode dontAsk \
      --allowedTools "$allowed"
    ;;
esac
