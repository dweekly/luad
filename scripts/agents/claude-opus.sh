#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/agents/claude-opus.sh review-fresh PROMPT_FILE
  scripts/agents/claude-opus.sh acceptance-start PROMPT_FILE
  scripts/agents/claude-opus.sh acceptance-resume SESSION_ID PROMPT_FILE

Runs Claude Opus through the logged-in claude.ai subscription. Console API
credentials are removed from the child environment so they cannot silently
override the subscription. Output is streaming Claude Code NDJSON; the final
`result` event carries cumulative session usage. Set LUAD_CLAUDE_DEBUG_FILE to
choose the detailed CLI debug log.

review-fresh       Independent read-only review with no persisted session.
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
  --effort high
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

case "$stage" in
  review-fresh)
    "${clean_env[@]}" claude "${common[@]}" "${session_args[@]}" \
      --tools "Read,Glob,Grep" \
      --permission-mode plan \
      --allowedTools "Read,Glob,Grep"
    ;;
  acceptance-start|acceptance-resume)
    allowed="Read,Glob,Grep,Edit,Write"
    "${clean_env[@]}" claude "${common[@]}" "${session_args[@]}" \
      --tools "Read,Glob,Grep,Edit,Write" \
      --permission-mode dontAsk \
      --allowedTools "$allowed"
    ;;
esac
