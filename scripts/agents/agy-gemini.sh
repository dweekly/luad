#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/agents/agy-gemini.sh plan PROMPT_FILE
  scripts/agents/agy-gemini.sh implement PROMPT_FILE
  scripts/agents/agy-gemini.sh resume CONVERSATION_ID PROMPT_FILE

Starts a scoped interactive Antigravity session in the current worktree using
Gemini 3.7 Flash High. The sandbox remains enabled and permission prompts remain
active. Trust only the isolated sprint worktree and approve only commands named
by the sprint prompt. Wall time and the Antigravity log path are printed when the
session exits. Set LUAD_AGY_LOG_FILE to choose the log location.
EOF
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
fi

if ! command -v agy >/dev/null 2>&1; then
  echo "agy is not installed or not on PATH" >&2
  exit 127
fi

stage=${1:-}
case "$stage" in
  plan|implement)
    prompt_file=${2:-}
    conversation_args=()
    ;;
  resume)
    conversation_id=${2:-}
    prompt_file=${3:-}
    if [[ ! "$conversation_id" =~ ^[a-zA-Z0-9-]+$ ]]; then
      echo "invalid conversation ID" >&2
      exit 2
    fi
    conversation_args=(--conversation "$conversation_id")
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if [[ -z "${prompt_file:-}" || ! -f "$prompt_file" ]]; then
  usage >&2
  exit 2
fi

prompt=$(<"$prompt_file")
mode=plan
if [[ "$stage" == "implement" || "$stage" == "resume" ]]; then
  mode=accept-edits
fi

started_at=$(date +%s)
log_file=${LUAD_AGY_LOG_FILE:-/tmp/luad-agy-${started_at}.log}
prompt_sha256=$(shasum -a 256 "$prompt_file" | awk '{print $1}')

finish() {
  status=$?
  finished_at=$(date +%s)
  echo "agy_prompt_sha256=$prompt_sha256" >&2
  echo "agy_wall_seconds=$((finished_at - started_at))" >&2
  echo "agy_log_file=$log_file" >&2
  exit "$status"
}
trap finish EXIT

agy "${conversation_args[@]}" \
  --model gemini-3.7-flash-high \
  --effort high \
  --mode "$mode" \
  --sandbox \
  --log-file "$log_file" \
  --prompt-interactive "$prompt"
