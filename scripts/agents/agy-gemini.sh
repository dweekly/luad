#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/agents/agy-gemini.sh config
  scripts/agents/agy-gemini.sh access
  scripts/agents/agy-gemini.sh plan PROMPT_FILE
  scripts/agents/agy-gemini.sh implement PROMPT_FILE
  scripts/agents/agy-gemini.sh resume-plan CONVERSATION_ID PROMPT_FILE
  scripts/agents/agy-gemini.sh resume CONVERSATION_ID PROMPT_FILE
  scripts/agents/agy-gemini.sh interactive-plan PROMPT_FILE
  scripts/agents/agy-gemini.sh interactive-implement PROMPT_FILE
  scripts/agents/agy-gemini.sh interactive-resume-plan CONVERSATION_ID PROMPT_FILE
  scripts/agents/agy-gemini.sh interactive-resume CONVERSATION_ID PROMPT_FILE

Runs one Antigravity turn in the current worktree using the Gemini 3.7 Flash High
model variant. Non-interactive results are JSON containing the conversation ID,
duration, and token usage. Pass that ID to `resume` so later checkpoints retain the
same conversation. The sandbox remains enabled. Wall time, prompt hash, and the
Antigravity log path are printed to stderr when the turn exits. Set LUAD_AGY_LOG_FILE
to choose the log location.

The interactive stages preserve the same model variant, mode, sandbox, and conversation
rules while allowing narrowly reviewed file permissions when print mode fails closed.
`config` prints the pinned model, reasoning source, and workspace controls without
starting a model turn. `access` prints Antigravity's effective configuration and
permission records for review without starting a model task.
EOF
}

model=gemini-3.7-flash-high
reasoning=high-model-variant

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
fi

if [[ ${1:-} == "config" ]]; then
  printf 'model=%s\nreasoning=%s\nworkspace=git-worktree\nsandbox=enabled\n' \
    "$model" "$reasoning"
  exit 0
fi

if ! command -v agy >/dev/null 2>&1; then
  echo "agy is not installed or not on PATH" >&2
  exit 127
fi

if [[ ${1:-} == "access" ]]; then
  echo "==> Antigravity configuration" >&2
  agy -p '/config' --output-format json
  echo "==> Antigravity permissions" >&2
  agy -p '/permissions' --output-format json
  exit 0
fi

if ! worktree_root=$(git rev-parse --show-toplevel 2>/dev/null); then
  echo "run the Antigravity wrapper from a Git worktree" >&2
  exit 2
fi

stage=${1:-}
case "$stage" in
  plan|implement|interactive-plan|interactive-implement)
    prompt_file=${2:-}
    conversation_args=()
    ;;
  resume-plan|resume|interactive-resume-plan|interactive-resume)
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
if [[ "$stage" == "implement" || "$stage" == "resume" || \
  "$stage" == "interactive-implement" || "$stage" == "interactive-resume" ]]; then
  mode=accept-edits
fi

interactive=false
if [[ "$stage" == interactive-* ]]; then
  interactive=true
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

common=(
  "${conversation_args[@]}"
  --add-dir "$worktree_root"
  --model "$model"
  --mode "$mode"
  --sandbox
  --log-file "$log_file"
)

if [[ "$interactive" == true ]]; then
  agy "${common[@]}" --prompt-interactive "$prompt"
else
  agy "${common[@]}" --print "$prompt" --output-format json
fi
