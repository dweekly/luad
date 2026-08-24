#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/agents/claude-opus.sh readonly PROMPT_FILE
  scripts/agents/claude-opus.sh author PROMPT_FILE TEST_MODULE

Runs Claude Opus through the logged-in claude.ai subscription. Console API
credentials are removed from the child environment so they cannot silently
override the subscription. Output is Claude Code JSON.

readonly  Read-only outline or review with Read, Glob, and Grep.
author    Acceptance authorship with file edits and exactly one allowed command:
          cargo test -p luad-oracle --test TEST_MODULE -- --nocapture
EOF
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
fi

stage=${1:-}
prompt_file=${2:-}

if [[ -z "$stage" || -z "$prompt_file" || ! -f "$prompt_file" ]]; then
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
common=(
  -p "$prompt"
  --model opus
  --effort high
  --strict-mcp-config
  --mcp-config '{"mcpServers":{}}'
  --disable-slash-commands
  --no-chrome
  --output-format json
  --no-session-persistence
)
clean_env=(env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_BASE_URL)

case "$stage" in
  readonly)
    exec "${clean_env[@]}" claude "${common[@]}" \
      --permission-mode plan \
      --allowedTools "Read,Glob,Grep"
    ;;
  author)
    test_module=${3:-}
    if [[ ! "$test_module" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      echo "TEST_MODULE must contain only letters, digits, underscores, or hyphens" >&2
      exit 2
    fi
    allowed="Read,Glob,Grep,Edit,Write,Bash(cargo test -p luad-oracle --test $test_module -- --nocapture)"
    exec "${clean_env[@]}" claude "${common[@]}" \
      --permission-mode dontAsk \
      --allowedTools "$allowed"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
