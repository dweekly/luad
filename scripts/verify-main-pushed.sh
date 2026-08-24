#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [[ $(git branch --show-current) != "main" ]]; then
  echo "verification must run from the main branch" >&2
  exit 1
fi

if [[ -n $(git status --porcelain) ]]; then
  echo "main is dirty" >&2
  git status --short >&2
  exit 1
fi

git fetch --quiet origin main
local_head=$(git rev-parse HEAD)
remote_head=$(git rev-parse refs/remotes/origin/main)

if [[ "$local_head" != "$remote_head" ]]; then
  echo "local main ($local_head) does not match origin/main ($remote_head)" >&2
  exit 1
fi

echo "main is clean and matches origin/main at $local_head"
