# Instructions for coding agents

This repository analyzes potentially hostile Lua bytecode. Correctness, evidence, and bounded behavior take priority over feature velocity.

## Required reading

Before modifying correctness-sensitive code, read:

1. `docs/REVIEW-2026-08-22.md`
2. `docs/CODING-AGENT-PLAN.md`
3. `ARCHITECTURE.md`
4. `CONTRIBUTING.md`

## Current priority

The project is under a correctness stop line. Work the gates in `docs/CODING-AGENT-PLAN.md` in order. Do not add dialects, decompiler features, overlays, persistent state, or new capability claims until the fact-layer gates pass.

## Repository rules

- Preserve unrelated and pre-existing worktree changes.
- Never weaken or delete a failing correctness test merely to restore green CI.
- A required oracle may not skip when a compiler or fixture is absent.
- Every oracle/comparator needs a negative control proving that corruption is detected.
- Preserve raw encoded facts separately from interpreted values.
- Do not use `unsafe` for opcode conversion; move toward `#![forbid(unsafe_code)]`.
- Do not silently default an unknown dialect, target, schema, or analysis mode.
- Keep input, allocation, traversal, recursion, diagnostics, and output bounded.
- Do not update `supported` capability status without a passing named evidence gate.
- Machine stdout must remain deterministic and free of commentary.
- Treat fixture binaries and evidence manifests as generated evidence with recorded provenance.

## Verification

Run the narrowest relevant test while iterating, then the named gate from the coding plan. Before declaring a task complete, run:

```console
bash scripts/check.sh
```

This aggregate check is necessary but not sufficient. Report which named oracle or analysis gate passed, which official compiler versions were present, and whether any tests skipped. “All tests pass” is not an adequate handoff by itself.

## Documentation

Keep documentation honest about current behavior. Link claims to evidence; do not promote roadmap intent into present-tense support. If code and documentation disagree, either correct the code in scope or downgrade the claim explicitly.
