# Instructions for coding agents

This repository analyzes potentially hostile Lua bytecode. Correctness, evidence, and bounded behavior take priority over feature velocity.

## Required context

Read `docs/NEXT-SPRINT.md` and the exact production and test paths named by the task.
For a patch-lane task, the steward's prompt supplies the relevant repository invariants;
do not reread the full documentation set unless the change crosses one of its boundaries.

For semantic or qualification work, also read `docs/DEVELOPMENT-WORKFLOW.md`,
`ROADMAP.md`, and the relevant architecture, machine-interface, firmware-requirement,
contributor, or release sections identified by the sprint contract.

## Current priority

Implement only the claim in `docs/NEXT-SPRINT.md` against its stated evidence boundary.
`ROADMAP.md` supplies direction but does not authorize adjacent work. Stop at the sprint
checkpoint and do not add dialects, decompiler features, persistent state, or
inference-heavy analysis unless the active sprint explicitly owns them.

## Repository rules

- Preserve unrelated and pre-existing worktree changes.
- Never weaken or delete a failing correctness test merely to restore green CI.
- A required oracle may not skip when a compiler or fixture is absent.
- Every oracle/comparator needs a negative control proving that corruption is detected.
- Preserve raw encoded facts separately from interpreted values.
- Never infer an artifact's layout from the build host: validate and honor declared widths and byte order, and gate vendor extensions behind explicit profiles.
- Preserve physical words separately from executable semantics; closure-binding descriptors must not acquire standalone instruction effects.
- Do not use `unsafe` for opcode conversion; move toward `#![forbid(unsafe_code)]`.
- Do not silently default an unknown dialect, target, schema, or analysis mode.
- Keep input, allocation, traversal, recursion, diagnostics, and output bounded.
- Do not update `supported` capability status without a passing named evidence gate.
- Machine stdout must remain deterministic and free of commentary.
- Treat fixture binaries and evidence manifests as generated evidence with recorded provenance.
- A gate's acceptance criteria must map to exact executable commands and assertions before implementation; source-text test-name presence and self-declared evidence are not proof.


## Verification

The implementation agent stops after a reviewable candidate diff. The steward runs the
narrowest relevant focused test, any named semantic or qualification gate, and the
aggregate check from the clean candidate. Patch work relies on one final CI aggregate
run after focused steward verification. For work outside these lanes, run:

```console
bash scripts/check.sh
```

This aggregate check is necessary but not sufficient. Report which named oracle or
analysis gate passed, which official compiler versions were present, and whether any
tests skipped. “All tests pass” is not an adequate handoff by itself. Do not duplicate
the steward's canonical or aggregate run unless explicitly asked.

## Documentation

Keep documentation honest about current behavior. Link claims to evidence; do not
promote roadmap intent into present-tense support. If code and documentation disagree,
either correct the code in scope or downgrade the claim explicitly.

- Every maintained Markdown document must appear in the documentation index in
  `README.md` with a summary, a last-fresh date, and a concrete revalidation or
  deletion trigger. Add, rename, move, or delete the index entry in the same change as
  the document.
- Plans and roadmaps contain only future obligations, decisions, dependencies, gates,
  and stop conditions. Remove accepted work instead of retaining completed checklists
  or comparisons with an earlier implementation.
- Implementation history belongs only in `CHANGELOG.md`, version release notes, pull
  requests, and Git commits. Requirements and reference documents describe the current
  truth and future needs.
- Code comments describe the present invariant, intent, safety condition, or externally
  relevant constraint. They do not narrate how the code differed in an earlier version.
- When a freshness trigger fires, update or delete the document before declaring the
  associated change complete. Deletion includes repairing the index and inbound links.
