# `luad` roadmap

This roadmap is evidence-gated. A milestone is complete only when its named CI jobs pass with no required skips; commit messages and feature presence do not establish completion.

## Current status: correctness stop line

No new dialect, decompiler, overlay, neighborhood, or persistence work should begin until Milestones 0–3 are complete. See [the 2026-08-22 review](docs/REVIEW-2026-08-22.md).

## Milestone 0: Make the proof system capable of failing

Goal: ensure the differential oracle detects incorrect decoded facts.

Required outcomes:

- Comparator checks mnemonic, operands, typed constants, prototype metadata, lines, locals, and upvalues.
- Comparison returns structured mismatches suitable for positive and negative tests.
- Negative controls prove that one corrupted mnemonic, operand, and constant each fail.
- Missing required official compilers fail the oracle gate.
- Lua archives and generated fixtures have recorded checksums and provenance.

Exit gate: `gate-oracle-negative-controls` and `gate-oracle-lua54` pass.

## Milestone 1: Restore trustworthy Lua 5.4 facts

Goal: establish one correct vertical slice before broadening claims.

Required outcomes:

- Correct `iABC` field positions and immediate-comparison modes.
- Preserve encoded and interpreted signed operands separately.
- Remove unsafe opcode conversion.
- Official instruction-word golden vectors pass.
- Independent encode/decode properties pass.
- Field-by-field `luac 5.4.8` comparison has zero unexplained mismatches.
- Out-of-range operands prevent valid-for-analysis verdicts.

Exit gate: `gate-facts-lua54` passes.

## Milestone 2: Restore trustworthy control-flow analysis

Goal: prove CFG and dominator results against explicit expectations.

Required outcomes:

- Immediate-dominator selection is corrected.
- Hand-authored CFG and dominator goldens cover straight-line, diamond, loop, nested branch, and unreachable-code cases.
- Invalid jump or instruction preconditions are rejected or surfaced as unavailable analysis.

Exit gate: `gate-analysis-cfg` passes.

## Milestone 3: Losslessness and byte accounting

Goal: replace cursor-derived accounting claims with executable round-trip evidence.

Required outcomes:

- Parse and serialize valid chunks byte-identically.
- Every input byte is classified as a recognized field, padding, preserved uninterpreted data, or diagnosed trailing data.
- Debug and stripped fixtures pass across the claimed Lua 5.4 range.

Exit gate: `gate-lossless-lua54` passes.

## Milestone 4: Lua 5.5 and additional stock dialects

Apply Milestones 0–3 independently to Lua 5.5. Only then reconsider Lua 5.1, 5.3, and 5.2 in that order. Each dialect remains `experimental` until its own gates pass.

Patch-range claims require evidence for every claimed patch release or must be narrowed to the exact tested releases.

## Milestone 5: Semantic-effect evidence

Goal: verify register reads/writes, ranges, multireturn, calls, and metamethod behavior independently of the lifter implementation.

Preferred mechanism: a test-only instrumented official Lua VM that logs actual stack-slot and upvalue effects per executed instruction.

Until this exists, semantic-effect capabilities must distinguish reviewed behavior from executable evidence.

## Milestone 6: Evidence-backed release contract

Required outcomes:

- Capability status derives from verified evidence artifacts.
- Evidence identifies gate, tool version, compiler archive hash, compiler version, platform, fixture hash, and result.
- README support status is generated from the same source.
- Release checks prohibit `supported` dialects without passing evidence.
- Security, machine-interface, and release docs describe actual behavior.

Exit gate: `gate-release-evidence` passes.

## Milestone 7: Composable research primitives

Only after the fact layer is trustworthy:

1. exact `get` retrieval, with `explain` implemented as a renderer;
2. presentation-only overlays with interpretation-scoped artifact references;
3. deterministic full-fidelity `export --format jsonl`;
4. bounded neighborhood traversal only after a concrete workflow demonstrates that export is insufficient.

No project database, session manager, hypothesis engine, or autonomous agent logic belongs in `luad`.

## Product-direction decision

Before work beyond stock Lua 5.4/5.5, decide explicitly whether `luad` primarily optimizes for:

- a correctness reference for stock Lua bytecode; or
- a practical reverse-engineering tool for prevalent ecosystems.

The second direction should prioritize LuaJIT and Luau ahead of low-usage stock dialect expansion. Record the decision in the PRD and this roadmap.
