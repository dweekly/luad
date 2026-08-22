# Coding-agent plan: restore trustworthy facts before adding features

## Objective

Turn the current broad implementation into an evidence-backed Lua bytecode tool by fixing the confirmed defects, repairing the proof apparatus, and making support claims derive from passing gates.

This plan is intentionally ordered. Do not begin composable-workflow features, new dialects, decompilation, or persistent state until the fact-layer gates are complete.

Primary references:

- [Correctness review](REVIEW-2026-08-22.md)
- [Architecture and invariants](../ARCHITECTURE.md)
- [Product requirements](../PRD.md)
- [Roadmap](../ROADMAP.md)

## Working-tree warning

The worktree contains uncommitted documentation plus partial infrastructure edits made during onboarding work. Start every coding turn with:

```console
git status --short
git diff --stat
git diff
```

Do not reset or overwrite these changes. Audit them individually.

Partial infrastructure changes expected in the tree include:

- a pinned development toolchain and workspace `rust-version` edits;
- `scripts/check.sh`;
- CI consolidation around that script;
- a fail-closed official-compiler installer updated toward Lua 5.4.8/5.5.1;
- Lua 5.4/5.5 `/tmp` compiler lookup paths;
- a standalone fuzz workspace fix.

Disposition:

| Change | Guidance |
|---|---|
| Remove CI `|| true` | Keep |
| Install exact 5.4.8 and 5.5.1 | Keep after verifying official releases and hashes |
| Fail when compiler build/version check fails | Keep |
| `/tmp/lua-tools/bin` lookup paths | Keep or replace with an explicit environment variable/PATH contract |
| Fuzz `[workspace]` isolation | Keep if `cargo check --manifest-path fuzz/Cargo.toml` passes |
| `scripts/check.sh` | Keep concept; make executable and separate aggregate checks from proof gates |
| Rust 1.97.1 toolchain pin | Keep only if intentionally selected for reproducible development |
| `rust-version = 1.97.1` | Reconsider; this declares MSRV and must be independently established |
| Compiler downloads | Add pinned SHA-256 verification before extraction |

## Operating rules

1. One proof gate per focused change or commit.
2. Add the failing positive case and a negative control before fixing production code.
3. Never report completion if a required test skipped.
4. Preserve raw encoded values separately from interpreted values.
5. Do not update capability support tiers until evidence gates pass.
6. Do not broaden refactors while repairing a gate unless necessary to make the gate testable.
7. Record official-source references and exact fixture/tool hashes in test evidence.

## Gate 0: Downgrade unsupported claims immediately

### Purpose

Prevent callers from treating implemented surface as verified support during remediation.

### Work

- Replace string support statuses with an enum such as `experimental`, `supported`, and `planned`.
- Mark Lua 5.1–5.5 experimental.
- Remove or clearly mark unverified prose evidence.
- Ensure text and JSON capabilities derive from one data structure.
- Add a test asserting that no dialect becomes `supported` without required evidence gate IDs.
- Keep the README support table consistent with the manifest.

### Acceptance

- `luad capabilities --format json --evidence` makes no false field-by-field or semantic-effect claim.
- A unit test fails if a dialect is marked supported with an empty or incomplete gate set.
- Text and JSON list identical statuses.

## Gate 1: Make the differential oracle detect errors

### Purpose

An oracle that cannot detect a deliberately introduced error is not a gate.

### Design

Refactor `assert_chunk_matches_luac` into two layers:

1. Normalize `luad` facts and `luac -l -l` output into comparable test-only records.
2. Return structured mismatches instead of asserting inline.

Suggested shape:

```rust
enum OracleMismatch {
    PrototypeCount { actual: usize, expected: usize },
    Metadata { proto: usize, field: String, actual: String, expected: String },
    Mnemonic { proto: usize, pc: usize, actual: String, expected: String },
    Operand { proto: usize, pc: usize, index: usize, actual: String, expected: String },
    Constant { proto: usize, index: usize, actual: String, expected: String },
    DebugInfo { proto: usize, field: String, actual: String, expected: String },
}
```

Use typed normalized operands where practical. Avoid comparing whitespace-sensitive listing strings when the format can be parsed into integers, constants, flags, or jump destinations.

### Work

- Parse and compare mnemonic at every PC.
- Parse and compare all operands according to the selected dialect and opcode mode.
- Preserve both encoded and interpreted signed operands in the actual representation.
- Parse constant tags and values into normalized types:
  - nil;
  - boolean;
  - integer;
  - float with exact bit handling where the listing permits;
  - byte string with unambiguous escaping.
- Continue comparing prototype metadata, line information, locals, and upvalues.
- Make diagnostics identify dialect, prototype path, PC, raw word, and differing field.

### Required negative controls

Tests must construct a valid normalized comparison pair and then independently perturb:

1. one mnemonic;
2. one operand value or field position;
3. one constant tag/value;
4. one debug/local field.

Each mutation must produce the expected `OracleMismatch` variant. A test that only expects “some panic” is insufficient.

### Acceptance

- Negative controls fail when the comparator is intentionally weakened.
- The current Lua 5.4 decoder fails the corrected oracle before its fix.
- Missing expected instructions or extra instructions fail clearly.
- No parsed `mnemonic`, `operands_raw`, or constant value field remains unused by comparison.

Suggested CI job: `gate-oracle-negative-controls`.

## Gate 2: Correct and prove Lua 5.4 instruction facts

### Confirmed fixes

In `luad-dialect-lua54`:

- Decode `k` from bit 15.
- Decode `B` from bits 16–23.
- Decode `C` from bits 24–31.
- Correct comments and schemas describing those fields.
- Add signed `sB = B - 127` and `sC = C - 127` while retaining raw `B` and `C`.
- Mark `EQI`, `LTI`, `LEI`, `GTI`, and `GEI` as `iABC`, not `IAsBx`.
- Audit every opcode mode against the exact official `lopcodes.h` release.

### Golden vectors

Add official/compiler-derived raw-word tests including the review's examples:

| Word | Expected interpretation |
|---|---|
| `0x050100a2` | `ADD 1 1 5` |
| `0x00010180` | `MOVE 3 1` |
| `0x01030146` | `RETURN 2 3 1` |

Also include immediate comparisons and positive/negative signed immediates.

### Round-trip property

Add an encoder used only for proof initially. It must be independently written from documented field positions, not call decoder helpers or share a possibly wrong layout table.

For applicable formats, test:

```text
encode(decode(word)) == word
```

over all opcode tables and a large/property-generated sample of `u32` words. Separate tests must verify semantic interpretation, because a mutually wrong encoder/decoder can still round-trip.

### Remove unsafe opcode conversion

Replace all five `unsafe { transmute }` conversions with exhaustive explicit or generated matches. Then add `#![forbid(unsafe_code)]` at crate roots and ultimately workspace-wide.

### Acceptance

- Golden raw words match official `luac -l -l` output.
- Corrected field-level oracle passes Lua 5.4 fixtures with zero unexplained mismatches.
- The old shifts or modes cause a negative regression test to fail.
- `cargo geiger` is optional evidence; `rg 'unsafe|transmute' crates` must find no production usage.

Suggested CI job: `gate-facts-lua54`.

## Gate 3: Make official compiler infrastructure mandatory and reproducible

### Installer

- Pin Lua 5.1.5, 5.2.4, 5.3.6, 5.4.8, and 5.5.1 only if those exact versions remain claimed.
- Record official archive URLs and independently verified SHA-256 values in one data file.
- Verify SHA-256 before extraction.
- Fail on download, checksum, extraction, build, missing binary, or version mismatch.
- Do not use `|| true` in compiler or CI proof paths.
- Prefer an explicit `LUAD_ORACLE_BIN_DIR` recognized by the oracle harness over scattered absolute-path guesses.

### Tests

- Required oracle tests must use `expect`/error on missing compilers, not return early.
- Print detected compiler paths and versions at gate start.
- Ensure CI runs field-by-field tests on Linux and macOS where the format depends on native representation.
- Keep bundled fixtures for safety/regression tests, but do not substitute them silently for an official differential gate.

### Fixture manifest

Create `tests/fixtures/precompiled/MANIFEST.json` with:

- exact source and output hashes;
- compiler archive URL/hash/version;
- platform/architecture/endianness;
- integer, instruction, and number sizes;
- strip flags;
- generator revision and command.

Mark historical unknowns as unknown and regenerate them under the verified process before using them as release evidence.

### Acceptance

- Breaking one archive checksum makes CI fail before build.
- Removing one compiler makes the appropriate oracle gate red.
- The manifest verifier detects a modified fixture.
- Capability evidence names the same versions actually executed.

Suggested CI jobs: `oracle-toolchains` and per-dialect oracle gates.

## Gate 4: Correct CFG dominators and validation preconditions

### Dominators

Fix the immediate-dominator rule: `idom(n)` is the strict dominator of `n` that is itself dominated by every other strict dominator of `n`.

Do not validate only by checking that an `idom` exists. Add hand-authored expected graphs for:

- a linear chain;
- a diamond;
- a loop with back edge;
- nested branches;
- multiple exits;
- unreachable blocks.

Test complete dominator sets and exact immediate dominators by stable block ID.

### Validation

- Classify out-of-range register references as errors, not warnings compatible with valid-for-analysis.
- Audit jump destinations, constant indices, upvalues, stack ranges, and top-dependent operands.
- Define the preconditions for CFG, xrefs, and semantic analysis.
- Refuse or explicitly mark unavailable any analysis whose preconditions fail.
- Add CLI tests for verdict and exit code.

### Acceptance

- The current “all reachable blocks have `idom=b0`” behavior fails a golden test.
- The reviewed control-flow fixture reports its hand-authored dominator tree.
- The misdecoded out-of-range register fixture cannot return valid-for-analysis.

Suggested CI job: `gate-analysis-cfg`.

## Gate 5: Prove losslessness with a serializer

### Purpose

Replace cursor-derived byte-count equality with a real reconstruction proof.

### Work

- Implement a dialect writer beginning with Lua 5.4.
- Serialize parsed valid chunks without normalization.
- Preserve unknown/uninterpreted bytes explicitly where the format permits.
- Add a byte-classification ledger with non-overlapping ranges:
  - recognized field;
  - padding/alignment;
  - preserved uninterpreted;
  - diagnosed trailing.
- Assert complete coverage with no gaps or overlaps.

### Tests

- Debug and stripped fixtures.
- Nested prototypes, all constant types, embedded NUL, numeric extremes, and line-info variants.
- `parse → serialize` byte identity.
- `parse → serialize → parse` structural identity.
- Negative classification controls introducing a gap and overlap.

### Acceptance

- Every maintained valid fixture is byte-identical after serialization.
- Byte accounting is derived from classified fields, not only cursor start/end positions.

Suggested CI job: `gate-lossless-lua54`.

## Gate 6: Verify or downgrade semantic effects

### Preferred oracle

Build a test-only instrumented official Lua VM. Keep the patch and its upstream source/archive hash under oracle test infrastructure.

For each executed instruction, log:

- prototype/function identity and PC;
- opcode and raw word;
- stack/register slots read and written;
- upvalues read and written;
- table/global access where observable;
- top before/after for variable-range instructions;
- metamethod dispatch and called prototype where applicable.

### Comparison semantics

Static and dynamic effects are not always equal:

- Every observed runtime access must be permitted by the static effect declaration.
- Deterministic non-conditional instructions should generally match exactly.
- Conditional, range, top-dependent, and metamethod-capable instructions need explicit comparison rules.
- Fixtures must force normal and metamethod paths separately.

### Acceptance

- The corpus executes every supported opcode/effect form claimed by a dialect, or reports coverage gaps.
- An intentionally deleted read/write effect fails comparison.
- Capability evidence distinguishes executable effect coverage from source review.

Suggested CI job: `gate-effects-lua54`.

If this gate is deferred, downgrade effect-related features and documentation instead of treating code review as equivalent evidence.

## Gate 7: Evidence-backed capabilities and release status

### Evidence artifact

Use a machine-readable, versioned manifest committed or generated for a specific source revision. Include:

- source commit;
- tool/schema version;
- dialect and exact patch release;
- gate ID and result;
- compiler archive and binary hashes;
- platform and representation settings;
- fixture/corpus hashes;
- comparator/instrumentation version;
- timestamp and generation command.

CI must validate that embedded evidence matches the current source and expected fixtures. Runtime `capabilities` should embed verified evidence rather than construct claims from prose strings.

### Support policy

- `planned`: no complete implementation.
- `experimental`: implementation exists but one or more required gates are missing.
- `supported`: all required release gates pass for the exact advertised scope.

Patch ranges require per-patch evidence or a narrower claim.

### Acceptance

- Removing evidence or changing a fixture downgrades/fails support automatically.
- README and text/JSON capabilities cannot disagree.
- Release procedure rejects unsupported claims.

Suggested CI job: `gate-release-evidence`.

## Gate 8: Repeat per dialect deliberately

Recommended order:

1. Lua 5.4
2. Lua 5.5
3. Lua 5.1
4. Lua 5.3
5. Lua 5.2

Do not mechanically copy the 5.4 gate and assume equivalence. Each dialect needs its own official layout audit, golden words, negative controls, compiler evidence, round-trip proof, and validator preconditions.

Before expanding beyond 5.4/5.5, resolve the product-positioning decision in `ROADMAP.md`; a practical reverse-engineering tool may prioritize LuaJIT and Luau instead.

## Deferred: composable research workflows

After the factual gates are trustworthy, revise and implement the proposal in this order:

1. `get` as the exact retrieval primitive; implement `explain` as a renderer over it.
2. Interpretation-scoped references containing artifact hash, dialect/profile, parse mode, and configuration identity.
3. Read-only overlays with strict escaping and explicit unresolved-target policy.
4. Deterministic full-fidelity `export --format jsonl` for external indexes.
5. Consider a command named `neighborhood` or `expand` only if a real workflow cannot be served efficiently by export.

No new command may expose a factual claim not covered by a passing oracle gate.

## Proposed CI topology

Use separate jobs with readable names and artifacts:

```text
static
oracle-toolchains
gate-oracle-negative-controls
gate-facts-lua54
gate-analysis-cfg
gate-lossless-lua54
gate-effects-lua54          # may initially report not implemented, never supported
fuzz-build
fuzz-regression-corpus
docs
gate-release-evidence
```

Add Lua 5.5 and other dialect jobs only as their gates are implemented. An aggregate `scripts/check.sh` remains useful for contributors but must not collapse distinct evidence into one undifferentiated green check.

## Final handoff requirements

For every completed gate, report:

- files changed;
- defect or claim addressed;
- negative control added;
- exact command run;
- compiler versions and paths;
- number of tests and whether any skipped;
- evidence artifact produced;
- remaining unsupported or experimental behavior.

Do not report “production grade” until the release-evidence gate passes for a precisely stated support scope.
