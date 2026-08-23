# Coding-agent execution plan

Status: authoritative forward plan for the first evidence-backed `luad` release.

Read with:

- [Product requirements](../PRD.md)
- [Architecture](../ARCHITECTURE.md)
- [Machine interface](MACHINE-INTERFACE.md)
- [TP-Link Lua 5.1 field requirements](FIELD-REPORT-TP-LINK-LUA51.md)
- [Release procedure](RELEASING.md)

This document is the sole implementation sequence.

## 1. Release outcome

The first release candidate must provide a reliable, composable CLI for Lua
reverse engineering with:

- exact, evidence-backed parsing and public disassembly for official Lua 5.4.8;
- explicit Lua 5.1 layouts and vendor profiles needed for embedded firmware;
- correct closure-capture facts and public constant resolution;
- deterministic text and structured output for humans and AI agents;
- capability claims derived only from verified gate artifacts.

Lua 5.2, 5.3, and 5.5 remain experimental. Runtime verification of semantic
effects remains a separate project. `luad` does not own researcher sessions,
hypotheses, project databases, or autonomous interpretation.

## 2. Current proof boundary

The following foundations are accepted and should be preserved:

- truthful containment: all stock dialects remain experimental;
- the executable gate harness and tamper-checked result artifacts;
- the exact Lua 5.4.8 typed listing oracle and its independent reference decoder.

The next release blocker is the public boundary. The Lua 5.4.8 oracle verifies
raw instruction facts, while `luad disasm` still renders some signed operands
through generic opcode-mode formatting. Lua 5.1 closure and resolved-constant
gates likewise exercise internal facts without proving their required CLI and
machine output.

No promotion gate may pass until these public boundaries are covered.

## 3. Operating rules

1. Write each adversarial probe first and record its failure before changing implementation.
2. A public claim requires a test at the public CLI or schema boundary. Internal tests may support that evidence but may not substitute for it.
3. Commands are passed as argv arrays. Required tests, compilers, fixtures, and profiles may not skip.
4. Gate results require a clean source revision, exact tool identities, exact fixture hashes, and validated prerequisite results.
5. Preserve raw encoded facts separately from interpreted and displayed values.
6. The production decoder, semantic layer, and renderer must not use the independent oracle implementation.
7. The independent oracle must not import production opcode tables, decoders, lifters, or renderers.
8. Do not broaden an exact patch or vendor-profile result into a family claim.
9. Keep physical bytecode records distinct from executable semantic instructions.
10. Static effect claims are `reviewed` or `unverified` until an instrumented-runtime gate exists.
11. Machine output is a product API: deterministic, schema-governed, bounded, and free of commentary on stdout.
12. Make the smallest commit that closes one work package. Stop at every checkpoint below.

## 4. Gate artifact contract

Every canonical gate has exactly one committed `GateSpec` and one canonical
wrapper script. The wrapper invokes the production gate runner, emits a fresh
`GateResult`, verifies it, and makes its artifacts available for release-manifest
assembly.

Each result records:

- canonical spec hash;
- source revision and dirty state;
- exact argv and process result;
- enumerated, passed, failed, ignored, and missing tests;
- compiler/runtime path, exact version, and SHA-256 when applicable;
- fixture and profile paths and SHA-256 values;
- platform, architecture, timestamps, and output hashes;
- prerequisite result hashes;
- success derived by the runner.

Aliases that bypass this contract are removed. Generated evidence consumes only
verified results; scripts may not hardcode successful booleans.

## 5. Required order

```text
C0 truth and gate hygiene
  -> R6 public Lua 5.4.8 disassembly conformance
       -> checkpoint R6
       -> R3 CFG/precondition review
       -> R4 lossless-model review

C0
  -> F1 Lua 5.1 layout/profile review
       -> F2 public closure bindings
       -> F3 public resolved operands for Lua 5.1 and Lua 5.4
       -> F4 reproducible field evidence

R3 + R4 + R6 + F1 + F2 + F3 + F4
  -> R5 release promotion
```

Do not add dialects, decompiler features, overlays, persistence, or neighborhood
work while this critical path is open.

## 6. C0 — truthful public claims and canonical gates

### Work

- Change `explain` static-effect confidence from `Fact` to `reviewed` or `unverified`.
- Pin official-source citations to an exact Lua release and source path, or remove them from public output.
- Delete `scripts/generate_evidence.py` or make it consume verified `GateResult` artifacts exclusively.
- Establish one-to-one naming between canonical scripts and specs.
- Remove the duplicate CFG, operand, corpus, and field-evidence wrapper aliases.
- Add a consistency test that rejects a plan gate whose canonical spec omits a named required probe.
- Keep every dialect experimental and every unreviewed `completed_gates` list empty.

### Required probes

- No public `Confidence: Fact` appears for static effects without the runtime gate.
- A hardcoded successful evidence boolean cannot affect capabilities or promotion.
- Every canonical wrapper resolves to exactly one committed spec with the same gate ID.
- An orphan wrapper or duplicate canonical gate ID fails the consistency test.

### Acceptance

```console
cargo test -p luad-oracle --test test_cli_e2e
cargo test -p luad-oracle --test test_gate_harness
bash scripts/gates/gate-proof-harness.sh
```

## 7. R6 — public Lua 5.4.8 disassembly conformance

### Design boundary

Create a typed production disassembly record owned by a reusable library layer,
not by the text renderer. It contains:

- physical PC and semantic role;
- opcode identity;
- encoded operands;
- interpreted signed operands;
- `k`, Ax/Bx, and companion information;
- resolved constant/prototype/upvalue IDs where applicable;
- typed exact values and bounded display previews;
- source line and resolved jump target;
- confidence and provenance.

Text, JSON, JSONL, `explain`, and relevant xref views consume this shared record.
The CLI renderer must not independently decode raw words by generic opcode mode.

### Three-way proof

For every instruction in all ten maintained Lua 5.4.8 fixtures, require agreement
between three independent paths:

1. the exact `luac -l -l` listing parsed into typed expected fields;
2. the independently transcribed Lua 5.4.8 reference decoder;
3. the production decoder/lifter/public disassembly record exposed through CLI JSON.

The production and reference paths must use separate opcode/bitfield authorities.
Add normalized text goldens for `luad disasm` as a second public check. Normalize
only intentional presentation differences such as headings and zero-based PCs;
do not normalize operand values, types, lines, targets, or resolved facts.

### Required output behavior

- Render each opcode according to its typed operand kinds, not only `OpMode54`.
- Render signed `sB`, `sC`, `sBx`, and `sJ` values with the official biases.
- Render `k` in the opcode-specific canonical position.
- Omit fields that the opcode does not expose; do not print generic zero operands.
- Include per-instruction source lines where present.
- Include resolved jump targets and metamethod annotations.
- Resolve constant-bearing Lua 5.4 operands while retaining encoded indices.
- Emit exact typed constant values in machine output and safely bounded previews in text.

### Killer probes

- `GTI 1 0 0`, `ADDI 1 1 -5`, `MMBINI 1 5 7 0`, and `EQI 1 15 1` must match the official control-flow listing.
- Mutate only the production signed-operand mapping; the independent and `luac` sides stay equal and the gate fails at the public record.
- Mutate only the text renderer; typed JSON remains correct and the text golden fails.
- Mutate only JSON serialization; text remains correct and the machine comparison fails.
- Remove a jump target, source line, constant object, or `k` flag; the corresponding public-boundary probe fails.
- Unknown opcodes and invalid operand references produce structured diagnostics, never fabricated output.

### Canonical gate

Create:

```console
bash scripts/gates/gate-public-disasm-lua54-8.sh
```

Its spec must pin Lua 5.4.8, the compiler binary, all ten fixtures, the public
schema version, and every probe above. Add it as a prerequisite of the release gate.

### Checkpoint R6

Provide the exact text and JSON records for the four signed-immediate examples,
the three-way comparison summary for all fixture instructions, compiler and
fixture hashes, the verified gate result, and the failing output from each killer probe.

## 8. R3 — CFG, dominators, and analysis preconditions

Treat the existing implementation as unreviewed until this checkpoint passes.

### Required proof

- Exercise a graph-level API independent of Lua decoding.
- Assert complete dominator sets and exact immediate dominators for linear,
  diamond, loop, nested-branch, multiple-exit, unreachable, and irreducible graphs.
- Reject out-of-range registers, constants, upvalues, register ranges, jumps,
  companions, and non-executable targets before analysis.
- Add one public JSON or DOT golden demonstrating the production CFG boundary.

### Canonical gate

Use one script/spec pair named `gate-analysis-r3`. Remove the duplicate CFG alias.

### Checkpoint R3

Provide the full expected dominator trees, invalid-precondition diagnostics, and
the public CFG golden.

## 9. R4 — Lua 5.4.8 model serialization and byte accounting

Treat the existing writer and ledger as unreviewed until this checkpoint passes.

### Required proof

- Clear aggregate captured raw spans; serialization remains byte-identical.
- Mutate a modeled instruction and constant; bytes change at the expected spans
  and reparse to the mutation.
- Prove non-overlapping, gap-free classified coverage from byte zero to EOF.
- Reject an internal gap, overlap, or duplicate coverage with equal summed length.
- Cover debug, stripped, nested, embedded-NUL, NaN payload, infinity, and signed-zero inputs.
- Expose the round-trip/ledger verdict through a public validation record.

### Canonical gate

```console
bash scripts/gates/gate-lossless-lua54-8.sh
```

### Checkpoint R4

Provide byte-identical artifacts, mutation diffs, ledger summaries, and the
public validation record.

## 10. F1 — Lua 5.1 layouts and explicit profiles

Treat present layout/profile code as unreviewed until both canonical gates pass.

### Required proof

- One immutable `ChunkLayout` drives byte order and all declared widths.
- Real official 32-bit and 64-bit `size_t` fixtures pass in debug and stripped forms.
- Unsupported byte-order/number combinations fail at the exact header field.
- LNUM is a pinned explicit profile with exact integer representation and raw bytes.
- Stock/LNUM cross-profile negatives fail.
- Diagnostics preserve the deepest byte offset and structural context.
- Text and machine output expose the resolved layout and profile.

### Canonical gates

```console
bash scripts/gates/gate-layout-lua51-stock.sh
bash scripts/gates/gate-profile-lua51-lnum.sh
```

### Checkpoint F1

Provide toolchain hashes, fixture provenance, the supported layout matrix,
cross-profile failures, and public layout/profile output.

## 11. F2 — public Lua 5.1 closure bindings

### Work

- Preserve descriptor words and physical PCs with a `closure_binding` role.
- Attach ordered capture bindings to the owning `CLOSURE`.
- Exclude descriptors from executable disassembly rows, effects, CFG nodes,
  instruction queries, and standalone explanations.
- Render each binding as `upvalue[i] <- parent Rn` or
  `upvalue[i] <- parent upvalue[n]` beneath the owning closure.
- Add forward and inverse capture xrefs across nested prototypes.
- Validate descriptor count/opcode, source ranges, truncation, overlap, and jumps into descriptors.

### Killer probes

- The closures fixture contains no standalone descriptor `MOVE` or `GETUPVAL` row.
- Text and JSON expose the same ordered binding records.
- A descriptor has no standalone reads/writes and no CFG node.
- Querying either side of a binding returns the other side.
- A register-to-child-to-grandchild capture chain is traversable mechanically.
- Every malformed descriptor-group class returns a stable diagnostic at its physical PC.

### Canonical gate

```console
bash scripts/gates/gate-closures-lua51.sh
```

The spec must enumerate the public text, JSON, query, xref, CFG, and malformed-group probes.

### Checkpoint F2

Provide closure rows, JSON binding objects, forward/inverse xrefs, chain traversal,
and malformed-group diagnostics.

## 12. F3 — public resolved operands for Lua 5.1 and Lua 5.4

Use the typed production disassembly record introduced by R6.

### Work

- Resolve `LOADK`, globals, every RK-capable form, tables, comparisons,
  arithmetic, and profile-specific numeric constants.
- Preserve the encoded index, stable constant ID, exact typed value, tag/profile,
  raw representation, and safely escaped bounded preview.
- Make text, JSON/JSONL, `explain`, xrefs, and queries consume the same operand object.
- Replace missing-constant-to-`nil` fallbacks with invalid-operand diagnostics.

### Killer probes

- Lua 5.1 `LOADK 1 1` includes the encoded index and resolved string on the same row.
- A global shows its encoded constant index and resolved name.
- Control characters, invalid UTF-8, quotes, backslashes, and long keys are escaped and bounded.
- JSON exposes a typed value; no machine consumer must parse text previews.
- The same operand object agrees across disassembly, explanation, xrefs, and query.
- Invalid indices never render as `nil`.
- Equivalent Lua 5.4 constant-bearing instructions meet the same contract.

### Canonical gate

```console
bash scripts/gates/gate-resolved-constants-lua51.sh
```

Extend its spec or add a precisely named Lua 5.4 companion spec. Remove the
non-artifact `gate-operands-lua51.sh` alias.

### Checkpoint F3

Provide exact text and JSON for string, global, RK, hostile-string,
profile-integer, invalid-index, and Lua 5.4 cases.

## 13. F4 — reproducible embedded-field evidence

### Work

- Maintain redistributable minimized fixtures for 32-bit `size_t`, LNUM tags,
  closure bindings, error offsets, and resolved constants.
- Run the private 252-file corpus externally under its exact F1 profile.
- Record aggregate corpus hashes, source revision, tool/profile identities,
  layout distribution, parse/validation counts, diagnostics, and resource use.
- Keep private evidence supplemental; every disclosed defect needs a public reproducer.
- Never describe parse/validation counts as semantic correctness.

### Canonical gate

Create one script/spec pair named:

```console
bash scripts/gates/gate-field-reproducers-lua51.sh
```

Remove the generic corpus and duplicate field-evidence aliases.

### Checkpoint F4

Provide the public reproducer manifest and a reproducible private-corpus report template.

## 14. R5 — evidence-derived release promotion

R5 is last. Its prerequisite closure must include R1, R2, R3, R4, R6, F1,
F2, F3, and F4 results from one clean source revision.

### Required proof

- Assemble the release manifest from verified result hashes only.
- Derive capabilities and README status from the verified manifest.
- Promote only exact releases/layouts/profiles represented in the prerequisite results.
- Keep runtime semantic effects unverified.
- Reject missing, stale, dirty, mutated, or cross-revision prerequisite artifacts.
- Reject any standalone JSON or source edit that attempts to promote support.

### Canonical gate

```console
bash scripts/gates/gate-release-lua54-8.sh
```

Rename it when the release scope includes the required Lua 5.1 profiles; the
gate ID and documentation must describe the same promotion boundary.

### Checkpoint R5

Provide the clean source revision, every prerequisite hash, the release-manifest
hash, exact promoted fields, and remaining experimental capabilities.

## 15. Deferred work

### Runtime semantic-effect evidence

Instrument a pinned official Lua runtime, execute fast and metamethod paths, log
actual register/stack/upvalue accesses, and compare them with static declarations.
Until this gate exists, static effects are not `Fact`.

### Composable research workflows

After R5, implement exact retrieval, presentation-only overlays, deterministic
full-fidelity export, and only then bounded neighborhood traversal if a concrete
workflow requires it. Persistent interpretation remains external to `luad`.

## 16. Required checkpoint handoff

Every checkpoint reports:

- exact clean source revision;
- gate ID, spec path, and spec SHA-256;
- exact command argv;
- enumerated positive and adversarial tests;
- red-before and green-after output;
- compiler/runtime and fixture/profile identities;
- passed, failed, ignored, and missing-test counts;
- result artifact path and SHA-256;
- exact capability fields changed, or `none`;
- remaining red gates and limitations.

“All tests pass” is not a checkpoint handoff.

## 17. First release-candidate definition

The first release candidate is eligible only when:

- all checkpoints in the required order are reviewed;
- public text and machine output satisfy R6, F2, and F3;
- exact support scope is derived from one verified release manifest;
- every advertised layout/profile has redistributable fixtures and provenance;
- unsupported dialects and unverified semantic effects remain explicit;
- `bash scripts/check.sh`, maintained fuzz jobs, and every canonical gate pass on
  the release revision.

Repository health is necessary evidence. It is never a substitute for a named gate.
