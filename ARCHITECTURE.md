# `luad` architecture

## Purpose

`luad` turns compiled Lua bytecode into deterministic, inspectable facts. It does not own researcher judgment, project state, hypotheses, or agent planning.

The intended pipeline is:

```text
input bytes
  → bounded SafeReader
  → dialect detection and decoder
  → lossless Chunk model + provenance
  → dialect semantic lifter and validator
  → CFG / dominators / xrefs / query / diff
  → text, JSON, JSONL, or DOT renderer
```

Every arrow is a correctness boundary and must have explicit preconditions and independent tests.

## Crates

### `luad-core`

Owns shared factual types and parsing primitives: chunk models, stable IDs, provenance, diagnostics, resource limits, and `SafeReader`. It must not depend on a particular Lua dialect or presentation policy.

### Dialect crates

`luad-dialect-lua51` through `luad-dialect-lua55` own header detection, layout parsing, opcode fields and modes, signed-operand interpretation, semantic lifting, and dialect validation.

Similar-looking layouts are not evidence of equivalence. Shared helpers are appropriate only where official formats and independent tests establish the shared rule.

### `luad-analysis`

Consumes the shared model and semantic instructions to produce CFGs, dominators, xrefs, queries, and diffs. It must not reparse bytecode or silently select a default dialect.

Every analysis must state or enforce its preconditions. Invalid registers, jumps, stack references, or instruction modes can make analysis unavailable rather than merely less precise.

### `luad-cli`

Owns command parsing, bounded input ingestion, exit behavior, schema export, and rendering. It should remain thin; reusable behavior belongs in library crates.

Machine output is a product API. JSON/JSONL schemas, exit codes, ordering, truncation, and stdout/stderr separation are compatibility contracts.

### `luad-oracle`

Owns test-only integration with official Lua compilers and canonical listings. It is not trusted merely because it is called an oracle. Its comparator requires negative controls demonstrating that meaningful corruption is detected.

## Core invariants

### Representation and meaning remain distinct

- Preserve raw instruction words.
- Preserve exact integer values and IEEE-754 bits.
- Preserve raw strings independently of escaped display strings.
- Preserve encoded operands independently of interpreted signed values.
- Never overwrite factual fields with external names or interpretations.

### Provenance is structural

Important facts identify their source byte range and derivation. Cursor-length arithmetic alone is not complete byte accounting; every byte should ultimately be classified as a recognized field, format padding, preserved uninterpreted data, or diagnosed trailing data.

### Identity is interpretation-scoped

A `StableId` is stable only within one exact artifact and selected parse interpretation. A portable reference must eventually include the artifact SHA-256, resolved dialect/vendor profile, parse mode and relevant analysis configuration, and stable object ID. No cross-build equivalence is implied.

### Invalid states fail closed

- Unknown dialects are not decoded as a nearby version.
- Missing selectors do not fall back to another object.
- Missing proof dependencies do not skip required gates.
- Invalid register, jump, or stack references prevent valid-for-analysis verdicts where relevant.
- Limits are checked before allocation or unbounded traversal.

### Determinism

For identical bytes, configuration, dialect implementation, and tool version, machine output must be byte-for-byte deterministic. Ordered maps or explicit sorting are required at serialization boundaries.

### No unsafe opcode conversion

Opcode conversion should use exhaustive generated or explicit matches. The target state is `#![forbid(unsafe_code)]` across the workspace.

## Trust and evidence layers

1. Memory-safety and boundedness tests
2. Parse/serialize byte identity
3. Official-listing comparison of decoded facts
4. Hand-authored structural-analysis expectations
5. Instrumented-runtime evidence for semantic effects

Passing a lower layer does not imply a higher one. Capability status must name the gates supporting it.

The current implementation does not yet satisfy this model. See [the review](docs/REVIEW-2026-08-22.md) and [coding plan](docs/CODING-AGENT-PLAN.md).

## Extension rules

When adding a dialect, opcode, analysis, or command:

- add the smallest reusable primitive in the owning crate;
- expose facts rather than workflow policy;
- declare preconditions and resource ceilings;
- add a negative control for any new oracle/comparator;
- add schema and deterministic-output coverage for machine records;
- advertise the feature only after its named evidence gate passes.

Composable-workflow features are deferred until the factual layer is trustworthy.
