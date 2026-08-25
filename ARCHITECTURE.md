# `luad` architecture

## Purpose

`luad` turns compiled Lua bytecode into deterministic, inspectable facts. It does not own researcher judgment, project state, hypotheses, or agent planning.

The intended pipeline is:

```text
input bytes
  → bounded SafeReader
  → dialect/profile detection and validated ChunkLayout
  → layout-driven decoder
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

`luad-dialect-lua51` through `luad-dialect-lua55` own header detection, profile selection, layout parsing, opcode fields and modes, signed-operand interpretation, semantic lifting, and dialect validation.

Similar-looking layouts are not evidence of equivalence. Shared helpers are appropriate only where official formats and independent tests establish the shared rule.

Each decoder must construct a validated, immutable `ChunkLayout` from the chunk header before reading layout-dependent fields. At minimum it records byte order and the declared widths of integers, `size_t`, instructions, and Lua numbers, plus number-integrality and any explicit vendor profile. No decoder may substitute the build host's widths or byte order for values declared by the artifact.

### `luad-analysis`

Consumes the shared model and semantic instructions to produce CFGs, dominators, xrefs,
queries, diffs, symbolic callee facts, call-argument origin expressions,
caller-to-prototype relations, and versioned prototype subtree identities. It must not
reparse bytecode or silently select a default dialect.

Every analysis must state or enforce its preconditions. Invalid registers, jumps, stack
references, or instruction modes can make analysis unavailable rather than merely less
precise. Dataflow analyses are bounded and emit typed unresolved or unknown results when
the evidence is ambiguous, unsupported, unreachable, or exceeds a declared resource
limit. Provenance evidence uses stable instruction and object identifiers; it does not
make security, reachability, or attacker-control judgments.

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
- Preserve every physical instruction word even when the dialect assigns it a non-executable role.
- Never overwrite factual fields with external names or interpretations.

For example, the words following a Lua 5.1 `CLOSURE` describe how child upvalues bind to parent registers or parent upvalues. They occupy physical PCs but are not independently executed `MOVE` or `GETUPVAL` operations. The shared model must retain the words and provenance, assign an explicit `closure_binding` role, attach the ordered capture relation to the owning closure, and exclude the descriptor words from standalone effects and control-flow semantics.

### Provenance is structural

Important facts identify their source byte range and derivation. Cursor-length arithmetic alone is not complete byte accounting; every byte should ultimately be classified as a recognized field, format padding, preserved uninterpreted data, or diagnosed trailing data.

### Identity is interpretation-scoped

A `StableId` is stable only within one exact artifact and selected parse interpretation. A portable reference must eventually include the artifact SHA-256, resolved dialect/vendor profile, validated layout, parse mode and relevant analysis configuration, and stable object ID. No cross-build equivalence is implied.

Prototype subtree identities are a separate, versioned content-join key. Their canonical
preimage excludes artifact and structural identity while committing to decoded Lua 5.1
instruction content, exact constants, capture shape, and ordered child identities. They
do not replace artifact-local paths and do not assert source or behavioral equivalence.

### Invalid states fail closed

- Unknown dialects are not decoded as a nearby version.
- Vendor extensions such as Lua 5.1 LNUM are accepted only under a detected or explicitly selected profile, never silently as stock Lua.
- Missing selectors do not fall back to another object.
- Missing proof dependencies do not skip required gates.
- Invalid register, jump, or stack references prevent valid-for-analysis verdicts where relevant.
- Limits are checked before allocation or unbounded traversal.

### Diagnostics retain the deepest known location

A diagnostic's primary byte offset identifies the field or byte where the failure was detected. Wrapping an error with prototype, constant, or instruction context must not replace that offset with the caller's earlier cursor position. Human-readable context and structural paths are separate fields.

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

The release path applies these layers independently. A Lua 5.4.8 raw-fact oracle does not establish public rendering, analysis, losslessness, or runtime-effect claims. See the [product roadmap](ROADMAP.md) and [active sprint](docs/NEXT-SPRINT.md) for direction and the gate that closes the current boundary.

Public disassembly should be constructed as a typed reusable record before presentation. Text, JSON/JSONL, explanation, query, and xref views consume that record rather than re-decoding operands in their renderers. Test-only independent decoders remain isolated from this production path.

## Extension rules

When adding a dialect, opcode, analysis, or command:

- add the smallest reusable primitive in the owning crate;
- expose facts rather than workflow policy;
- declare preconditions and resource ceilings;
- add a negative control for any new oracle/comparator;
- add schema and deterministic-output coverage for machine records;
- advertise the feature only after its named evidence gate passes.

Composable-workflow features are deferred until the factual layer is trustworthy.
