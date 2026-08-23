# Proposal: Composable Support for Progressive Reverse-Engineering Workflows

## Status

Deferred until R5 in [docs/CODING-AGENT-PLAN.md](docs/CODING-AGENT-PLAN.md) passes. New workflow primitives may expose only fact types represented in verified release evidence.

## Summary

`luad` should make progressive reverse-engineering workflows easy to build without becoming the system that manages those workflows.

The division of responsibility should be explicit:

- `luad` owns deterministic facts derived from Lua bytecode: parsing, validation, disassembly, semantic effects, control flow, cross-references, provenance, and bounded extraction.
- The caller owns accumulated interpretation: names, inferred types, notes, hypotheses, confidence, research history, collaboration, session state, and decisions about what to investigate next.

This proposal adds a small set of composable primitives to `luad`:

1. Globally unambiguous references to artifacts within an exact parse interpretation.
2. Exact retrieval of one identified object.
3. A read-only overlay format that lets an external system attach labels and metadata when rendering or exporting results.
4. One deterministic, full-fidelity JSONL export for callers that own indexing and traversal.

These primitives allow a human notebook, AI agent, Git repository, database, or future reverse-engineering application to preserve and reuse knowledge across sessions. `luad` itself remains stateless and does not acquire a project database, research model, or agent behavior.

## Motivation

A researcher rarely understands a program in one pass. They progressively determine that:

- a prototype is probably a request handler;
- a constant is a protocol field rather than arbitrary text;
- an upvalue holds configuration or a cryptographic key;
- several functions together form a module;
- a register or table has a particular conceptual type;
- a branch implements an authentication or error path.

The intelligence required to make those judgments should remain outside `luad`. AI systems will improve, researchers use different methodologies, and organizations will want different persistence and collaboration systems. Encoding those policies into `luad` would increase complexity while making the tool less adaptable.

What external researchers need from `luad` is narrower:

- identifiers that can be stored and used again;
- precise, compact retrieval of facts about an identifier;
- efficient export of facts for caller-owned indexing and traversal;
- a way to reapply external names and notes when viewing the same artifact;
- reliable schemas, limits, diagnostics, and deterministic results.

The TP-Link Lua 5.1 field report makes this boundary concrete. A caller should not have to reconstruct constant-table indices or closure capture chains from presentation text, because both are deterministic bytecode facts. `luad` should resolve typed constants and expose ordered parent-to-child capture relations. Deciding that a captured string is an AES key, naming the closure `dec_file`, and persisting that interpretation remain caller responsibilities.

The available substrate includes chunk SHA-256 digests, `StableId` values, disassembly, CFG, xrefs, queries, diffs, and JSON schemas. After R5, the next product gaps are interpretation-scoped identity, uniform object retrieval, deterministic full-fidelity export, and presentation of externally owned interpretations.

## Product boundary

### What belongs in `luad`

A feature generally belongs in `luad` when it is:

- deterministically derived from the input bytes and explicit command options;
- useful to many different callers;
- expressible with clear resource bounds;
- testable against bytecode facts or a declared presentation transformation;
- independent of a researcher's goals or beliefs.

Examples include resolving a stable ID, finding callers, exporting CFG edges, producing a proven backward dataflow slice, or decorating an object with a supplied display label.

### What does not belong in `luad`

The following are explicit non-goals:

- project, workspace, or session databases;
- an annotation editor or `luad annotate` command;
- hypothesis, confidence, or claim-management systems;
- research history, authorship, collaboration, and merge policy;
- selecting what the researcher should investigate next;
- autonomous AI calls or agent planning;
- carrying interpretations across changed artifacts;
- automatically accepting inferred names or types;
- proprietary storage formats for accumulated research;
- changing decoded facts based on external annotations.

The external caller may implement any of these. `luad` should make doing so convenient but should not prescribe how.

## Design principles

### 1. Facts remain immutable

An overlay may affect presentation but must not change decoded operands, semantic effects, diagnostics, CFG topology, xrefs, validation verdicts, or any other derived fact.

### 2. Identity is scoped to bytes and interpretation

`proto:0/3:pc:14` is stable within one exact chunk and selected parse interpretation, not across recompilation or different parsing profiles. Durable external references must pair the ID with the chunk SHA-256, resolved dialect/profile, validated layout, parse mode, and relevant configuration identity. `luad` must not suggest that structural IDs identify equivalent code in another artifact or interpretation.

### 3. No implicit state

Every output must be determined by the input artifact, command arguments, and explicitly supplied overlay. `luad` must not search for a hidden project directory, modify a sidecar, or depend on command history.

### 4. Bounded by construction

Retrieval and export must use explicit limits where applicable, return truncation metadata, and use deterministic ordering. A request must not accidentally exhaust memory or produce unbounded output.

### 5. Machine contracts come first

New output types must have versioned JSON Schemas. JSON and JSONL stdout must contain only the requested records. Diagnostics go to stderr or a declared diagnostics field, and failures use documented nonzero exit codes.

### 6. Prefer one primitive over overlapping commands

`get` should be the factual retrieval primitive. `explain` should become a human-oriented renderer over `get --include semantic`, rather than maintain an overlapping resolver and result path. Other existing commands remain useful specialized views.

## Proposed capability 1: Interpretation-scoped artifact references

Add a serializable `ArtifactRef` type:

```json
{
  "artifact_sha256": "d81f...9a2c",
  "dialect": "lua5.4",
  "profile": "stock",
  "parse_mode": "strict",
  "configuration_sha256": "8c20...0f4d",
  "id": "proto:0/3:pc:14"
}
```

Conceptually:

```rust
pub struct ArtifactRef {
    pub artifact_sha256: String,
    pub dialect: String,
    pub profile: String,
    pub parse_mode: ParseMode,
    pub configuration_sha256: String,
    pub id: StableId,
}
```

This does not replace `StableId`. Internally, and in commands already operating on one explicit file, a `StableId` remains sufficient. `ArtifactRef` is the portable form intended for external persistence, links between command results, and long-lived research records.

Requirements:

- Validate both digests as lowercase SHA-256 values.
- Validate that the resolved dialect/profile and parse mode match the active interpretation.
- Define the configuration digest to commit to any layout or profile-selection input not already determined by the artifact bytes and resolved profile.
- Include an `artifact_ref` for addressable objects in new response types.
- Preserve the existing compact `id` field where it is convenient within a response already scoped to one artifact.
- Add `luad schema artifact-ref`.
- Document explicitly that no cross-artifact equivalence is implied.

This is the only persistence-related identity mechanism `luad` needs. Mapping an old artifact to a new artifact remains an external concern, optionally assisted by the existing `diff` output.

## Proposed capability 2: Exact object retrieval

Add a `get` command that resolves one `StableId` and emits a typed, self-contained record:

```console
luad get sample.luac proto:0/3 --format json
luad get sample.luac proto:0/3:pc:14 --include semantic,provenance --format json
luad get sample.luac proto:0/3:k:7 --format json
```

Recommended arguments:

```text
luad get <FILE> <TARGET>
    --include <LIST>       raw,semantic,provenance,debug
    --overlay <FILE>
    --format text|json|jsonl
    --strict
```

The command should support every stable object kind that `luad` emits:

- chunk;
- prototype;
- instruction;
- basic block;
- constant;
- upvalue;
- local;
- diagnostic.

The response should be a discriminated union rather than an untyped JSON value:

```json
{
  "schema_version": 1,
  "artifact_sha256": "d81f...9a2c",
  "id": "proto:0/3:pc:14",
  "kind": "instruction",
  "data": {
    "raw": {},
    "semantic": {},
    "provenance": {}
  },
  "overlay": null
}
```

Requirements:

- Missing targets must fail with a documented nonzero exit code; never fall back to another object.
- Unsupported `--include` values must be usage errors.
- The same request must produce byte-for-byte deterministic JSON.
- `kind` and `data` must agree by schema.
- All identifiers returned inside `data` must be valid inputs to `get` when they represent addressable objects.
- Add `luad schema object` and end-to-end tests for every supported object kind.

`get` becomes the shared resolver and typed data path. `explain` remains a useful command name, but its implementation should be a text renderer over `get --include semantic`, not a parallel retrieval mechanism.

## Proposed capability 3: Deterministic full-fidelity export

Add an `export` command that emits one normalized, deterministic stream containing all facts needed by an external indexer:

```console
luad export sample.luac --format jsonl > sample.luad.jsonl
```

The caller, not `luad`, can load this stream into SQLite, a graph store, a notebook, or an agent's own persistence layer and perform arbitrary neighborhood traversal there.

Recommended record sequence:

1. stream header with schema version and interpretation-scoped artifact identity;
2. chunk and prototype records;
3. typed constants, physical instruction words and roles, debug records, and diagnostics;
4. semantic instruction records whose evidence gates pass;
5. ordered closure-binding and other cross-prototype relation records whose gates pass;
6. CFG blocks and edges whose analysis gates pass;
7. xref and other proven relation records;
8. terminal summary with counts, truncation, and diagnostics.

Every record should be self-identifying:

```json
{
  "record_type": "instruction",
  "artifact_ref": {
    "artifact_sha256": "d81f...9a2c",
    "dialect": "lua5.4",
    "profile": "stock",
    "parse_mode": "strict",
    "configuration_sha256": "8c20...0f4d",
    "id": "proto:0/3:pc:14"
  },
  "data": {}
}
```

Requirements:

- JSONL is the primary format; callers can consume it without retaining the entire document.
- Record ordering is documented and deterministic.
- Every factual record identifies the evidence gate supporting its type.
- No record type is exported until its underlying facts have a passing oracle or analysis gate.
- Limits and truncation are explicit in the header and terminal summary.
- A complete, non-truncated export can reconstruct the supported factual model without invoking multiple commands.
- Constant-bearing instruction operands retain their encoded index and include a typed resolved value; any text preview remains a bounded presentation field.
- Lua 5.1 closure descriptor words retain their physical PC and raw value, carry a non-executable role, and link the closure site, child upvalue, and parent register/upvalue in both traversal directions.
- Add `luad schema export-record`.

Do not add graph traversal in the first pass. If a demonstrated workflow later cannot use `export` efficiently, consider a command named `neighborhood` or `expand`. Do not use `slice`; the PRD reserves slicing for actual dataflow slicing.

## Proposed capability 4: Read-only presentation overlays

Define a small external overlay schema. The caller creates and persists this file; `luad` only validates and applies it to presentation.

Example:

```json
{
  "schema_version": 1,
  "artifact_sha256": "d81f...9a2c",
  "dialect": "lua5.4",
  "profile": "stock",
  "parse_mode": "strict",
  "configuration_sha256": "8c20...0f4d",
  "entries": [
    {
      "target": "proto:0/3",
      "label": "authenticate_request",
      "comment": "Working interpretation; signing-key origin remains unknown",
      "attributes": {
        "research.type": "RequestHandler"
      }
    },
    {
      "target": "proto:0/3:k:7",
      "label": "authorization_header"
    }
  ]
}
```

Recommended v1 fields:

```rust
pub struct Overlay {
    pub schema_version: u32,
    pub artifact_sha256: String,
    pub dialect: String,
    pub profile: String,
    pub parse_mode: ParseMode,
    pub configuration_sha256: String,
    pub entries: Vec<OverlayEntry>,
}

pub struct OverlayEntry {
    pub target: StableId,
    pub label: Option<String>,
    pub comment: Option<String>,
    pub attributes: BTreeMap<String, JsonValue>,
}
```

The intentionally generic `attributes` map lets callers retain types or domain-specific metadata without making `luad` define their meaning. Namespaced keys such as `research.type` reduce collisions.

Apply overlays with an explicit option:

```console
luad disasm sample.luac --overlay research.json
luad get sample.luac proto:0/3 --overlay research.json --format json
luad cfg sample.luac --proto proto:0/3 --overlay research.json --format dot
luad export sample.luac --overlay research.json --format jsonl
```

Overlay semantics:

- The artifact digest and parse-interpretation fields must match the analyzed input. A mismatch is an error.
- Every target must parse as a `StableId`. Unresolved behavior is explicit through `--overlay-unresolved=error|warn|ignore`, defaulting to `error`.
- Labels and comments are presentation data only.
- Original/debug names remain present and distinguishable from overlay labels.
- An overlay never changes validation, lifting, xrefs, CFG construction, query matching, or diff results.
- JSON places overlay data in a separate `overlay` field. It does not overwrite decoded fields.
- Text and DOT output may display labels alongside stable IDs, but stable IDs remain visible or recoverable.
- Overlay strings are untrusted input. Terminal, JSON, JSONL, and DOT renderers must apply the same control-character, bidi, escaping, and length policies used for hostile chunk strings.
- Overlay file size, entry count, string length, and attribute depth are bounded.
- Only one overlay is accepted in v1. Merging overlays and resolving conflicts are caller responsibilities.
- Add `luad schema overlay` and a standalone validation path such as `luad validate-overlay <FILE> <OVERLAY>` only if users need validation without rendering. Do not add overlay mutation commands.

The strongest regression test is semantic invariance: running a command with and without an overlay, removing the dedicated overlay fields, must yield identical factual output.

## CLI and library changes

### `luad-core`

Add narrowly scoped public types:

- `ArtifactRef`;
- `Overlay` and `OverlayEntry`;
- `ResolvedObject` or the object-response discriminated union;
- validation limits for externally supplied overlay data.

Keep these types free of file I/O and session concepts.

### `luad-analysis`

Add:

- a shared resolver from `StableId` to a typed object view;
- normalized export records for already-proven CFG, xref, and semantic facts;
- deterministic streaming order.

Existing CFG and xref implementations should be reused rather than duplicated. If an object kind cannot be resolved correctly, omit support until it can be proven rather than returning an approximate substitute.

Capture traversal should extend the generalized relation/xref model. A future `upvalues` command may provide a convenient rendering of those records, but it must not create a second binding analysis or own research state.

### `luad-cli`

Add:

- `get`;
- `export`;
- `--overlay` on presentation commands where it has a clear meaning;
- schemas for `artifact-ref`, `object`, `export-record`, and `overlay`;
- self-documenting record-type and include-value enumeration;
- consistent target-not-found, overlay-invalid, and artifact-mismatch exit behavior.

Overlay parsing belongs near CLI input handling, but overlay validation and application should be reusable by library callers.

### Renderers

Text renderers should prefer a compact convention that preserves identity:

```text
proto:0/3  authenticate_request
```

They should not replace the ID with the label. JSON output keeps facts and external presentation metadata structurally separate. DOT node labels may include both, with proper escaping and bounded comment inclusion.

## Example external workflow

An external AI harness or human researcher can implement persistence with ordinary files:

```console
# Establish the immutable artifact identity.
luad inspect sample.luac --summary --format json > artifact.json

# Export facts once for caller-owned indexing and traversal.
luad export sample.luac --format jsonl > evidence-001.jsonl

# The external researcher updates research.json using its own policy.

# Reapply that interpretation without changing luad's facts.
luad disasm sample.luac \
  --proto proto:0/3 \
  --effects \
  --overlay research.json

# Pull exact evidence for a follow-up question.
luad get sample.luac proto:0/3:pc:14 \
  --include raw,semantic,provenance \
  --overlay research.json \
  --format json
```

Across sessions, the external system retains `research.json`, its own index, and any evidence snapshots it wants. `luad` retains nothing. If the artifact or parse interpretation changes, the scoped-reference mismatch prevents accidental application of stale interpretations.

## Implementation plan and proof gates

### Prerequisite: trustworthy facts

Do not implement these milestones until R5 in [docs/CODING-AGENT-PLAN.md](docs/CODING-AGENT-PLAN.md) passes. No new command may expose a fact type absent from the verified release manifest.

### Milestone 1: Identity and exact retrieval

Implement `ArtifactRef`, shared target resolution, `get`, and the new schemas.

Proof gate:

- Every emitted addressable ID round-trips through `get`.
- Invalid and absent targets fail closed.
- Results are deterministic on all supported dialects.
- Artifact hash, interpretation identity, and ID uniquely identify every returned object.
- No existing command contract regresses.
- `explain` uses the same resolver and semantic record as `get`.

### Milestone 2: Read-only overlays

Implement the overlay schema, validation, and separate presentation fields. Initially support `get` and `disasm`; extend to `cfg` and `export` only after the invariance and escaping tests pass.

Proof gate:

- Interpretation mismatch is an error; unresolved-target behavior follows the explicit policy flag and defaults to error.
- Fuzzed overlay inputs cannot panic or exceed declared limits.
- Facts are identical with and without an overlay after overlay fields are removed.
- Original debug names and overlay labels are never conflated.
- Control characters, bidi controls, terminal text, JSON, and DOT are escaped according to the hostile-string policy.
- `luad` never writes or silently discovers an overlay.

### Milestone 3: Full-fidelity export

Implement deterministic streaming records for the complete proven factual model.

Proof gate:

- Golden fixtures cover every exported record type.
- A complete export reconstructs the supported model without additional commands.
- Every exported addressable record resolves through `get`.
- Record order and terminal counts are deterministic.
- Truncation is explicit and reproducible.
- Streaming memory remains bounded on limit-scale chunks.

### Milestone 4: Efficiency and contract hardening

Measure realistic human and agent command sequences, then optimize only demonstrated bottlenecks. Likely work includes sharing analysis within a command, avoiding construction of unused views, streaming JSONL, and keeping overlay application linear in the number of entries.

Proof gate:

- Benchmarks cover small, medium, and limit-scale chunks.
- `get` does not serialize the whole chunk to return one object.
- `export` does not retain the complete serialized stream in memory.
- Machine stdout remains clean in every success and error path.
- Capability and schema manifests advertise the features from one source of truth.

## Complexity budget

This proposal should be rejected or reduced if implementation begins to require:

- a persistent database;
- background indexing services;
- mutable project state;
- a general-purpose graph query language;
- overlay merge semantics;
- probabilistic ranking;
- hidden caches that affect correctness;
- cross-version identity guesses;
- agent-specific APIs beyond ordinary JSON contracts.
- any new command exposing a fact without a passing oracle gate.

The expected implementation is a few reusable data types, a resolver, a streaming exporter, strict overlay validation, CLI wiring, schemas, and tests. If it grows into a research platform, it has crossed the intended boundary.

## Recommended decision

After R5, proceed with Milestone 1. Exact object retrieval and interpretation-scoped references clarify the meaning of existing stable IDs and create the cleanest substrate for both humans and agents.

Add overlays next because they provide session-to-session continuity without introducing state into `luad`. Add full-fidelity export after that so callers can own indexing and traversal. Defer neighborhood traversal until a concrete workflow demonstrates that export is insufficient.

Do not add any project or session abstraction. A successful outcome is that increasingly capable external researchers can build sophisticated progressive-revelation workflows by composing `luad` commands, while `luad` remains reliable, efficient, understandable, and honest about what it knows.
