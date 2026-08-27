# `luad` product roadmap

Status: authoritative product direction.

Fresh as of: 2026-08-27.

Product requirements live in [PRD.md](PRD.md). Exact implementation and acceptance
details live only in [the active sprint](docs/NEXT-SPRINT.md). This roadmap orders
future obligations; it does not promote a target, authorize product work, or replace an
executable gate.

## Destination

`luad` 1.0 will be a small, trustworthy Lua bytecode disassembler and engineering tool.
It will turn untrusted compiled chunks into exact, auditable structural and instruction
facts for humans, scripts, and AI agents without executing the input. Equivalent inputs
and options will produce byte-for-byte deterministic output on every advertised host.

The public product should feel consistent with Lua itself: narrow claims, exact version
names, portable behavior, plain documentation, liberal licensing, and releases that are
easy to download and verify. The proof machinery can remain detailed internally; a user
should need only the support matrix, command reference, limitations, checksums, and one
evidence link.

### Version 1 support boundary

Version 1.0 will promote only the independently qualified targets in the canonical
[release boundary](docs/RELEASING.md#frozen-version-1-boundary):

1. OpenWrt-derived Lua 5.1.5 profile `lua5.1-lnum32` with
   `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4`;
2. stock PUC Lua 5.1.5 profile `lua5.1` with
   `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0`; and
3. stock PUC Lua 5.4.9 profile `lua5.4`, format 0, with 4-byte instructions, 8-byte
   `lua_Integer`, 8-byte `lua_Number`, and the pinned official compiler's standard
   little-endian representation.

[Lua 5.4.9](https://www.lua.org/versions.html) replaces 5.4.8 as the forward-looking
1.0 target because it is the final Lua 5.4 bug-fix release. Accepted 5.4.8 evidence may
be a prerequisite where the exact 5.4.9 qualification contract proves the relevant
format and opcode facts unchanged, but it cannot by itself promote 5.4.9.

Each Lua 5.1 profile and layout is a separate claim. Passing LNUM32 never implies stock
Lua 5.1 support, and passing one stock layout never implies a different numeric
representation, word size, or byte order. Lua 5.2, 5.3, 5.5, LuaJIT, Luau, other stock
layouts, and other vendor profiles remain experimental or unsupported until their own
post-1.0 contracts pass.

The 1.0 distribution boundary is Linux x86-64 and macOS arm64. Additional package
targets require their own build and smoke evidence but do not broaden the bytecode
support matrix.

## Product boundaries

`luad` owns:

- hostile-input parsing, layout detection, validation, and lossless byte provenance;
- version-specific instruction decoding, physical roles, operands, constants, effects,
  targets, source locations, and closure bindings;
- deterministic text plus versioned JSON and JSONL contracts;
- structural navigation through prototypes, cross-references, control flow, queries,
  exports, and exact comparisons; and
- explicit evidence for every public support claim.

`luad` will not own decompilation, guessed source reconstruction, security policy,
attacker-control or exploitability judgments, target execution, persistent research
state, or autonomous investigation. Those consumers compose over the factual CLI.

## Engineering mountains

The roadmap does not assign equal weight to unequal work.

| Mountain | Size | Release position | Core difficulty |
|---|---:|---|---|
| Exact target fidelity | Large | Version 1 | Serialized layouts, opcode semantics, malformed-input behavior, and independent authority across every claimed target |
| Stable machine and human contracts | Large | Version 1 | Typed facts, bounded streams, schemas, diagnostics, deterministic ordering, and platform-independent scalar rendering |
| Robustness, evidence, and distribution | Large | Version 1 | Resource limits, fuzzing, capability evidence, reproducible artifacts, installation, and release mechanics |
| Structural navigation and comparison | Medium–large | Version 1 | CFGs, xrefs, focused selection, recursive export, and semantically honest diff without source reconstruction |
| Bounded value and call analysis | Extra large | After version 1 | Reaching definitions, joins, loops, aliasing, captures, cutoffs, and evidence-preserving uncertainty |
| LuaJIT | Extra large, separate product track | Scoping decision after version 1 | A distinct serialization model, instruction set, runtime authority, and qualification strategy |

LuaJIT is not another row in a stock-Lua version matrix. Work begins only after a
written scope and authority decision demonstrates that it should share this product.

## Release train

The dependency order is:

```text
publication and artifact-retention implementation
  -> stable public CLI and schema boundary
  -> robustness and distribution infrastructure
  -> LNUM32 exact-target qualification
  -> PUC Lua 5.4.9 exact-target qualification
  -> stock PUC Lua 5.1.5 exact-target qualification
  -> public workflow transfer
  -> one frozen 1.0 candidate and release
```

Accepted prerequisite gates are referenced by identity. A downstream milestone does
not duplicate their semantic suites unless it owns a new interaction capable of
falsifying the release claim.

### Milestone 1 — make publication boring

Outcome: a release can be assembled, installed, verified, and withdrawn without
inventing procedure on release day.

Required work:

- use a GitHub release as the primary 1.0 channel, with source plus reproducible
  `linux-x86_64` and `macos-aarch64` archives;
- name archives `luad-<version>-<platform>.tar.gz` and include `luad`, `README.md`,
  license files, and version/source identity;
- publish `SHA256SUMS`, a machine-readable evidence index, and one generated SPDX or
  CycloneDX SBOM;
- correct package metadata, define whether `cargo install luad` is a supported
  secondary channel, and run its publish/install dry run if it is advertised;
- establish the minimum supported Rust version separately from the contributor
  toolchain pin;
- run one dependency-license and vulnerability audit in release CI;
- document tag, release-note, checksum, failed-release, and rollback behavior; and
- retain release evidence beyond ordinary CI artifact expiry.

Detached signing is not a 1.0 blocker unless a stable signing identity and owner are
selected before the release contract freezes. If it is omitted, the release procedure
must say so plainly and rely on repository provenance plus published checksums.

Evidence boundary: a non-promoting packaging dry run from a clean revision proves the
archive ledger, reproducibility policy, installation transcript, SBOM generation, and
checksum verification. It cannot change capability status.

Stop condition: no target promotion artifact is produced by the packaging dry run.

### Milestone 2 — freeze the public automation contract

Outcome: a shell script, Lua developer, or AI agent can consume the same small,
documented interface throughout the 1.x line.

Required work:

- stabilize command discovery, schemas, envelopes, interpretation identity,
  diagnostics, exit codes, stdout/stderr separation, pagination, and resource-limit
  reporting;
- keep `inspect`, `disasm`, and `validate` as the smallest stable core;
- qualify the structural navigation surface promised for 1.0—prototype trees, CFG, xrefs,
  query, export, explain, and diff—only to the extent promised by the 1.0 schemas;
- retain recursive batch export with per-input outcomes and explicit fact-family
  selection so consumers do not materialize irrelevant instruction streams;
- keep the query grammar deliberately small and reject unsupported predicates rather
  than silently approximating them;
- make every JSON/JSONL example executable against the same schemas as live output;
- define the 1.x compatibility policy for closed variants, open vocabularies, additive
  fields, schema-major changes, target identities, and prototype-content schemes; and
- ensure `luad capabilities --format json --evidence` distinguishes implementation
  presence, experimental evidence, and exact promoted targets.

Bounded callee, origin, call-relation, and prototype-identity facts may remain available
when their current schemas and evidence fit the frozen contract. More ambitious
data-flow extensions are not required for 1.0 and must not force a late schema break.

Evidence boundary: one machine-contract qualification gate exercises every stable
command and format at the public CLI, validates live output against schemas, compares
shared facts across text/JSON/JSONL consumers, and includes corruption controls.

Stop condition: after this milestone, an incompatible public change requires an
explicit schema-major or CLI-major qualification contract; new analysis ideas return to
the post-1.0 roadmap.

### Milestone 3 — establish hostile-input and operational infrastructure

Outcome: every later target candidate automatically crosses the same boundedness,
fuzzing, audit, and performance tripwires before final qualification.

Required work:

- audit every parser allocation and recursive/traversal boundary against declared
  resource limits;
- exercise detection, every parser in the planned support matrix, post-parse analysis,
  and text/JSON
  rendering through maintained fuzz targets;
- retain bounded fuzz smoke in routine CI and run one representative time-bounded
  campaign to prove that the extended-campaign procedure and artifact retention work;
- turn every crash, timeout, excessive allocation, or inconsistent verdict into a
  minimized redistributable regression;
- define the final focused security-review packet for hostile input, archive
  construction, dependency handling, terminal escaping, and output-file behavior;
- record representative runtime and peak-memory tripwires for small input, a large
  instruction vector, deep prototypes, long strings, and the firmware-scale mixed
  workflow; and
- define how the final candidate will publish campaign configuration, duration, corpus
  identity, and result in the evidence bundle.

This milestone requires useful tripwires, not a benchmark product. Correctness and
bounded behavior take priority over optimizing headline throughput.

Evidence boundary: CI proves that every maintained target executes under the common
smoke envelope, the representative campaign produces a retained artifact, and each
tripwire has a falsifiable assertion. The final campaign, security review, and
performance record are rerun or completed on the Milestone 8 candidate.

Stop condition: any known panic, unbounded allocation/traversal defect, unexplained
timeout, or P0 correctness/security defect blocks qualification.

### Milestone 4 — qualify the LNUM32 target

Outcome: the first exact vendor profile proves the complete promotion and firmware-tree
workflow.

Required work:

- issue a new candidate identity for the current revision rather than reusing the
  superseded `lua51-lnum32-0.1.0-rc1` identity;
- authenticate the Lua 5.1.5 source, OpenWrt revision and ordered patch series, build
  recipe, platform compiler binaries, fixtures, profile, and exact layout;
- reference the accepted public-read, validator, diagnostic, machine-contract,
  retrieval, scalar-rendering, export-bound, and hostile-input prerequisites needed by
  the advertised claim;
- prove that open argument/result windows cannot erase a callee already established in
  an unaffected register;
- run one internal uncoached investigation with an independently authored objective on
  different firmware;
- run one outside-human in-profile trial after pre-screening that the sample resolves to
  the exact LNUM32 profile;
- separately prove that an out-of-profile sample fails with an actionable diagnostic and
  the correct exit code; and
- minimize every reproducible correctness finding before promotion.

Evidence boundary: the canonical LNUM32 promotion gate emits a release manifest only
after all clean prerequisite results, platform attestations, customer records, mutation
probes, and the aggregate check close over one revision with zero required skips.

Stop condition: promote only the exact LNUM32 profile/layout. Stock Lua 5.1 and every
other vendor layout remain experimental.

### Milestone 5 — qualify stock PUC Lua 5.4.9

Outcome: the promotion machinery repeats on a current, broadly recognizable stock Lua
target rather than remaining specific to one vendor profile.

Required work:

- pin the final Lua 5.4.9 archive, official compiler binaries, reference manual, source
  tables, fixtures, and exact standard layout;
- review the 5.4.8-to-5.4.9 source and binary-chunk delta and accept prior evidence only
  for facts the delta proof preserves;
- qualify parsing, byte accounting, physical instruction roles, typed operands,
  constants, prototype/upvalue identity, targets, source lines, validation, deterministic
  scalar rendering, text/JSON/JSONL agreement, and malformed-input behavior;
- require an official `luac -l -l` comparison plus an implementation-independent
  decoder or semantic authority and meaningful corruption controls; and
- run the stable command/schema interaction gate against the packaged candidate.

Evidence boundary: one exact Lua 5.4.9 release gate assembles and verifies its own
target-scoped manifest. A 5.4.8 gate is a prerequisite only where explicitly admitted by
the delta proof.

Stop condition: promote Lua 5.4.9 only. Do not describe the result as generic Lua 5.4,
5.5, or cross-version support.

### Milestone 6 — qualify stock PUC Lua 5.1.5

Outcome: ordinary Lua 5.1 users receive an exact stock claim that cannot be confused
with LNUM32.

Required work:

- pin the official Lua 5.1.5 authority and the exact little-endian 64-bit `size_t`,
  non-integral-double layout;
- prove profile selection and symmetric stock-versus-LNUM rejection;
- qualify the full public disassembly and validation contract, including closure
  descriptors, `SETLIST C == 0` data words, stripped/debug prototypes, constants,
  offsets, jump targets, and bounded malformed-input handling;
- close text/JSON/JSONL determinism and the stable command/schema interaction gate for
  this exact profile; and
- keep 32-bit stock, big-endian, integral-number, and other Lua 5.1 layouts experimental
  until separately qualified.

Evidence boundary: the stock Lua 5.1.5 release gate uses only stock-profile authorities
and rejects LNUM32 or another layout as a prerequisite substitute.

Stop condition: capability and documentation records name the exact stock layout; they
must not collapse it into a broad `Lua 5.1 supported` claim.

### Milestone 7 — prove public transfer

Outcome: the release can be understood and used without access to the implementation
history or qualification vocabulary.

Required work:

- reduce the README entry path to purpose, exact support table, installation, three
  first commands, limitations, and links;
- provide plain guides for a Lua learner, a firmware researcher, and a machine consumer;
- publish exact-version format notes with links to the relevant official Lua sources;
- retain a worked external-consumer example that uses JSONL and stable evidence links
  without embedding sink, taint, or exploitability policy in `luad`;
- make installation, verification, quick-start, command, schema, diagnostic, evidence,
  security, and known-limitation documentation discoverable from the README index;
- commit customer-trial records using a stable template while excluding private
  firmware and investigation-specific security judgments; and
- ask Lua community reviewers specifically for corrections to terminology, target
  claims, build instructions, and surprising output before the final freeze.

Evidence boundary: a fresh human or agent installs the packaged candidate and completes
inspection, disassembly, validation, navigation, query, export, and comparison using
only published help and documentation.

Stop condition: documentation never calls an experimental dialect supported, never
implies affiliation with Lua.org or PUC-Rio, and never makes a security conclusion from
static facts.

### Milestone 8 — freeze and publish 1.0

Outcome: one revision, one support matrix, and one set of artifacts can be independently
verified after publication.

Required work:

1. Freeze a clean candidate commit and stop feature/schema work.
2. Run each target-specific promotion gate with its exact official compiler and no
   required skips.
3. Run the aggregate repository check once and the extended fuzz campaign once.
4. Complete the focused security review and final performance tripwire record.
5. Build both platform archives and verify their installed binaries and schemas.
6. Assemble the evidence index, SBOM, checksums, compatibility statement, and known
   limitations from the candidate results.
7. Confirm that capabilities, README, security policy, release notes, schemas, and
   downloadable artifacts identify the same targets and revision.
8. Confirm that no P0 correctness or security defect remains open.
9. Tag `v1.0.0`, publish the release, download each public artifact into a fresh
   environment, and repeat checksum plus smoke verification.
10. Retain the accepted evidence and customer records in release storage.

Stop condition: a failed or partial publication does not change capability status. Use
the documented rollback procedure, correct the bounded defect, issue a new candidate,
and rerun only the evidence invalidated by the change.

## Version 1 acceptance

Version 1 is eligible only when all of these statements are true for the exact promoted
targets:

1. Every maintained release fixture crosses the public CLI and agrees with the pinned
   official authority plus an implementation-independent decoder or semantic oracle.
2. Mutation probes prove that gates reject wrong opcodes, operands, constants, roles,
   targets, metadata, schema fields, and evidence substitutions.
3. Text, JSON, JSONL, query, export, and comparison consumers agree on shared facts and
   remain deterministic across advertised hosts, including floating-point rendering.
4. Resource limits, malformed-input tests, the extended fuzz campaign, security review,
   and clean builds support the safety claim.
5. The capability manifest, release evidence, documentation, SBOM, checksums, and
   downloadable artifacts identify the same targets, revision, and limitations.
6. A fresh human or agent can install the tool and complete the documented inspection,
   disassembly, validation, navigation, query, export, and comparison workflows using
   only public help and examples.

## Post-version-1 research

### Bounded value and call facts

Before expanding value analysis, run a design spike over representative public chunks
and measure the proportion of call sites resolved under deliberately conservative
rules. A proposal must define join, loop, alias, capture-mutation, and cutoff semantics
before committing to a stable schema. Path-specific facts must not be replaced by a
union over unrelated paths or callers.

The first admissible increments are intraprocedural and evidence-linked. SSA,
whole-program interprocedural dataflow, high-level expressions, and security
classification remain outside version 1.

### Additional targets

Promote one exact target at a time in customer-value order. Lua 5.2, 5.3, 5.5, and
additional stock layouts may reuse the stock-Lua qualification contract. Vendor
mappings may enter only as explicit, provenance-bound profiles. LuaJIT requires the
separate product decision described above.

### Other deferred surfaces

Decompiler output, source reconstruction, an assembler, execution, tracing, persistent
research state, GUI/TUI work, hosted services, and policy-bearing security analysis all
require separate post-1.0 product decisions.

## Sequencing rules

- Silent incorrect answers interrupt planned feature work.
- Release infrastructure advances alongside qualification; it is not deferred to the
  final candidate.
- Schema promotion precedes compatibility promises. Experimental fields and commands
  remain labeled as such.
- Private or downloaded corpora may find defects and measure usefulness but never
  replace redistributable fixtures and independent authorities.
- A release checkpoint measures an external user outcome, but self-run evaluation is
  usability evidence rather than independent adoption evidence.
- Waiting for an outside participant does not authorize unrelated product work. A
  disjoint documentation, packaging, or evidence-retention batch may proceed only under
  its own sprint contract.
- One gate per release claim is preferred over a public thicket of badges. Internal
  prerequisite gates remain discoverable through the evidence manifest.

## Preserved planning provenance

The archived [2026-08-25 roadmap and release-readiness
review](docs/reviews/2026-08-25-roadmap-review.md) records the exploration that exposed
the open-window replay, fuzzing, manifest, publication, string-limit, performance,
customer-transfer, external-layer, documentation, and distribution gaps. It remains a
point-in-time critique rather than current status. This roadmap preserves those concerns
as forward obligations without retaining completed-work comparisons or superseded
phase checklists here.
