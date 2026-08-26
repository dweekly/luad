# `luad` product roadmap

Status: authoritative product direction. Product requirements live in
[PRD.md](PRD.md); exact implementation and acceptance details live only in
[the active sprint](docs/NEXT-SPRINT.md).

## Destination

`luad` will be a trustworthy Lua bytecode disassembler and engineering tool. It will
turn untrusted compiled chunks into exact, auditable structural and instruction facts
for humans, scripts, and AI agents without executing the input. Equivalent inputs and
options will produce byte-for-byte deterministic output on every supported host.

Existing tools are generally either runtime- and version-coupled listings such as
`luac -l`, version-locked binary inspectors, or decompilers whose reconstruction can
obscure the underlying evidence. `luad` will provide a memory-safe, independently
verified factual layer with typed machine output, explicit support boundaries, and raw
byte provenance.

Version 1 will qualify exact PUC Lua 5.1.5 and Lua 5.4.8 targets. Lua 5.1 profiles and
layouts will be named independently; a passing profile will never imply support for a
different numeric representation, word size, or byte order. Other stock releases will
remain experimental until they satisfy the same target-specific contract.

## Product boundaries

`luad` owns:

- hostile-input parsing, layout detection, validation, and lossless byte provenance;
- version-specific instruction decoding, physical roles, operands, constants, effects,
  targets, source locations, and closure bindings;
- deterministic text plus versioned JSON and JSONL contracts;
- structural navigation through prototypes, cross-references, control flow, queries,
  exports, and exact comparisons;
- explicit evidence for every public support claim.

`luad` will not own decompilation, guessed source reconstruction, security policy,
attacker-control or exploitability judgments, target execution, persistent research
state, or autonomous investigation. Those consumers compose over the factual CLI.

## The engineering mountains

The roadmap does not assign equal weight to unequal work.

| Mountain | Size | Release position | Core difficulty |
|---|---:|---|---|
| Exact target fidelity | Large | Version 1 | Serialized layouts, opcode semantics, malformed-input behavior, and independent authority across every claimed target |
| Stable machine and human contracts | Large | Version 1 | Typed facts, bounded streams, schemas, diagnostics, deterministic ordering, and platform-independent numeric rendering |
| Robustness, evidence, and distribution | Large | Version 1 | Resource limits, fuzzing, capability evidence, reproducible artifacts, installation, and release mechanics |
| Structural navigation and comparison | Medium–large | Version 1 | CFGs, xrefs, focused selection, recursive export, and semantically honest diff without source reconstruction |
| Bounded value and call analysis | Extra large | After version 1 | Reaching definitions, joins, loops, aliasing, captures, cutoffs, and evidence-preserving uncertainty |
| LuaJIT | Extra large, separate product track | Scoping decision after version 1 | A distinct serialization model, instruction set, runtime authority, and qualification strategy |

LuaJIT is not another row in a stock-Lua version matrix. Work begins only after a
written scope and authority decision demonstrates that it should share this product.

## Version 1 delivery sequence

Each stage is a vertical slice across implementation, public output, independent
evidence, hostile-input behavior, and documentation. Enumerable opcode, operand, or
layout families belong in one table-driven batch rather than one sprint per member.

### Stage 1 — release-grade exact disassembly

Qualify the full public disassembly contract for the exact Lua 5.1.5 and Lua 5.4.8
targets:

- parse every serialized field with the declared layout and bounded resource use;
- classify executable instructions, companion words, closure descriptors, and data
  words without inventing execution semantics;
- emit mnemonics, typed physical operands, resolved constants, prototype and upvalue
  identities, jump targets, line metadata, and exact offsets;
- keep text and machine records derived from one fact model;
- make malformed, ambiguous, and unsupported inputs fail loudly with stable diagnostics;
- pin compiler/runtime provenance and compare public output with official and
  independent authorities;
- specify deterministic integer, byte-string, and floating-point rendering across
  supported hosts.

Exit: a consumer can replace a version-matched `luac -l -l` listing with `luad` while
gaining typed facts, provenance, validation, and hostile-input safety.

### Stage 2 — coherent automation contract

Make the CLI a dependable component in shell and agent toolchains:

- stabilize command discovery, schemas, envelopes, identities, diagnostics, exit codes,
  stdout/stderr separation, pagination, and bounded output;
- expose recursive batch export with per-input outcomes and explicit fact-family
  selection so consumers do not materialize irrelevant instruction streams;
- retain a small, documented query grammar for stable selectors and reject unsupported
  predicates rather than silently approximating them;
- keep richer query expressions experimental until their grammar, typing, errors, and
  compatibility policy have independent acceptance evidence;
- publish executable examples that validate against the same schemas as live output.

Exit: a human-written script or AI agent can discover the interface, request a bounded
fact set, join records by stable identity, and recover from errors without scraping
human text.

### Stage 3 — structural navigation and comparison

Provide code-understanding features that remain below decompilation:

- prototype trees and closure/upvalue binding graphs;
- instruction, constant, global, upvalue, and control-flow cross-references;
- CFGs, reachability, dominators, and explicit physical-to-logical PC relationships;
- exact and normalized comparison modes whose equivalence rules are named and tested;
- concise explanations that distinguish raw facts from reviewed derivations and never
  upgrade incomplete static effects to certainty.

Exit: a consumer can navigate a non-trivial chunk, explain every structural edge, and
compare two builds without reconstructing Lua source.

### Cross-cutting workstream — robust and obtainable release

Advance this workstream alongside Stages 1–3 so product closure is never deferred until
the algorithms are finished:

- run parse, analysis, and renderer fuzz targets in bounded CI smoke jobs and recorded
  extended campaigns;
- derive the public capability manifest from real gate and release evidence;
- enforce the memory-safety and resource-limit claims across every production crate and
  every parser allocation path;
- record representative runtime and peak-memory tripwires without constructing a broad
  benchmark program;
- publish reproducible checksummed binaries and a documented installation path;
- define versioning, rollback, minimum Rust version, dependency audit, and release
  ownership before the first release candidate.

Exit: exact artifacts are installable, their claims are independently inspectable, and
routine malformed inputs cannot escape bounded behavior.

## Version 1 acceptance

Version 1 is eligible when all of these statements are true for the exact promoted
targets:

1. Every maintained fixture crosses the public CLI and agrees with the pinned official
   authority plus an implementation-independent decoder or semantic oracle.
2. Mutation probes prove that gates reject wrong opcodes, operands, constants, roles,
   targets, metadata, schema fields, and evidence substitutions.
3. Text, JSON, JSONL, query, export, and comparison consumers agree on shared facts and
   remain deterministic across supported hosts, including floating-point rendering.
4. Resource limits, malformed-input tests, fuzz campaigns, and clean builds support the
   safety claim.
5. The capability manifest, release evidence, documentation, and downloadable artifacts
   identify the same targets and limitations.
6. A fresh human or agent can install the tool and complete the documented inspection,
   disassembly, navigation, query, export, and comparison workflows using only public
   help and examples.

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

Promote one exact target at a time in value order rather than numerical version order.
Lua 5.2, 5.3, and 5.5 reuse the stock-Lua qualification contract. Vendor mappings may
enter only as explicit, provenance-bound profiles. LuaJIT requires the separate product
decision described above.

## Sequencing rules

- Silent incorrect answers interrupt planned feature work.
- Release infrastructure advances alongside feature stages; it is not deferred to the
  end of the roadmap.
- Schema promotion precedes compatibility promises. Experimental fields and commands
  are labeled as such.
- Private or downloaded corpora may find defects and measure usefulness but never
  replace redistributable fixtures and independent authorities.
- A release checkpoint measures an external user outcome, but self-run evaluation is
  treated as usability evidence rather than independent adoption evidence.
