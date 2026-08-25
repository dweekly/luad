# `luad` product roadmap

Status: authoritative product direction. Exact implementation and acceptance details
belong only in [the active sprint](docs/NEXT-SPRINT.md).

## Destination state

`luad` will be a deterministic, stateless fact tool that lets a human researcher or
external agent move from a firmware tree to reproducible answers about bytecode
identity, constants, symbolic call paths, captures, value origins, control flow, and
change across firmware versions. Every answer will carry the artifact interpretation
and instruction evidence needed to audit it. Machine consumers will join and query
those facts without decoding Lua instructions or retaining hidden stream state.

Security classification, attacker control, exploitability, inferred intent, research
memory, and autonomous planning remain outside the executable. Deterministic VM facts
belong in `luad`; investigation-dependent judgments belong in the caller.

The first release target is the OpenWrt-derived Lua 5.1.5 LNUM32 profile with
little-endian, 32-bit serialized string lengths. Every support claim remains scoped to
an exact release, profile, layout, public surface, and evidence manifest.

## Delivery sequence

### 1. Make firmware-tree streams self-identifying and discoverable

All JSONL fact variants will carry or directly reference stable input and interpretation
identity. Interleaved records will be joinable without a `file_start` state machine.
Schema compatibility, ordering, limits, failures, diagnostic-catalog discovery, and
capability discovery will close under one machine-contract matrix.

Exit outcome: an agent can stream a mixed firmware tree into relational or JSON tooling,
attribute every record to the correct full path and interpretation, and discover the
diagnostic surface without prose parsing.

### 2. Measure and resolve symbolic callees

A bounded design spike will first measure call-site resolution coverage at intra-block,
strict-dominator, and closure-capture tiers, plus conflicts, loop mutations, dynamic
keys, and alias boundaries. The production matrix will then cover literal globals and
tables, `require`-labeled module paths, deterministic local aliases, and multi-hop
upvalue bindings.

Every `CALL` and `TAILCALL` will expose an evidence-linked path or a typed unresolved
reason. Module labels describe their literal loader basis; they do not assert runtime
object identity.

Exit outcome: firmware consumers can enumerate trustworthy symbolic callees without
building a second Lua register/closure resolver, while incomplete coverage is loud and
measurable.

### 3. Expose bounded argument and value origins

Call arguments and selected registers will link to a cycle-safe value-expression graph.
The matrix will cover constants, parameters, upvalues, fields, call results,
concatenations, computations, unknowns, and explicit cutoffs. Operands are captured at
the writing instruction so self-aliasing operations such as `CONCAT A A C` remain sound.

Lua 5.1 `MOD` will preserve string-format provenance used by LuCI (`"fmt" % {args}`)
without claiming that every runtime `MOD` is formatting. Constant-only `CONCAT` and
format expressions remain distinguishable from parameter-dependent expressions.

Exit outcome: an external investigator can audit each origin edge, distinguish
constant-only expressions from dependent computations, and tell “computed” from “the
analysis stopped.”

### 4. Publish provable call relations and prototype content identity

Cross-prototype call edges will be emitted only where closure construction, the value
stored at that exact instruction, lookup, and invocation establish one target. The
matrix will cover global storage, closure/upvalue storage, ambiguity, and the
off-by-one-sensitive sequence of adjacent closure writes.

Each prototype will receive a versioned identity derived from documented normalized
instructions, constants, captures, and child relationships. Artifact-local paths remain
the navigation identity; content identities enable ordinary cross-firmware joins.

Exit outcome: callers can build a provable partial call graph, answer “who calls this”
where bytecode permits, and identify changed prototype bodies across firmware releases.

### 5. Close queries, recipes, and the stable release

Queries will cover callee paths, unresolved reasons, origin shapes, call relations,
interpretation identity, and prototype content identity. Every predicate applies its
complete operand or fails. Tested recipes will cover corpus constant search, capture
traversal, call-site enumeration, argument-origin triage, caller navigation, and
cross-version comparison. A dedicated constant-search verb is eligible only if it
materially improves the tested export/query recipe without creating parallel semantics.

The release candidate will freeze the schema major, publish exact target artifacts,
derive the `lua5.1-lnum32` support tier from the verified release evidence bundle, and
keep the base `lua5.1` dialect experimental. It will undergo an uncoached investigation
against a different firmware version or objective. Reproducible correctness defects
become minimized public regressions.

Exit outcome: a human or AI agent can complete the reference firmware workflows with
the supported CLI and a thin external judgment layer.

### 6. Qualify additional targets independently

Stock Lua layouts, Lua 5.2, 5.3, 5.4, 5.5, LuaJIT, and vendor mappings advance one exact
target at a time. Vendor qualification may consume a provenance-bound mapping recovered
by an external interpreter-analysis tool. Firmware rehosting and dynamic gadget testing
remain external.

## Dependency order

```text
self-identifying streams
  -> measured symbolic callees
       -> bounded value origins
            -> provable calls + content identity
                 -> query/recipe closure + stable release evidence
```

## Customer checkpoints

- After streams and symbolic callees: repeat a corpus-wide call-site survey using only
  public machine output and report resolution coverage.
- After value origins and call relations: trace representative format/concatenation
  arguments and caller relationships while leaving reachability and sink policy external.
- Before release: investigate a different firmware version or objective without
  implementation guidance.

Silent incorrect answers interrupt the sequence. Friction routes to the nearest factual
matrix. A private or externally downloaded corpus supplements but never replaces
redistributable evidence.

## Delivery roles

- The steward owns roadmap scope, algorithmic review, gate execution, and promotion.
- A fast implementation model handles bounded edits in an isolated worktree.
- A model-diverse acceptance author is used for new semantic primitives and
  qualification, not routine corrections.
- A portfolio-level reviewer critiques the roadmap after a batch of stages and before
  stable release planning.

Serial work remains the default. Parallel work becomes eligible only when production,
acceptance, gates, worktrees, and integration order are demonstrably independent.

## Persistent exclusions

`luad` will not own decompilation, sink classification, attacker control, sanitization,
authentication, exploitability, whole-system reachability, persistent research state,
autonomous planning, firmware unpacking, target execution, or dynamic gadget testing.
