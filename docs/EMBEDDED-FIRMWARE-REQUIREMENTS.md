# Embedded Lua 5.1 firmware requirements

Status: current product requirements for the embedded-firmware use case. This document
does not define implementation order; the [product roadmap](../ROADMAP.md) owns
direction and the [active sprint](NEXT-SPRINT.md) owns exact gates and sequencing.

## Reference use case

The reference corpus is TP-Link Deco X55 V1.2 firmware 1.4.6, build 20250211. Its Lua
surface contains 260 `.lua` files: 252 stripped Lua 5.1 bytecode chunks from the LuCI
administration stack and eight source files. The bytecode uses:

- little-endian Lua 5.1 encoding;
- a header-declared 32-bit `size_t`;
- an LNUM-derived vendor profile whose integer constant uses tag 9;
- stripped and nested prototypes representative of embedded OpenWrt deployments.

The private corpus supplies supplemental field evidence only. Every release claim
requires minimized redistributable fixtures, recorded provenance, and public-boundary
tests independent of the private files.

Vendor key material, credential hashes, and extracted secrets remain outside this
repository. Examples use placeholders or safely bounded prefixes and hashes.

## Research outcome

A researcher or agent must be able to move from an unknown firmware tree to exact,
machine-consumable answers for these questions:

1. Which files are Lua bytecode, source, malformed, or unsupported?
2. Which exact dialect, vendor profile, byte order, widths, and numeric representation
   govern each chunk?
3. Which constants, globals, calls, prototypes, and upvalues occur at each physical PC?
4. Which parent register or upvalue supplies each child-closure upvalue?
5. Can a constant be followed through nested closure captures to a security-relevant
   function without manually decoding instruction fields?
6. Does a query match its supplied operand exactly, or fail closed when it cannot apply
   the predicate?
7. Can the same facts be consumed deterministically by a human and an AI agent across a
   firmware-scale batch?

`luad` supplies deterministic facts for this workflow. Security classification,
attacker-control judgments, hypotheses, naming, and cross-session research state remain
the caller's responsibility.

## Required parsing and profile identity

- Every Lua 5.1 layout-dependent read uses the widths, byte order, and numeric form
  declared by the chunk header and validated by the selected profile.
- Stock Lua 5.1 and LNUM-derived formats remain distinct interpretations. Tag 9 is never
  accepted by silently broadening the stock profile.
- The CLI provides an explicit route to every supported profile and rejects unknown,
  conflicting, or inapplicable selectors.
- Human and machine output identify the resolved base dialect, profile, layout, parse
  mode, and the evidence supporting automatic or explicit selection.
- Durable artifact identity includes the interpretation profile and layout so the same
  bytes cannot alias across incompatible meanings.
- Parse failures retain the deepest known byte offset and structural context.

## Required instruction and constant facts

- Public disassembly exposes mnemonic, raw word, physical PC, typed operands, operand
  roles, interpreted signed values, source metadata, semantic role, and confidence.
- Every dialect-defined constant-bearing operand retains its constant index and resolves
  to a typed value in text and machine output.
- String previews are escaped and bounded. Full machine values obey explicit output
  limits and truncation records.
- Query predicates apply every supplied operand. Unknown fields, unsupported operators,
  malformed selectors, and unapplied operands are hard errors rather than broad or empty
  plausible-looking matches.
- Recursive queries cover nested prototypes and report stable prototype context for each
  result.

## Required closure-capture model

In Lua 5.1, the `nups` physical words following `CLOSURE` are binding descriptors:

```text
MOVE     0 B   => child upvalue[i] captures parent register B
GETUPVAL 0 B   => child upvalue[i] captures parent upvalue B
```

The model and every public view must:

- preserve descriptor raw words and physical PCs;
- classify them as non-executable closure-binding records;
- attach ordered bindings to the owning `CLOSURE` and exact child prototype;
- expose forward and inverse parent-to-child capture relations;
- exclude descriptors from standalone register effects, executable CFG nodes, and
  ordinary instruction explanations;
- validate descriptor count and opcode class against the child prototype's upvalue
  declaration;
- render bindings directly, such as `upvalue[0] <- parent R5`, without requiring users
  to infer positional meaning.

This representation must support a multi-hop chain such as parent register → child
upvalue → nested-child upvalue while keeping each hop tied to an exact closure site.

## Required machine and batch behavior

- JSON and JSONL records are self-describing and validate against discoverable,
  versioned response schemas.
- Text and machine formats consume the same typed facts rather than independently
  decoding operands.
- Batch export accepts explicit file sets or bounded recursive discovery, produces one
  deterministic record sequence, identifies each input, and reports per-file outcomes.
- A failed file cannot disappear from batch output or be converted into overall success.
- Output ordering, pagination, limits, exit status, stdout, and stderr behavior remain
  stable and documented.
- Capability output distinguishes code presence, experimental surfaces, and exact
  release evidence. A fixture-only library result cannot imply firmware readiness.

## Public evidence requirements

The redistributable fixture matrix must include:

- stock Lua 5.1 with 32-bit and 64-bit `size_t`;
- the exact supported LNUM profile and a cross-profile rejection case;
- stripped and debug-bearing chunks;
- register and parent-upvalue captures, zero and multiple captures, nested closures,
  and malformed descriptor sequences;
- representative constant-bearing opcodes and signed operands;
- valid and invalid query operands;
- exact diagnostic-offset cases;
- a mixed source, valid-bytecode, malformed-bytecode, and unsupported-file batch.

Each fixture records source provenance, source and output hashes, compiler or patch
identity, compiler arguments, platform, endianness, integer and number widths, and
integrality settings. Required tools and fixtures never skip silently.

Acceptance occurs at the public CLI and response-schema boundary. Independent oracles
and mutation probes must reject wrong widths, profile substitution, changed operands,
missing constants, incorrect child identities, executable closure descriptors, dropped
batch records, and stale or cross-revision evidence.

## Adjacent workflows

Corpus-wide search, call-graph inference, sink classification, register provenance,
firmware-tree diffing, pseudo-code structuring, interpreter-semantic recovery,
cross-language taint, native SRE synchronization, and persistent research sessions may
be valuable external layers. `luad` may exchange provenance-bound mappings and factual
schemas with those layers without owning their execution or judgments. They do not
enter the embedded Lua 5.1 release claim unless a future sprint gives one of them a
separate public contract and independent proof gate.
