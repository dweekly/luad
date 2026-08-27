# Embedded Lua 5.1 firmware requirements

Status: current product requirements for the embedded-firmware use case. This document
does not define implementation order; the [product roadmap](../ROADMAP.md) owns
direction and the [active sprint](NEXT-SPRINT.md) owns exact gates and sequencing.

Fresh as of: 2026-08-27.

## Reference use case

The primary reference corpus is TP-Link Deco X55 V1.2 firmware 1.4.6, build 20250211.
Repeated audit evidence also covers Deco M4R 1.8.2. The X55 Lua surface contains 260
`.lua` files: 252 stripped Lua 5.1 bytecode chunks from the LuCI administration stack
and eight source files. The bytecode uses:

- little-endian Lua 5.1 encoding;
- a header-declared 32-bit `size_t`;
- an LNUM-derived vendor profile whose integer constant uses tag 9;
- stripped and nested prototypes representative of embedded OpenWrt deployments.

The private corpus supplies supplemental field evidence only. Every release claim
requires minimized redistributable fixtures, recorded provenance, and public-boundary
tests independent of the private files.

The current reference investigation surface includes 993 dispatch endpoints and 38,862
physical call sites across the firmware tree. Product prioritization follows the
repeated factual joins required by that workload: symbolic callees, recursive argument
origins, provable call relations, corpus search, and content identity.

Vendor key material, credential hashes, and extracted secrets remain outside this
repository. Examples use placeholders or safely bounded prefixes and hashes.

## Recorded corpus sizing baseline

The last retained release-build export over the 260-file reference tree completed 252
bytecode files, explicitly skipped eight source files, and emitted one terminal result
for every input. The 252 chunks contained 344,120 physical instructions, 6,058
prototypes, and 38,862 physical `CALL` or `TAILCALL` sites.

That pre-correction run resolved 37,590 of 38,862 calls to a symbolic label or exact
prototype. The remaining 1,272 calls reported `open-register-window`; 1,220 had a
callee-register definition already handled by the analysis, concentrated in
`GETTABLE`, `GETGLOBAL`, `SELF`, `GETUPVAL`, and `MOVE`. This baseline established that
open vararg forwarding was a callee-completeness defect rather than evidence that the
target was dynamic.

The same run contained 3,662 provable call relations. Origin analysis reported 2,940
`control-flow-conflict` values, including 89 investigation-selected sink arguments, and
2,394 `unsupported-value` values. Constant-key table repacking was the dominant bounded
shape inside the latter category. These are historical coverage measurements, not
permission to infer taint, sink danger, or path feasibility.

Current `main` contains a focused open-window correction, but no retained full-corpus
replay has replaced this baseline. The LNUM32 qualification milestone must pre-register
its expected replay behavior, run the same input inventory, and publish the new counts
without rewriting this older measurement as though it came from the new candidate.

The baseline all-facts JSONL stream was approximately 776 MB; instruction and xref
records accounted for about 76% of it. Consumers commonly need only callee, origin,
relation, and prototype facts. No independently repeatable per-stage timing and
peak-memory benchmark is currently retained; PERF-008 requires that evidence before a
performance claim can be promoted.

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
8. Which literal global, table, local-alias, or closure-bound path names a call target,
   and which exact instructions establish that symbolic path?
9. Is a call argument a constant-leaf expression, parameter-dependent expression,
   upvalue, call result, other computation, or explicitly unresolved value?
10. Which statically provable prototype calls another, and which relationships remain
    ambiguous?
11. Which prototype bodies remain identical or change across firmware versions?
12. Which bounded alternative definitions can reach a value at a control-flow join,
    and which exact predecessor path supplies each alternative?

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
- Batch export can select required fact families without changing the identity,
  ordering, diagnostic, truncation, or per-file outcome contract of the retained facts.
- Structured query can apply one expression to an explicit file list and retain the
  same per-input identity and failure accounting as export.
- Every exported fact carries or directly references an input and interpretation
  identity, so interleaved records are joinable without retaining envelope state.
- Prototype records expose both artifact-local navigation identity and a versioned,
  documented content identity suitable for cross-firmware joins.
- A failed file cannot disappear from batch output or be converted into overall success.
- Output ordering, pagination, limits, exit status, stdout, and stderr behavior remain
  stable and documented.
- Capability output distinguishes code presence, experimental surfaces, and exact
  release evidence. A fixture-only library result cannot imply firmware readiness.

## Required factual resolution

- `CALL` and `TAILCALL` records expose an evidence-linked symbolic callee path when
  bytecode lookup, alias, and closure-binding facts establish one unambiguously.
- Callee identity is resolved from the callee register independently of fixed or open
  argument and result windows. Top-dependent writes invalidate only registers they can
  write; an open argument window remains an origin fact and cannot erase an unaffected
  callee value.
- A literal module-loader call may label a symbolic path with its constant argument,
  but the record identifies that basis and does not claim which runtime object the
  loader returns.
- Callee resolution through upvalues preserves every parent-to-child binding hop. A
  dynamic key, conflicting definition, unsupported boundary, or analysis limit yields
  an explicit unresolved reason rather than a guessed name.
- Selected registers and call arguments link to a bounded value-expression graph that
  distinguishes constants, parameters, upvalues, call results, concatenations, other
  computations, cycles, and explicit cutoffs.
- When multiple individually bounded definitions reach one use, the origin graph
  preserves evidence-linked alternatives rather than replacing the entire set with a
  plausible complete negative answer.
- A bounded `NEWTABLE` plus constant-key field-write sequence can expose a table-literal
  origin whose field values retain their own origins and instruction evidence.
- Operand origins are captured at the writing instruction. A destination that aliases
  an input, including `CONCAT A A C`, cannot recurse into its newly written value or
  silently degrade a known operand to unknown.
- Lua 5.1 `MOD` preserves operand provenance for the LuCI string-format convention
  `"format" % {arguments}` without treating every runtime modulo operation as string
  formatting or hiding its contributing operands.
- Recursive provenance identifies the leaf origins of an expression; the opcode
  `CONCAT` alone does not imply parameter dependence.
- Statically provable call edges link exact caller instructions to exact callee
  prototypes and their evidence. Dynamic dispatch, framework reachability,
  authentication, attacker control, and dangerous-sink labels remain caller judgments.
- All traversal and output have explicit depth, node, and size bounds. Exhaustion
  produces a machine-visible cutoff and never a plausible complete classification.

## Required LNUM32 public authority

The embedded profile requires a public compiler authority derived from Lua 5.1.5 and
an immutable revision of the official OpenWrt Lua package recipe and ordered patch
series. The authority manifest pins every bytecode-affecting input, including numeric
mode, integer tag, serialized string-width behavior, compiler flags, target toolchain,
and build command.

Source archive, OpenWrt revision, patches, configuration, and generated output establish
portable provenance. A native compiler executable hash identifies only that particular
platform/toolchain build. Private TP-Link chunks supplement compatibility evidence but
cannot define the format or promote the target.

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
- redistributable stripped LNUM fixtures reproducing the relevant layouts from each
  architecture family claimed by CI; private vendor chunks require explicit
  redistribution authority and never enter the repository by implication.

Each fixture records source provenance, source and output hashes, compiler or patch
identity, compiler arguments, platform, endianness, integer and number widths, and
integrality settings. Required tools and fixtures never skip silently.

Acceptance occurs at the public CLI and response-schema boundary. Independent oracles
and mutation probes must reject wrong widths, profile substitution, changed operands,
missing constants, incorrect child identities, executable closure descriptors, dropped
batch records, and stale or cross-revision evidence.

## Adjacent workflows

Whole-system reachability, sink classification, attacker-control analysis,
pseudo-code structuring, interpreter-semantic recovery, cross-language taint, native
SRE synchronization, and persistent research sessions may be valuable external layers.
`luad` may exchange provenance-bound mappings and factual schemas with those layers
without owning their execution or judgments. They do not enter the embedded Lua 5.1
release claim unless a future sprint gives a narrower deterministic fact its own public
contract and independent proof gate.
