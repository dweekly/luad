# `luad` roadmap

This roadmap is forward-looking and evidence-gated. A milestone is complete only
when its canonical gate passes with every required positive and adversarial probe,
no required skips, and a verified result artifact. Feature presence and aggregate
test success are not substitutes for a named gate.

The authoritative implementation sequence and checkpoint contents are in the
[coding-agent execution plan](docs/CODING-AGENT-PLAN.md).

## Release boundary

The first release candidate targets an exact, reliable vertical slice:

- public parsing and disassembly for official Lua 5.4.8;
- explicit Lua 5.1 layouts and vendor profiles required for embedded firmware;
- public Lua 5.1 closure-capture facts and resolved constant operands;
- deterministic, schema-governed output for human and agent callers;
- capability claims derived from verified gate artifacts.

All dialects remain experimental until the release-promotion gate says otherwise.
New dialects, decompilation, persistent project state, overlays, and neighborhood
features remain outside the release critical path.

## C0: Truthful claims and canonical gates

Make the proof and documentation surface internally consistent:

- classify static semantic effects as reviewed or unverified;
- pin source citations to exact upstream versions;
- generate evidence only from verified gate results;
- provide exactly one canonical wrapper and specification per gate;
- reject orphan gates, duplicate IDs, and specifications missing required probes.

Exit gate: `gate-proof-harness` plus the C0 CLI and harness tests.

## R6: Public Lua 5.4.8 disassembly conformance

Move operand interpretation out of generic text formatting and into a typed,
reusable production disassembly record. Prove the public JSON record through
three independent paths: the exact official listing, an independent reference
decoder, and the production decoder/lifter. Add normalized public text goldens.

The gate must cover signed operands, opcode-specific `k` placement, source lines,
jump targets, metamethod annotations, resolved constants, invalid references, and
renderer/serializer mutation controls.

Exit gate: `gate-public-disasm-lua54-8` and checkpoint R6.

## R3 and R4: Analysis and losslessness review

Review rather than assume the existing implementation:

- R3 proves complete dominator sets, exact immediate dominators, analysis
  preconditions, and one public CFG representation.
- R4 proves model-driven byte-identical serialization, mutation locality,
  gap-free byte classification, and a public validation record.

Exit gates: `gate-analysis-r3` and `gate-lossless-lua54-8`.

## F1: Lua 5.1 layouts and profiles

Prove that one immutable `ChunkLayout` drives byte order and every declared
width. Cover official 32-bit and 64-bit `size_t` fixtures, debug and stripped
chunks, explicit LNUM profile selection, cross-profile rejection, precise
diagnostics, and public layout/profile output.

Exit gates: `gate-layout-lua51-stock` and `gate-profile-lua51-lnum`.

## F2: Public closure bindings

Represent the words following Lua 5.1 `CLOSURE` as lossless physical binding
descriptors rather than executable instructions. Expose ordered parent-to-child
captures through disassembly, JSON, queries, and forward/inverse xrefs, while
excluding descriptors from effects and CFG nodes.

Exit gate: `gate-closures-lua51`.

## F3: Public resolved operands

Resolve every constant-bearing Lua 5.1 and in-scope Lua 5.4 operand through the
same typed disassembly record. Preserve encoded indices and exact typed values;
keep text previews escaped and bounded. Invalid indices must produce diagnostics,
never fabricated `nil` values.

Exit gate: `gate-resolved-constants-lua51` plus its exact Lua 5.4 companion scope.

## F4: Reproducible embedded-field evidence

Maintain redistributable minimized fixtures for every field defect and a
reproducible report format for the private TP-Link corpus. Corpus parse and
validation counts remain supplemental evidence, not semantic proof.

Exit gate: `gate-field-reproducers-lua51`.

## R5: Evidence-derived release promotion

Assemble one release manifest from verified R1, R2, R3, R4, R6, F1, F2, F3, and
F4 results produced from the same clean revision. Generate capability and README
status from that manifest and promote only the exact releases, layouts, and
profiles represented by it.

Exit gate: the precisely scoped release gate defined at R5.

## After the first release candidate

Two independent tracks may then proceed:

1. instrument a pinned official runtime to verify semantic register, stack, and
   upvalue effects;
2. add composable research primitives in this order: exact retrieval,
   presentation-only overlays, full-fidelity deterministic export, and bounded
   neighborhood traversal only if export proves insufficient.

Persistent interpretations, hypotheses, researcher sessions, and agent planning
remain outside `luad`.

Before adding another dialect, make an explicit product decision between a stock
Lua correctness reference and a practical ecosystem reverse-engineering tool. If
the latter is chosen, evaluate LuaJIT and Luau before expanding low-usage stock
dialect coverage.
