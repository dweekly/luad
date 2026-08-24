# `luad` product roadmap

Status: authoritative product direction. Exact implementation and acceptance details
belong only in [the active sprint](docs/NEXT-SPRINT.md).

## Product direction

`luad` is a deterministic, stateless fact tool for compiled Lua. It should make
bytecode easy for a human researcher or external agent to inspect, validate, query,
and compose without embedding researcher judgment, project memory, or security
classification in the executable.

Every capability remains experimental until an exact target release closes over its
public-boundary evidence. Product growth follows the sequence below.

## 1. Validator authority and diagnostic discoverability

Validation, disassembly, and analysis need one dialect-owned understanding of operand
roles so raw bitfields cannot acquire inconsistent meanings across consumers. Every
public diagnostic needs discoverable semantics, severity, category, and a useful next
action.

Prototype references must retain their owning prototype path in every structured fact,
comment, text rendering, and xref. Direct register fields, implicit register spans, and
non-register scalar fields need independently proved domain rules before target
qualification.

Qualification advances through separately accepted slices for conditional RK
operands, closure-capture source bounds, implicit register spans, and public diagnostic
discoverability. Each slice owns one field or semantic distinction and one canonical
gate.

Operand-role slices derive their authority from executed Lua 5.1 VM semantics, with
the official opcode-mode table serving as a mechanically checked input rather than an
unexamined authority. Contextually ignored fields and declared roles that the VM does
not read must be named in the acceptance oracle. Unsigned size hints and counts such
as `NEWTABLE.C`, `SETLIST.C`, and `TFORLOOP.C` must never
acquire register diagnostics.

Prototype-identity acceptance compares every referenced child path across disassembly,
queries, xrefs, and export. A surface may not render a raw child index as a top-level
prototype path.

Exit outcome: valid compiler-produced fixtures have no unjustified diagnostics,
targeted corruptions produce exact documented diagnostics, and every emitted code is
present in the public catalog. Acceptance also exercises manifest-pinned,
redistributable embedded-firmware cases that contain operand values and prototype
depths absent from small compiler fixtures.

## 2. Exact Lua 5.1 target qualification

Stock Lua 5.1 layouts and the supported LNUM32 profile need separate promotion
boundaries. Each target must identify its compiler or vendor authority, profile,
layout, public fixtures, schemas, supported command surfaces, and known limitations.

Qualification includes a reproducible corpus manifest with artifact provenance,
expected parse status, expected validation verdict, and bounded execution. Plain Lua
source and supported bytecode profiles remain distinguishable outcomes. Private
corpora may supplement this evidence but cannot be the only promotion proof.

Exit outcome: a release manifest promotes one exact Lua 5.1 profile/layout target at
a time. Evidence for one target cannot substitute for another.

## 3. Stable machine consumption

Human and AI callers need schema-versioned JSON and JSONL with deterministic ordering,
bounded strings, stable interpretation-scoped identifiers, and explicit compatibility
rules. Schema evolution must preserve discoverability and reject incompatible majors.

Exit outcome: every advertised response and stream record validates at the live CLI
boundary, and consumers can negotiate or reject schema versions without prose parsing.

## 4. Composable research facts

Researchers need direct factual primitives for constants, globals, calls, prototypes,
captures, control flow, and artifact comparison. External tools should be able to
persist names, hypotheses, and cross-session findings while `luad` remains stateless.

Exit outcome: representative reverse-engineering workflows are expressible through
documented CLI composition without adding decompiler judgment, sink classification,
or project state to `luad`. Query gates prove that changing a predicate operand changes
the result set, and bounded register-provenance facts remain eligible only when they can
be expressed without inferred names, security labels, or persistent project state.

## 5. Additional dialect qualification

Lua 5.2, 5.3, 5.5, LuaJIT, and vendor profiles advance independently. Parser presence
does not imply semantic, analysis, or release support.

Vendor qualification may consume an explicit, provenance-bound description of opcode,
header, field-layout, and numeric-format mappings recovered by an external tool.
Interpreter execution, gadget testing, and firmware rehosting remain outside `luad`;
the imported mapping and every normalized fact require deterministic validation and
target-specific evidence.

Exit outcome: each dialect or profile follows the same exact-target fixture, oracle,
machine-contract, and promotion discipline used by qualified Lua targets.

## Dependency order

```text
validator and diagnostic authority
  -> exact Lua 5.1 target qualification
       -> stable machine consumption
            -> composable research facts

additional dialect qualification depends on the relevant machine, validator,
and exact-target evidence boundaries.
```

## Persistent exclusions

The roadmap does not place these responsibilities inside `luad`:

- decompilation or pseudo-code generation;
- vulnerability and dangerous-sink classification;
- attacker-control or exploitability judgments;
- inferred names presented as facts;
- persistent projects, annotations, hypotheses, or sessions;
- autonomous research planning;
- firmware unpacking, target-interpreter execution, or dynamic gadget testing;
- execution of untrusted Lua bytecode.

Those capabilities belong in composable external layers unless a future roadmap
revision establishes a narrowly factual primitive that `luad` alone must own.
