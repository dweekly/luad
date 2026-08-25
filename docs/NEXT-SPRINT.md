# Active sprint: Lua 5.1 companion-word and capture safety

Lane: corrective semantic analysis. Target: prevent non-executable data and shared
upvalue mutation from producing plausible false call facts.

## Claim and researcher value

Two bounded Lua 5.1 semantic families will close together:

1. A closure or symbolic value captured from a parent local/upvalue remains known only
   when no parent write, descendant write, or sibling closure can mutate the shared
   upvalue cell.
2. When executable `SETLIST` has `C == 0`, its following physical word is a raw
   list-batch operand. That word is non-executable and cannot create effects, CFG
   branches, calls, origins, call relations, xrefs, or explanations as an opcode.

Researchers will not receive a resolved prototype target that may have been replaced
through a sibling closure, and arbitrary bits in a list-batch operand will not appear as
program behavior.

## Shared capture contract

Lua 5.1 closures that capture the same parent local share one upvalue cell. A capture
environment may preserve a value only when all relevant mutation checks agree:

- the parent does not write the captured register or upvalue on any path after the
  closure site;
- the receiving child or any descendant does not write the captured slot;
- no sibling closure captures the same parent register and writes its corresponding
  upvalue slot;
- for a parent-upvalue binding, the parent prototype and its descendants do not write
  that upvalue cell.

The callee and call-relation analyses use the same conservative mutation facts already
required by origin analysis. A rejected capture emits the existing `mutable-capture`
reason. It never degrades into a different plausible target. Unresolved relations never
emit a `calls` xref.

## Shared physical-role contract

Physical-role discovery scans executable Lua 5.1 code in PC order and classifies
non-executable companions before lifting or analysis:

- `CLOSURE` owns exactly the child prototype's declared number of following
  `closure_binding` descriptor words.
- Executable `SETLIST A B 0` owns exactly one following `setlist_extra` word whose
  complete raw `u32` value is the list-batch operand.
- A word already classified as a non-executable companion cannot itself own companions,
  regardless of the opcode bits it resembles.
- Missing, overlapping, or branch-targeted companion words are validation errors rather
  than guessed execution.

Disassembly and semantic IR preserve the extra word's physical PC and raw bytes, give it
the `setlist_extra` role, link it to its owning `SETLIST`, and expose its raw value as
data. It has no executable reads, writes, jump target, conditional skip, metamethod,
call kind, or standalone opcode explanation.

CFG remains physically auditable while deriving leaders, terminators, successors,
reachability, and dataflow only from executable instructions. Analysis enumeration uses
the shared role rather than re-decoding low opcode bits.

## Public surface

Text and structured disassembly render `setlist_extra` as a data continuation, not an
ordinary mnemonic. Explain identifies its owner and non-executable role. CFG, callee,
origin, callgraph, xref, query, and recursive export agree on the same physical role.

The existing Lua 5.1 closure-binding representation remains unchanged except that role
discovery cannot be confused by opcode-shaped companion data. No new command or security
classification is added.

## Acceptance matrix

One table-driven corrective family will prove capture safety for:

- one sibling closure that mutates a parent local captured by a separate caller closure;
- the same shape through a parent upvalue across an additional nesting level;
- mutation before versus after the relevant closure site;
- a non-mutating sibling, equal safe captures, and direct local closure flow;
- callee `mutable-capture`, unresolved call relation, and absence of a `calls` xref;
- agreement with origin analysis on the same shared-cell mutation shapes.

A synthesized physical-word family will cover `SETLIST C == 0` extra values whose low
bits resemble `CALL`, `TAILCALL`, `JMP`, `RETURN`, `CLOSURE`, and `SETLIST`.
It will prove:

- exactly one `setlist_extra` role at the expected physical PC;
- no invented call/origin/relation/xref or executable effects;
- no invented leader, successor, exit, or unreachable region;
- the real instruction after the extra word remains reachable and executes normally;
- a closure-binding word that resembles `SETLIST C == 0` does not consume another word;
- an extra word that resembles `CLOSURE` does not create closure bindings;
- missing, overlapping, and branch-targeted companions fail validation with stable
  diagnostics;
- text, JSON, JSONL, explain, CFG, and recursive export agree.

Independent acceptance enumerates executable calls from the physical-role contract, not
from the production lifter. Killer mutations remove the sibling scan, skip the
parent-upvalue scan, retain the stale prototype target, emit an unresolved `calls`
xref, execute the extra word, derive a branch from its bits, or let companion data own
another companion.

## Allowed production paths

- shared Lua 5.1 physical-role discovery, disassembly, lifter, and validator
- CFG handling of non-executable roles
- callee capture-safety logic and shared helpers used by origins/call relations
- existing explain/query/xref/export rendering only where shared role propagation
  requires it
- focused redistributable fixtures or synthesized chunks, corrective oracle tests,
  diagnostics, one combined gate spec/runner, schemas/examples, and indexed docs

## Non-goals

This sprint does not add constant-key labels, query predicates, SSA, decompilation,
runtime execution, general table analysis, sink policy, new dialects, or support-tier
promotion. It does not redesign every Lua 5.1 companion form or use private firmware as
an oracle.

## Verification and stop condition

Acceptance requires both corrective matrices and killers, all existing Lua 5.1
callee/origin/call-relation/closure/CFG gates, canonical machine and batch checks,
aggregate repository checks, a fresh model-diverse combined-area PASS, green pull-request
CI, and a clean merged revision equal to `origin/main`. The sprint stops rather than
preserving a capture or executing a word whose role is ambiguous.
