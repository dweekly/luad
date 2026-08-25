# Active sprint: sound symbolic callee facts

Lane: semantic analysis. Target: emit one auditable resolution result for every Lua 5.1
`CALL` and `TAILCALL` without allowing control-flow ambiguity to become a guessed name.

## Claim and researcher value

Every call instruction will produce either an evidence-linked symbolic path or a typed
unresolved reason. The supported resolved paths will cover literal globals, constant-key
table lookups, literal `require` module labels, deterministic register aliases, and
closure captures whose parent value is unambiguous.

This gives firmware researchers a trustworthy denominator for call-site surveys. A
consumer can distinguish incomplete analysis from the absence of a call and does not
need to reimplement Lua register and closure tracking to discover common LuCI APIs.

## Contract

The analysis will operate on parsed prototypes, shared semantic instructions, and the
existing CFG and closure-binding facts. It will not decode raw instruction words in the
analysis crate.

The abstract value domain will contain an explicit bottom, symbolic label paths, literal
strings, closure identities, and unknown reasons. Global and module paths are labels, not
runtime object identities, and their distinct bases participate in equality. Each value
will carry the stable instruction IDs that establish it. `require("luci.sys")` creates a
module label only when the callee is the literal-global `require` label (including a
deterministic alias), the call has exactly one literal string argument and exactly one
result, and no open register window participates.

Forward register analysis will traverse reachable basic blocks in deterministic
reverse-postorder to a bounded fixed point. Bottom is the meet identity; each register
descends monotonically from bottom to one value to unknown. A join retains a value only
when every reachable predecessor supplies the same basis and value. Evidence at a
surviving join is the sorted, de-duplicated union from every predecessor. Conflicting,
missing, loop-mutated, dynamic-key, open-register, unsupported-instruction, path-limit,
analysis-limit, and ambiguous-capture cases remain explicitly unresolved. Transfer
functions eagerly read their source state before applying writes, and paths have a fixed
segment bound.

All 38 Lua 5.1 opcodes will have an explicit register-write classification. Fixed and
open ranges invalidate every potentially written register; an unclassified instruction
invalidates the whole frame. Conditional writes use edge-specific state when the value
cannot be retained on both successors. Closure-binding descriptors do not execute in the
parent dataflow.

A captured parent local is a live reference rather than a snapshot. The analysis will
propagate it only when the source definition dominates the closure, no other parent write
can mutate that register, and no relevant child or descendant `SETUPVAL` can mutate the
shared value. Other captures receive `mutable-capture` or `ambiguous-capture`.

Every public callee fact will contain the call instruction ID and prototype path, call
kind, callee register, and a tagged resolution union. Resolved variants contain a label
basis, path, and stable evidence; the unresolved variant contains one closed reason enum.
The CLI will expose a bounded `callees`
analysis command in text, JSON, and self-identifying JSONL. Recursive export will emit
the same fact type for every prototype.

## Acceptance matrix

A single table-driven semantic matrix will prove all supported transfer functions and
their combinations:

- `GETGLOBAL`, `MOVE`, constant-key `GETTABLE`, and `SELF` paths;
- literal `require` results followed by table lookups;
- same-block aliases, identical values joining across branches, strict-dominator values,
  and conflicting branch definitions;
- local-register and parent-upvalue closure captures across at least three prototype
  levels, plus conflicting instantiations of one child prototype;
- loops that preserve a value and loops that may mutate its defining register;
- dynamic keys, open argument/result ranges, overwritten registers, unsupported writes,
  and unreachable code;
- complete write classification for all 38 opcodes, range invalidation, conditional
  writes, and closure descriptors that never execute as parent transfers;
- captures mutated after closure construction and captures mutated through `SETUPVAL`;
- one explicit resolved or unresolved fact for every `CALL` and `TAILCALL`;
- deterministic text, JSON, JSONL, recursive export, schema, and capability discovery.

Killer controls will delete a call fact, replace an unresolved result with a path, mutate
one evidence ID, omit one predecessor's evidence at a join, leak one predecessor value
through a conflict, substitute a module label for runtime object identity, retain a value
through a range write, and retain a local captured before a later mutation. Each mutation
must be rejected by typed comparison or schema validation. The public fixture matrix will
pin a resolution/reason histogram so coverage regressions are visible without a private
corpus.

Redistributable source fixtures will be compiled by the exact Lua 5.1 authorities. A
separate corpus survey may measure usefulness and unresolved-reason distribution, but it
will never decide correctness or gate acceptance.

## Allowed production paths

- `crates/luad-analysis/src/callees.rs` and its public exports
- command parsing and rendering in `crates/luad-cli`
- export records and public capability/schema discovery
- redistributable fixtures, focused oracle tests, one gate spec and runner
- indexed machine-interface, recipe, status, and changelog documentation

## Non-goals

This sprint does not classify sinks, infer attacker control, resolve dynamic table keys,
perform points-to analysis, identify arbitrary runtime objects, construct a complete call
graph, compute argument origins, add persistent state, or promote a support tier. It does
not promise a particular corpus coverage percentage.

## Verification and stop condition

Acceptance requires the focused callee matrix and killer controls, canonical machine and
batch-export regression gates, aggregate repository checks, green pull-request CI, and a
clean merged revision with local `main` equal to `origin/main`. The sprint stops rather
than weakening a transfer rule when a value cannot be proved at a control-flow join.
