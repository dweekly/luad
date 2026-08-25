# Active sprint: provable Lua 5.1 call relations

Lane: semantic analysis. Target: expose an auditable partial call graph from unique
bytecode-local closure identities without claiming runtime reachability.

## Claim and researcher value

Every Lua 5.1 `CALL` and `TAILCALL` will carry one typed target-resolution result. When
validated closure construction, deterministic value flow, storage, lookup, and
invocation establish one child prototype, the result will link the caller instruction
to that exact artifact-local prototype. Otherwise it will state why no unique relation
is available.

Researchers will be able to ask which statically established call sites refer to a
prototype without reconstructing register assignments or confusing symbolic names with
prototype identity. The result is a bytecode-local relation, not a claim that the call
executes, is reachable from an external entry point, or retains that target after
unobserved runtime mutation.

## Contract

The analysis will consume the parsed prototype tree, shared semantic instructions, CFG
facts, closure-binding records, and existing symbolic callee facts. It will not decode
raw instruction words, infer source-language function names, or equate a symbolic path
with a prototype unless storage evidence connects them.

Each physical call receives exactly one result from a tagged union:

- `resolved`, containing the exact caller instruction ID, callee prototype ID, a closed
  resolution basis, and sorted stable evidence IDs;
- `unresolved`, containing the caller instruction ID, a typed reason, and all evidence
  available at the stopping boundary.

The closed unresolved taxonomy will distinguish at least missing definitions,
conflicting reaching definitions, multiple prototype stores for one symbolic location,
dynamic keys, observed mutation, open value windows, unsupported instructions,
unreachable calls, and declared analysis limits. A symbolic callee name without a
unique closure store remains unresolved.

The value domain will retain exact child-prototype identities through `CLOSURE`, `MOVE`,
fixed register writes, and validated parent-to-child upvalue bindings. It will preserve
the value present at a store instruction: a later `CLOSURE` reusing the same register
cannot retroactively change an earlier `SETGLOBAL`, `SETUPVAL`, or constant-key table
store. CFG joins retain one target only when every reachable predecessor agrees.

Global relations require one compatible closure store for the literal global name in
the analyzed chunk. Multiple stores, dynamic environment access, or evidence of a
non-closure value produce an explicit unresolved result. Upvalue relations require an
exact closure-binding chain and become unresolved when a shared capture can be mutated
ambiguously.

The CLI will expose `callgraph` in text, JSON, and self-identifying JSONL. Recursive
export will emit the same relation facts. Xrefs will expose a `calls` relation from the
call instruction to the child prototype for resolved records; unresolved calls remain
discoverable through the callgraph facts rather than disappearing.

## Acceptance matrix

One redistributable compiler-shaped fixture will cover direct local closure calls,
`MOVE` aliases, literal global store/load pairs, closure capture through three prototype
levels, parent-upvalue capture, and `TAILCALL`. It will include same-target CFG joins,
conflicting-target joins, unreachable calls, dynamic keys, open values, observed
mutation, and bounded analysis exhaustion.

An adjacent-closure sequence will pin the store-time rule: two `CLOSURE` instructions
reuse one register around intervening stores, and each later call must resolve to the
prototype held at its own store PC. A separate global-collision case will prove that a
name with multiple compatible stores is not guessed.

The matrix will assert one result per physical call, exact caller/callee owner paths,
sorted evidence, resolved/unresolved histograms, agreement across text, JSON, JSONL,
xrefs, and recursive export, and automatic plus explicit LNUM32 profile selection.

Killer controls will swap adjacent prototype targets, use the following register value
for an earlier store, drop a closure-binding hop, erase one conflicting predecessor,
turn a multiple-store result into a unique relation, remove one physical call fact,
invent a calls xref for an unresolved result, and mutate a stable evidence ID. Every
mutation must be rejected by a comparator that recomputes the expected relation from
the fixture rather than trusting the serialized result.

A supplemental customer-corpus survey may report relation coverage and unresolved
reason distribution. Those measurements guide later product choices and never decide
correctness or gate acceptance.

## Allowed production paths

- `crates/luad-analysis/src/callgraph.rs` and narrowly shared dataflow helpers
- `XrefRelation` integration without re-decoding instructions
- command parsing and rendering in `crates/luad-cli`
- recursive export and public capability/schema discovery
- redistributable fixtures, focused oracle tests, one gate spec and runner
- indexed machine-interface, recipe, status, architecture, and changelog documentation

## Non-goals

This sprint does not infer authentication, attacker control, sink severity, runtime
reachability, dynamic dispatch, module-loading behavior, callback execution order, or
whole-program side effects. It does not assign source names, add SSA, persist research
state, compute content hashes, expand query grammar, propagate prototype identity through
arbitrary call results or table aliases, or promote a support tier. A resolved relation
is not proof that a call executes in any particular deployment.

## Verification and stop condition

Acceptance requires the call-relation matrix and killer controls, canonical xref,
machine-interface, batch-export, and aggregate repository checks, green pull-request CI,
and a clean merged revision with local `main` equal to `origin/main`. The sprint stops
rather than converting a symbolic name, possible target, or corpus convention into a
unique prototype relation.
