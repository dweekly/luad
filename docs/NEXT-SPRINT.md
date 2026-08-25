# Active sprint: constant-key Lua 5.1 call labels

Lane: bounded semantic feature. Target: preserve a literal call-selection key when the
receiver identity is not provable.

## Claim and researcher value

For a Lua 5.1 `CALL` or `TAILCALL` whose callee value comes from constant-key
`GETTABLE` or `SELF`, `luad` will emit a typed lookup label even when it cannot prove a
global, module, or exact-prototype callee. The label records only:

- whether selection used `GETTABLE` or `SELF`;
- the exact typed constant key;
- the lookup instruction and all value-preserving alias/capture evidence between that
  lookup and the call.

The label does not identify the receiver, implementation, runtime target, framework
route, or reachability. It is not a resolved symbolic path or a provable call edge.

This lets a caller retrieve literal selectors such as `execute`, `call`, or `format`
without reimplementing Lua register flow.

## Public semantic contract

`CalleeResolution` gains a distinct tagged lookup-label result. It is not encoded by
adding a rootless segment to `ResolvedPath`.

The structured result uses `status: "lookup-label"` and contains:

- `lookup_kind`: `gettable` or `self`;
- `key`: the selected `luad_core::model::ConstantValue` using its normal machine
  encoding unchanged;
- `evidence`: a `StableId` array normalized by lexicographic sort and deduplication,
  including every contributing lookup instruction and accepted alias or capture hop.

The result carries no receiver register, receiver path, or receiver-derived field.
Consumers may treat every evidence member as a contributing proof site, never as a
unique receiver or lookup site.

A string key is expected to provide the main firmware value, but the machine contract
retains the typed constant rather than silently stringifying numbers or booleans.
Human text may render an escaped, bounded preview while structured output retains the
normal constant representation and output limits.

The label propagates through the same bounded, control-flow-aware mechanisms used for
stronger callee facts:

- register `MOVE` aliases;
- equal joins that preserve the same lookup kind and typed key while retaining every
  contributing lookup instruction and unioning all evidence;
- safe parent-to-child closure captures;
- repeated instantiation sites only when their joined lookup labels are equal;
- the analysis and path bounds defined by the public contract.

It stops explicitly at dynamic keys, conflicting keys or lookup kinds, overwrite,
mutable or ambiguous capture, unsupported instruction, open register window, or
analysis exhaustion. An equal literal key selected from different unknown receivers may
join because the fact claims only the selector, not receiver equality.

Join equality requires the same constant type tag and byte-identical serialized value;
it is never numeric or stringified equality. Positive and negative zero conflict, and
NaN keys are conservatively excluded from equal joins even when their payload bytes
match. A single NaN-key lookup still emits a typed label; a join blocked only by this
NaN rule stops with `control-flow-conflict`.

When a receiver has a provable global or module symbolic path, the
`ResolvedPath` result remains stronger and unchanged. A directly constructed closure
remains `ResolvedPrototype`. Constant-key labels do not create exact call relations or
`calls` xrefs. `CallRelationUnresolvedReason` gains `lookup-label-only`, and the
unresolved relation retains the lookup label's evidence. `CalleeUnresolvedReason` gains
no variant, and its total conversion into call-relation reasons remains unchanged.
The new reason is an additive member of a closed enum under the documented pre-1.0
schema-major-1 stability policy; the retrieval-freeze stage will define the general
post-freeze compatibility rule for analysis vocabularies.

## Acceptance matrix

One table-driven Lua 5.1 family will cover:

1. `GETTABLE` with an unknown receiver and a literal string key immediately called.
2. `SELF` with an unknown receiver and a literal string key immediately called.
3. Register aliases between lookup and call.
4. Equal-key joins across control-flow branches with deterministic evidence union.
5. The same equal key selected from different unknown receiver registers.
6. Conflicting keys and conflicting `GETTABLE`/`SELF` forms.
7. Dynamic RK register keys.
8. Overwrite after lookup.
9. Safe local and parent-upvalue capture, plus mutable and ambiguous capture rejection.
10. Repeated child-prototype instantiation with equal versus conflicting labels.
11. A provable global/module receiver retaining the stronger `ResolvedPath` result.
12. Non-string RK(C) constants producing typed labels without stringification, with the
    independent decoder proving the Lua 5.1 operand encoding; signed-zero and NaN join
    boundaries are explicit rows.
13. Analysis-bound exhaustion and unreachable calls retaining their explicit stop
    reasons.
14. Callee-path query predicates will not match lookup labels; no lookup-label predicate
    enters the grammar in this sprint.

For every positive row, independent acceptance checks exact lookup kind, typed key,
ordered evidence set, physical call ID, text rendering, JSON/JSONL, recursive export,
and deterministic repetition. It also checks that call relations remain unresolved and
no exact `calls` xref is emitted.

The acceptance model decodes the synthesized Lua 5.1 words and performs its own bounded
register-flow calculation. It does not call production callee transfer, joins, capture
derivation, renderer, or schema types to decide the expected result. Killer mutations
must reject at least: dropping the key operand, treating every label as `SELF`, merging
different keys or lookup kinds, replacing byte-exact key comparison with numeric
comparison, dropping one branch's lookup evidence, erasing an alias evidence hop,
emitting a receiver-derived field, converting a lookup label to `ResolvedPath`,
downgrading a provable `ResolvedPath` to a lookup label, emitting an exact call edge,
and replacing an explicit stop reason with a plausible label.

## Corpus outcome check

The private reference corpus is a sizing check, not an oracle or release gate. After
the public matrix passes, one release-build survey will report:

- total call sites;
- counts by `ResolvedPath`, `ResolvedPrototype`, lookup label, and each unresolved
  reason;
- lookup-label counts by `GETTABLE` and `SELF`;
- `overwritten` and `unsupported-value` counts;
- deterministic output hash across two identical invocations;
- elapsed time and maximum resident set size using the documented measurement method.

The survey reports constant-key `SELF` and `GETTABLE` selections separately. Their
counts carry no acceptance threshold or pass condition and remain supplemental product
evidence rather than a public correctness claim.

Any public semantic discovered by the survey is minimized into a redistributable row
before it can affect the contract.

## Allowed production paths

- Lua 5.1 callee value, transfer, join, and capture representations
- call-relation mapping needed to preserve the no-exact-edge boundary
- text, JSON, JSONL, query, and recursive-export rendering of callee facts
- callee and callgraph schemas, examples, capability descriptions, and indexed docs
- one table-driven oracle family and one combined gate using synthesized or maintained
  redistributable fixtures

## Non-goals

This sprint does not infer receiver identity, runtime object type, actual method
implementation, framework routing, sink danger, attacker control, reachability,
prototype call edges, general table contents, SSA, or decompiled syntax. It does not
add a dedicated search command, broaden query grammar, change support tiers, repair the
site-accurate repeated-instantiation `Binds` xrefs assigned to the retrieval stage, or
add a dialect.

## Verification and stop condition

Acceptance requires the independent matrix and live killer probes, the symbolic
callee, call-relation, origin, closure, semantic-safety, machine-contract, and batch
gates, aggregate repository checks, a model-diverse correctness PASS, green pull-request
CI, and a clean merged revision equal to `origin/main`.

The sprint stops rather than emitting a label when the key, lookup form, evidence chain,
or preservation boundary is ambiguous. It stops rather than upgrading a lookup label
to a symbolic path or exact call edge without receiver or prototype proof.
