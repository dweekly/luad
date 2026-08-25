# Active sprint: Lua 5.1 retrieval and machine-contract freeze

Lane: public semantic batch. Target: make every release-critical Lua 5.1 fact directly
retrievable through a coherent, fail-closed machine interface.

## Claim and researcher value

An external consumer can search and navigate constants, symbolic callees, constant-key
lookup labels, unresolved reasons, argument-origin shapes, exact and unresolved call
relations, prototype identities, and closure captures without decoding instructions or
joining ambiguous records by position.

Every accepted predicate applies its complete typed operand. Unknown fields,
unsupported operators, malformed values, and predicates whose operands cannot be
applied are usage errors rather than empty or overbroad answers. Pagination remains
bound to the complete query and input identity.

## Public contract batch

### Retrieval vocabulary

Extend the existing bounded query surface with one documented, table-driven vocabulary
covering:

- typed constants and exact string containment;
- callee resolution kind, symbolic path, lookup kind, and typed lookup key;
- callee and call-relation unresolved reasons;
- argument index and origin-expression kind;
- exact child-prototype call target;
- artifact interpretation identity and prototype content identity;
- forward and inverse closure-capture relations, including the physical closure site.

The implementation may query normalized in-memory facts or the same recursive export
records. It must not create a second decoder or a second semantic representation.
Predicates over typed values preserve their public type and byte identity; text
containment is defined only for string constants and rejects incompatible operand
types. All result ordering is deterministic.

### Capture-site identity

A capture relation identifies the parent prototype, physical `CLOSURE` instruction,
descriptor instruction, child prototype instance, child upvalue slot, and parent
register or upvalue source. When the same child prototype definition is instantiated at
multiple closure sites, forward and inverse xrefs remain distinct and return the binder
for the selected site. No relation is inferred from child-prototype position alone.

### Machine compatibility and process behavior

Document and enforce one compatibility rule for schema-major 1 analysis records:
structural fields and tagged result variants are closed within the major, while fields
explicitly documented as open vocabularies are represented so an unknown member can be
retained or rejected deliberately rather than silently misread. Canonical schemas,
capability output, examples, and deserialization tests express the same rule.

Publish one command/verdict/exit-code table for every public command. Successful
queries, no-match queries, invalid predicates, malformed input, validation findings,
resource exhaustion, and mixed batch results have distinct documented behavior where
their semantics differ. Machine stdout stays parseable; diagnostics and operational
messages stay on their documented channels.

Remove the nonfunctional `compile` command, its capability/schema/help entries, and
forward-looking product requirements. `luad` does not run compilers as part of the
release surface. Repository proof tooling may invoke pinned compilers independently.

### Tested composition recipes

Executable recipes cover:

1. exact and substring constant search over a firmware tree;
2. calls selected by a symbolic path or constant key;
3. calls grouped by unresolved reason;
4. fixed call arguments grouped by origin-expression shape;
5. forward and inverse multi-hop capture traversal with closure-site identity;
6. navigation between a call site and an exact child prototype when proven;
7. comparison by artifact interpretation identity and prototype content identity.

Prefer `export` plus a standard JSON processor when that path is clear and bounded. A
dedicated constant-search command is in scope only if the executable recipe demonstrates
a material correctness or usability advantage and reuses the same fact implementation.

## Acceptance design

Use one table-driven public matrix and one combined gate. The matrix includes positive,
zero-result, malformed, unknown-field, unsupported-operator, wrong-type,
ignored-operand, cursor-replay, cursor-tamper, and bound-exhaustion rows for every
predicate family. Every positive row proves exact selected records and deterministic
ordering through the live CLI. Every negative row proves a nonzero usage or resource
exit and no plausible partial answer on stdout.

The capture matrix instantiates one child prototype at two or more physical closure
sites with different register and parent-upvalue binders. It proves both traversal
directions and rejects a mutation that collapses the sites. Remaining killer mutations
include dropping a `contains` operand, stringifying typed constants, treating unknown
enum values as known, accepting a cursor from another predicate, and returning success
for an invalid predicate.

Schema tests deserialize representative current records and deliberately altered
open-vocabulary records according to the published compatibility rule. CLI tests cover
the complete exit table. Recipe tests execute documented commands against
redistributable fixtures and validate their results rather than snapshotting prose.

The private firmware corpus is a usability and sizing check, never an oracle. A final
release-build survey records query coverage, no-match/error behavior, elapsed time,
maximum resident set size, and a deterministic output hash. Any newly discovered
semantic becomes a minimized public fixture before changing acceptance.

## Allowed production paths

- query grammar, typed predicate evaluation, pagination binding, and result records;
- xref capture identity and traversal;
- CLI help, capability declarations, schemas, examples, and machine documentation;
- removal of the nonfunctional compiler-laboratory surface;
- one table-driven oracle family, recipe executor, and combined gate;
- compatibility fixes required by live negative controls in this batch.

## Non-goals

This sprint does not add decompilation, sink classification, taint analysis, receiver
identity, runtime reachability, framework routing, persistent research state, firmware
unpacking, dynamic interpreter execution, arbitrary dataflow predicates, or a new Lua
dialect. It does not promote a support tier or freeze a release artifact.

## Verification and stop condition

Acceptance requires the combined retrieval gate, affected existing semantic and machine
gates, aggregate repository checks, a model-diverse adversarial correctness review,
green pull-request CI, and a clean merged revision equal to `origin/main`.

The sprint stops rather than returning a result when a predicate operand cannot be
applied, a capture site is ambiguous, a cursor does not bind to the complete request, or
a compatibility case cannot be interpreted under the documented schema-major rule.
