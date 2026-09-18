# Feature-request delivery plan

Status: proposed sequencing for future feature selection.

Fresh as of: 2026-09-18.

This plan translates the remaining Deco research requests into bounded future sprint outcomes. It is not an active implementation contract: a new contract in [`NEXT-SPRINT.md`](NEXT-SPRINT.md) must select each outcome before work begins. Private firmware measurements prioritize the work but do not become fixtures, test authorities, or core security policy.

## Shared boundary and evidence

The product reports deterministic VM facts. It does not classify sinks, infer attacker-control, decide exploitability, reconstruct source, infer receiver types, or claim whole-program path feasibility. Each batch needs a public claim, allowed paths, public fixture authority, named evidence, and stop condition.

Start from the established gates:

```console
bash scripts/gates/gate-argument-origins-lua51.sh
bash scripts/gates/gate-symbolic-callees-lua51.sh
bash scripts/gates/gate-batch-export.sh
```

Extend an existing gate when it owns the same fact family. Add a gate only for a new interaction it cannot falsify. Every comparator needs a corruption control; required fixtures and compilers fail rather than skip. The steward runs the focused gate and one clean-candidate aggregate `bash scripts/check.sh`.

## 1. Constant-key table-literal origins (R-1a)

**Outcome:** Consumers inspect request-shaped objects passed between Lua functions without manual construction tracing.

**Public claim:** A bounded `NEWTABLE` plus constant-key `SETTABLE` sequence emits a deterministically ordered `table-literal`. Fields retain typed keys, origins, and write evidence. A safe partial reconstruction says `incomplete: true`; it never claims a partial object is complete.

**Implementation:** Add a distinct expression variant rather than overloading the existing positional table expression. Use a bounded backward scan from the consumed table register to its proven allocation and follow only already-safe aliases. Stop conservatively on dynamic keys, `SETLIST`, escapes, uncertain aliases, conflicting writes, unsupported boundaries, and resource limits. Raw physical instructions remain separate from the derived origin graph.

**Evidence:** Cover a complete object (`t.a = "x"; t.b = p.q; f(t)`), dynamic-key partial object, post-construction mutation, aliases, branch conflicts, `SETLIST`, and every relevant limit. Assert fields and evidence rather than counts. Add omitted and substituted-field negative controls to the origin gate.

**Stop:** Output preserves exact known fields and visible cutoffs without asserting array or dynamic-key semantics.

## 2. CFG alternatives for bounded definitions (R-1b)

**Outcome:** Consumers see bounded definitions reaching a join instead of an opaque `control-flow-conflict`.

**Public claim:** If all retained reaching definitions are bounded, `origins` emits a closed `alternatives` expression. Each option contains its origin and reaching-write evidence. It represents a union of definitions, not path feasibility.

**Algorithm rules:** Deduplicate structurally equal options while unioning sorted evidence; canonicalize output order; impose option, expression-depth, node, transfer-step, and output-size bounds. An unresolved predecessor or option overflow emits a visible cutoff, never a silently pruned result. Define loop fixed-point behavior before implementation and do not flatten alternatives through mutable captures or dynamic keys.

**Evidence:** Cover two literals over an `if`, literal versus parameter, equivalent predecessors, a loop/back edge, unresolved predecessor, and option overflow. Mutation probes must catch dropped, substituted, or incorrectly merged alternatives. This CFG semantic change requires the workflow's bounded independent algorithm review.

**Stop:** Results are deterministic, bounded, evidence-linked, and cannot be mistaken for taint or an end-to-end path assertion.

## 3. Corpus-wide `query --input-list` (R-4)

**Outcome:** One exact query runs across an explicit artifact list with per-input identity and failures retained.

**Public claim:** `query --input-list <file|-> --where <expression>` adopts export's batch input and outcome semantics, preserving order, duplicates, identity, and one result or failure outcome for every input.

**Implementation:** Reuse export's list parser rather than duplicating stdin, path, and bound handling. Define multi-input JSONL framing and terminal records before coding; retain the fail-closed predicate grammar; define per-input and aggregate limits. Source, malformed, unsupported, and limited inputs remain visible.

**Evidence:** Test file versus stdin lists, mixed input outcomes, duplicates, order, zero matches, malformed predicates, truncated streams, and equivalence to filtering export on the same public fixture tree. Create a query-specific gate only for behavior not owned by the batch-export gate.

**Stop:** No failed file becomes an apparently clean no-match result.

## 4. Export fact-family discovery (R-5)

**Outcome:** Consumers discover every accepted `export --facts` value at runtime.

**Decision first:** The research note lists ten names including `diagnostic`, but current code has nine selectable `ExportFactFamily` values and diagnostics may be unfiltered control records. The contract must choose and document one truth: publish the nine selectable families with always-emitted diagnostics, or make `diagnostic` a real bounded selection family with defined framing and counting.

**Implementation:** Make a canonical registry drive parsing, help, invalid-value errors, capabilities JSON, schemas, and documentation. Invalid-family errors include the sorted valid set; capabilities exposes the closed vocabulary.

**Evidence:** Assert help, capabilities, accepted parser values, and the selection matrix agree; test unknown, duplicate, empty, omitted, and invented values; mutation proves an absent family cannot be advertised.

**Stop:** Consumers need neither source inspection nor guessing.

## 5. Convention-gated cross-chunk linking (R-2)

**Outcome:** A corpus consumer connects a proved LuCI module label to its defining artifact and prototype when a named convention applies.

**Public claim:** Explicit mode such as `--link-convention luci-module-setglobal` indexes the literal `module("...")` plus literal exported `CLOSURE`/`SETGLOBAL` shape. It adds a definition only for a unique match; absent, duplicate, dynamic, and unsupported shapes have explicit statuses.

**Implementation:** Leave default `callees` bytecode-local. Put corpus indexing behind the convention and expose a separately schema-governed link fact or clearly versioned extension. Include defining input identity/path, target prototype, label segments, index/definition evidence, deterministic order, and bounds on inputs, index entries, traversal, and output.

**Evidence:** Use a redistributable mini-corpus for success, missing definition, duplicate module, malformed/dynamic declaration, source/unsupported input, and reversed input order. A mutation must reject an incorrect target or defining path. This new inter-artifact identity claim needs its own named gate.

**Stop:** The convention remains opt-in and auditable, never a universal Lua or runtime reachability claim.

## 6. Caller-unioned parameter substitution (R-3)

Defer this pending a design-and-evidence spike. It must not replace bytecode-local `parameter` origins. The spike defines cross-file call-site identity, admissible proven `callgraph` edges, recursion, callbacks, cycles, depth limits, and cutoff behavior.

Any future opt-in record must visibly carry `context: "union-over-callers"` and per-caller call-site evidence. It is a union, not evidence for one feasible end-to-end path. A production contract follows only with a demonstrated public consumer benefit.

## Documentation and public evidence (R-6 and R-7)

Documentation and fixtures ship with the fact they evidence.

- Audit [`docs/examples/RECIPES.md`](examples/RECIPES.md) before adding material; it already covers selective export, query, origins, callees, and firmware-shaped batches. Add only missing recipes for discovery, corpus query, table/closure origins, alternatives, and convention links. Explain that alternatives and caller unions are not path facts.
- Use minimized, redistributable stripped LNUM32 firmware-shaped fixtures from the pinned public authority. Manifest source, compiler inputs, command, output hash, profile, layout, and semantic assertions.
- Add architecture-family layouts only when provenance and a distinct retained claim need them. Never commit Deco binaries, vendor secrets, or private findings. Counts alone are not an oracle.
- Regenerate affected schemas and examples and update [`MACHINE-INTERFACE.md`](MACHINE-INTERFACE.md) and the README index in the same change.

## Proposed order

1. Constant-key table-literal origins.
2. CFG alternatives.
3. Corpus-wide query input lists.
4. Fact-family discovery.
5. Convention-gated cross-chunk linking.
6. Caller-unioned substitution only after its safety and consumer spike.

This order starts with local, provable origin facts, then adds corpus composition, and postpones inter-artifact and caller-union semantics until their identity and interpretation boundaries are explicit.
