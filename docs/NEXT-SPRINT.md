# Active sprint: trustworthy convention-based module links

Fresh as of: 2026-10-22.

## Outcome and public boundary

A caller of `luci.sys.exec` must not acquire a target from a closure overwritten by
nil, a non-closure, or an unknown value; a module declaration that may not execute
must not establish an export namespace. An incomplete index must not prove a unique
target or absence. This is a conditional static binding under an explicit convention,
not runtime execution or security reachability.

Admit only straight-line Lua 5.1 root initialization with one directly loaded literal
`module` declaration before global stores. Extra arguments may load `package.seeall`. Admit only nonempty printable ASCII
selector bytes that need no byte-escaping (exclude quotes/backslashes); the existing
callee surface uses escaped byte labels, which must not alias literal raw names.
An escaped caller path is uncertainty, never proof of absence or a different target.
Reject branches/skips/loops, multiple declarations, stores before the declaration,
module aliases, unknown/root calls (including `require`), environment/table writes,
and executable code after a root return. Child bodies are not initialization execution.
Preserve central physical roles; descriptors/data do not act as instructions.

After admission, reuse shared global-store value facts. Keep root stores only, choose
the last store by PC for each exact raw name, and index it only if it is a closure.
Direct closure aliases and a final replacement closure remain useful positives.
Unknown/exhausted analysis refuses certainty. The admitted module CALL invalidates
its temporary register tail before any later read; only a final zero-result root
RETURN is admitted (an explicit returned value can replace package.loaded). Crafted, structurally valid bytecode
must not retain pre-call closure or literal facts there. Do not change shared callgraph
semantics in this batch.

## Scope and bounded behavior

Production: `crates/luad-analysis/src/linking.rs`; a root-only shared store entry point
in `callees.rs` if necessary to avoid walking child bodies; link-index preparation only
in `crates/luad-cli/src/main.rs`. No new dialect, convention, public record family,
policy, persistent state, whole-program interpreter, or capability promotion.

Count total retained definitions, including duplicates, against the existing cap.
Use canonical artifact order before capacity selection in the corpus builder and CLI
index pass, so a truncated index does not select targets by input order. Deduplicate
identical artifact identities for indexing; preserve export's existing file-stream order.
A failed input read/parse/analysis in the CLI prepass must make completeness uncertain.
Reject bytecode stdin with a linking convention before reading or writing: it cannot
be replayed by this two-pass interface. Document immutable corpus snapshots as a linking
precondition; target hashes identify index-pass bytes, not a transactional file snapshot.
Order ties for same-path/different-content library callers by complete reported facts.
Continue observing final unknown stores after the definition cap is reached.
Use the existing `dynamic`/`limit_exceeded` statuses, with no target attached. Duplicate
is justified by at least two admitted retained definitions; otherwise dynamic evidence
wins over a cap, then a cap wins over unique/absent. Do not scope unknown declarations
by guessed namespace. Preserve explicit convention selection, unsupported/absent/duplicate
outcomes when evidence is complete, limits, deterministic ordering, and stdout discipline.

Reuse parser bounds and linear role checks; do not introduce unbounded declaration
lookahead or dump raw constants/subtrees. Before lifting, cap a candidate root at 16,384 physical words and 16 MiB of
referenced constant representation bytes (count every use, including raw/display bytes).
These admission work budgets prevent repeated large constants from amplifying the
shared lifter. Each cutoff needs a limit outcome and a public negative/positive control,
never silent omission. Bound MOVE evidence chains at 64 steps before lifting and
retained index label payloads at 32 MiB (charge key and definition copies). Each needs
an isolated cutoff and a positive control, to bound evidence/prefix copying as well
as constant materialization.

Tests/evidence: `crates/luad-oracle/tests/test_cross_chunk_linking.rs` and
`tests/gates/gate-cross-chunk-link.json`. Compile new public source literals at runtime
with required official Lua 5.1.5. Crafted call-tail controls patch a required compiled
chunk using its declared layout and parsed offsets, assert structural validity, and
only parse/analyze the modified bytes; never execute them. Add no retained binary
without provenance.
Documentation: README, CHANGELOG, ROADMAP, MACHINE-INTERFACE, this checkpoint; update
existing index entries. Update generated schema descriptions only if typed comments
change, preserving shape. Shared authorities and other gate definitions remain frozen.

## Executable acceptance

Build CLI, then run:

```console
cargo test -p luad-oracle --test test_cross_chunk_linking
bash scripts/gates/gate-cross-chunk-link.sh <durable-result-directory>
bash scripts/check.sh
```

Required assertions, added to the existing gate:

- A table of final nil/number/unknown stores, conditional/unreachable/multiple/nested
  declarations, pre-declaration stores, aliases and possible clobbers never reports a
  stale target; dynamic or limited inputs do not masquerade as absence.
- Ordinary modules, `package.seeall`, direct export aliases and a final replacement
  closure resolve the exact expected artifact/prototype, with evidence. Never-called
  child stores cannot invent exports or overwrite a root export.
- Total-definition cap controls, a duplicate hidden at cap one in both orders, and
  mixed-label cap permutations prove deterministic statuses and no false unique target.
  Unrelated dynamic inputs downgrade a singleton; two retained definitions still prove
  duplicate. Exhaustion refuses certainty.
- Crafted call-tail controls must turn both the stale-closure and false-absence cases
  into uncertainty, with positive reinitialization controls.
- Public selected-fact JSONL checks the overwritten and positive pair, input-order
  permutation (normalized link facts), missing/corrupt provider inputs, bytecode-stdin refusal versus the ordinary stdin
  positive, and unselected convention. Existing negative/absent/duplicate/schema/limit controls remain intact.

Prove order invariance with a mixed-label capped corpus: status precedence alone is
not proof. Canonical preselection and an explicit permutation regression must establish
that property. Obtain bounded independent implementation criticism if any authority
ambiguity remains; a model verdict substitutes for no executable check.

## Stop condition

Stop the implementation session with one reviewable candidate. The steward formats,
reviews, verifies the focused suite, existing named gate and one clean-candidate aggregate
under pinned Rust, then integrates only the exact passing remote head. Retain compiler
identity, no-skip results and counterexamples; remove accepted obligations from the
roadmap and restore a neutral checkpoint. Consumer correctness is the next separate
outcome, owned in its private repository.
