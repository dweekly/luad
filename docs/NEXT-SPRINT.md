# Sprint checkpoint

Status: no implementation contract is active.

Fresh as of: 2026-10-22.

## Next outcome to contract

Choose **reliable artifact comparison**, the first batch in
[ROADMAP.md](../ROADMAP.md#a-correct-false-answers-before-expanding-analysis).
A user comparing builds must see a constant-only change; a result labeled identical
must be limited to an explicitly defined comparison, never behavioral equivalence.

Prepare a product-lane contract covering:

- `crates/luad-analysis/src/diff.rs`;
- the diff handler and rendering in `crates/luad-cli/src/main.rs`;
- `crates/luad-oracle/tests/test_analysis.rs` and an ordinary focused public CLI test
  if needed; identify its exact path in the contract;
- comparison documentation and the existing README index entries affected by it.

Before implementation, retain a public stripped Lua 5.1 source pair differing only in
one same-length string constant, and specify executable assertions for both default
and `--semantic` CLI output. Add identical-input controls and a field matrix covering
constant payloads/types, added/removed child prototypes, vararg/capture metadata,
layout, and selected debug fields. Set the exact commands, asserted comparison boundary,
fixture-generation authority, and stop condition in the contract. Reuse
`test_analysis`; do not invent a new qualification framework for an ordinary fix.

## Following work and boundaries

Convention-link correctness follows as a separate product batch. The firmware consumer
owns expression-cutoff preservation, actual call reachability, source coverage, and
its before/after measurement loop. Those dependencies and the public-workflow sequence
live only in the roadmap; private counts cannot substitute for public acceptance.

This checkpoint authorizes no production changes, schema changes, target promotion,
new dialects, automatic conventions, interprocedural unions, or release publication.
Replace it with one bounded contract before implementing. Remove accepted work from
that contract at closeout; retain history in commits, issues, and the changelog.
