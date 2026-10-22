# Active sprint: reliable artifact comparison

Fresh as of: 2026-10-22.

## Outcome and public claim

A maintainer comparing two builds must detect a same-count constant-only change.
The public reproduction is a stripped stock Lua 5.1 pair returning `old-command` and
`new-command`. Every output format and both instruction modes must report a change.
An identical decoded input is the positive control.

`is_identical` means no differences in the documented compared content under the
selected options. It never asserts execution or behavioral equivalence. Default mode
compares physical instruction words; `--semantic` compares decoded instruction facts
without depending on prose explanations, source offsets, or diagnostic rendering.
The comparison is conservative: decoded instruction descriptions retain every physical
word, including unused fields and companion data; no normalization claims runtime
equivalence or discards encoded differences. Avoid lifting constant payloads per
instruction merely to compare them.
Both modes retain exact constant representations, prototype shape/metadata, header/
layout declarations, and trailing bytes. Comparison remains positional rather than
an inferred alignment of reordered functions or instructions.

## Scope and invariants

Allowed production paths:

- `crates/luad-analysis/src/diff.rs`;
- the diff handler in `crates/luad-cli/src/main.rs` and the diff text renderer in
  `crates/luad-cli/src/render/text.rs`, and diff help in `crates/luad-cli/src/args.rs`,
  only where the contract requires clarification.

Allowed tests/evidence and documentation:

- `crates/luad-oracle/tests/test_analysis.rs`;
- generated `tests/schemas/diff.schema.json` descriptions, regenerated from the typed
  CLI schema without changing its shape;
- new ordinary CLI tests `crates/luad-oracle/tests/test_diff_cli.rs`;
- public source pair `tests/fixtures/comparison/before.lua` and `after.lua`, compiled
  during tests by required official Lua 5.1.5; retain no generated binary without a
  provenance manifest;
- `README.md`, `docs/MACHINE-INTERFACE.md`, `CHANGELOG.md`, `ROADMAP.md`, and this
  checkpoint, with corresponding existing README index entries.

Compare all constant kinds by exact raw representation and type. Equal NaN payloads
must compare equal despite floating-point `NaN != NaN`; distinct payloads and signed
zero must remain distinguishable. Compare string bytes, not display text. Ignore
source locations, artifact hashes, paths and derived stable IDs when comparing content.
Compare complete prototype/capture metadata, including varargs and added/removed
children. With debug selected compare source-name bytes, line definitions, line data,
local names/scopes and upvalue names; `--ignore debug` excludes exactly that metadata.
Debug names must not leak back through lifted operand/effect names in semantic mode.
Compare every modeled header field plus the resolved validated layout, excluding
selection/configuration/provenance bookkeeping. Preserve physical companion/data word
content in semantic mode rather than giving it independent effects.

Keep descriptions and previews bounded per differing field; never serialize an entire
large constant or instruction subtree merely to display a change. The existing parsed
input/prototype bounds limit traversal. Preserve the public response shape (JSONL carries chunk-header changes in the root
`diff_prototype` record rather than losing them) and existing
analysis eligibility; no dialect or capability promotion, new dependency, decompiler,
new gate framework, cross-build alignment algorithm, or unrelated cleanup.

## Executable acceptance

The steward builds the CLI before public-boundary checks:

```console
cargo build -p luad-cli --bin luad
cargo test -p luad-oracle --test test_analysis
cargo test -p luad-oracle --test test_diff_cli
bash scripts/check.sh
```

`test_diff_cli` must compile the public pair with the required compiler, fail rather
than skip if unavailable, and assert changed versus identical results in text, JSON,
and JSONL, both with and without `--semantic`. It must validate typed JSON content,
not only subprocess success or test-name presence. Include debug-selected versus
ignored controls and invalid `--ignore` selector refusal if the handler is touched.

The library matrix in `test_analysis` isolates constant payload/type changes, equal
and differing float bit patterns, child addition/removal, captures and varargs,
header/layout declarations, trailing bytes, same-length debug changes, debug-ignored
invariance, and a decoded operand change that prose-only comparison misses. Assert
which difference family carries each change. Positive controls must prove that
unchanged content and relocated provenance do not invent differences. Tests are the
negative controls for this production comparator; no self-declared result is proof.

## Review and stop condition

The implementation agent edits production and ordinary tests in one session and stops
with a reviewable diff; the steward reviews, formats, and runs verification. Obtain a
bounded independent review if decoded-instruction equality or authority remains
ambiguous after inspection. Do not weaken any pre-existing test.

The batch is eligible for integration only when focused assertions and one clean-
candidate aggregate check pass, documentation states the actual comparison boundary,
and known-false equality is removed from the advertised modes. Record results and
compiler identity in the handoff, remove the completed roadmap obligation, and restore
the neutral next-outcome checkpoint. Link correctness is the following separate batch.
