# Active product batch: selectable recursive export fact families

Lane: product. Roadmap position: Stage 2 coherent automation contract.

## Public claim

`luad export --facts <FAMILY,...>` lets a firmware-tree consumer request only the
existing counted fact families it needs. Selection reduces emitted output and avoids
eagerly constructing unrelated analyses while preserving deterministic JSONL framing,
diagnostics, input attribution, and resource bounds.

The selectable names are exactly `prototype`, `prototype_identity`, `instruction`,
`constant`, `upvalue`, `xref`, `callee`, `origin`, and `call_relation`. The option takes
one non-empty comma-separated list. Unknown or duplicate names are usage errors with
empty stdout. Omitting `--facts` preserves the current family set, order, counts, and
stream shape.

Selection behavior applies to every currently recognized bytecode dialect. The evidence
boundary is the exact Lua 5.1.5 stock and LNUM32 profiles and exact Lua 5.4.8 target;
this batch does not promote any dialect or add facts to less-proven targets.

## Behavior and bounds

- Control records and diagnostics are always emitted and are neither selectable nor
  counted facts.
- An explicit selection is recorded once in `export_start.fact_families` in the fixed
  family order above. The field is absent when `--facts` is omitted, preserving the
  default stream contract.
- `available_fact_count`, `emitted_fact_count`, and `is_truncated` are computed over the
  selected families. `instruction_count` and `total_instructions` count selected,
  emitted instruction records and are zero when `instruction` is not selected.
- `--max-facts-per-file` applies after family selection. A bound never suppresses
  framing or diagnostics and never prevents later inputs from being processed.
- Prototype identity, xref, callee, origin, and call-relation analyses run only when
  their family is selected or a selected family has a real production dependency on
  them. Filtering an already-built all-family record list is insufficient.

## Allowed paths

Production:

- `crates/luad-cli/src/args.rs`
- `crates/luad-cli/src/main.rs`
- `crates/luad-core/src/envelope.rs`

Ordinary tests and existing evidence:

- `crates/luad-oracle/tests/test_batch_export.rs`
- `crates/luad-oracle/tests/test_batch_export_bounds.rs`
- `crates/luad-oracle/tests/test_machine_interface.rs`
- `tests/gates/gate-batch-export.json`
- `tests/schemas/export.schema.json`

Public documentation:

- `docs/MACHINE-INTERFACE.md`
- `docs/examples/RECIPES.md`
- `README.md`
- `CHANGELOG.md`

## Evidence

- A table-driven CLI regression covers every singleton family, a mixed selection, the
  explicit all-family selection, omitted-selection compatibility, and unknown,
  duplicate, and empty selections on maintained exact-target fixtures.
- Selected streams contain only the requested counted record types plus control records
  and diagnostics. Every emitted fact retains its existing context.
- A bounds regression composes selection with zero, exact, and truncating
  `--max-facts-per-file` values and recomputes all terminal counts from the stream.
- A direct production unit test proves the selection plan does not request unselected
  independent analyses. No source-text scanner or new gate is added.
- Focused command:
  `cargo test -p luad-oracle --test test_batch_export --test test_batch_export_bounds`.
- Existing named gate: `gate-batch-export`. The steward also runs the aggregate check
  once; the implementation agent stops at a reviewable candidate diff.

## Non-goals

No new fact family, analysis algorithm, query projection language, persistent export
configuration, schema-major change, dialect support claim, target promotion, benchmark
suite, or candidate qualification. Do not change the meaning or ordering of records in
the default unfiltered export.

## Stop condition

Stop when exact-target consumers can select any valid family set, unselected analyses
are not eagerly built, filtered counts and truncation are exact, invalid selections fail
closed, omitted selection preserves current behavior, and the focused regression plus
the existing batch-export gate pass. Do not expand selection beyond `export`.
