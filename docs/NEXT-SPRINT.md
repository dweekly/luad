# Export record variant coverage

Fresh as of: 2026-10-22. Lane: product; no compatibility or target promotion.

## Outcome and public claim

A consumer must have a typed schema variant for every current `luad export` record
tag. The ordinary finite-valued fixture streams must validate against `luad schema export`. The CLI currently emits `parameter_field` but omits its variant
from the schema enum. Independent python-jsonschema validation of the official-compiled
`origins_parameter_fields.lua` stream rejects those records. Correct the typed schema
coverage without weakening required context, discriminators or payload types.

## Scope and non-goals

Production scope is the `ExportRecord` schema enum in `crates/luad-cli/src/main.rs`.
Tests live in `crates/luad-oracle/tests/test_machine_interface.rs`; update the schema
golden and indexed README, machine reference, CHANGELOG, ROADMAP/checkpoint as needed.
Keep the existing machine gate spec and archived RC1 specification immutable. Extend
the gate-owned export test with the new executable family assertions rather than
changing the archived prerequisite identity. Required official Lua 5.1.5 generates
ordinary test inputs; this schema check establishes no compiler/target qualification.
The emitted payload, analysis, order, schema version and support tier do not change.
Individual record validation does not prove ordering, completion or identity joins.
No new proof framework or model review is needed for a missing typed variant.
A separately reproduced nonfinite-float/null schema mismatch remains a future scalar
obligation. Do not claim every possible payload now conforms.

## Executable evidence and stop condition

Extend `test_jsonl_streaming_batch_export_deterministic_and_recursive` with the
`assert_export_record_family_conforms_and_rejects_corruption` helper. Run
`cargo build -p luad-cli --bin luad`, then
`cargo test -p luad-oracle --test test_machine_interface test_jsonl_streaming_batch_export_`.
Require official Lua 5.1.5, fail if absent, and retain a failing run against the previous
CLI, proving the existing canonical test reaches the new assertions.
The test compiles small public source templates, exports actual CLI records, and checks:

- The default linked stream exercises every counted/control/diagnostic variant,
  including `parameter_field`, callee, origin, relation, prototype identity and link.
- Selected origin facts still validate and contain parameter fields; mixed source/read
  failures and capped terminal records validate without losing their explicit status.
- Each record validates against both live and checked-in schemas; variants are asserted
  by observed output. Corrupted parameter access/type/context and unknown tags fail.

Run the existing unchanged `gate-machine-contract` spec on the clean candidate and
one pinned-Rust `bash scripts/check.sh`. Retain compiler version/hash observations
separately: the archived gate spec does not assert compiler qualification. Require no
failed/ignored tests. Stop at a CI-green merged correction with a neutral checkpoint;
select the machine-scalar and reference-reader/caller outcomes separately.
