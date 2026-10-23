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
Tests live in `crates/luad-oracle/tests/test_machine_interface.rs`; update the existing
`tests/gates/gate-machine-contract.json`, `tests/schemas/export.schema.json`, the future
candidate's prerequisite spec hash in `tests/candidates/lua51-lnum32-rc1.json`, and indexed
README, machine reference, CHANGELOG, ROADMAP/checkpoint as needed. The emitted payload,
analysis, record order, schema version, support tier and consumer policy do not change.
This is not a schema-major transition or an interface freeze. Schema validation of
individual records does not prove stream ordering, completion or identity joins.
The newly required compiler uses GateSpec format 2; updating the future candidate's
prerequisite hash binds it to that stricter spec and does not rewrite accepted results.
No new gate framework or model review is required for a missing typed variant.
A separately reproduced nonfinite-float/null schema mismatch is outside this record-tag
correction and remains a blocking future machine-scalar obligation; do not claim every
possible payload now conforms.

## Executable evidence and stop condition

Before production edits, add `test_export_record_family_conforms_and_rejects_corruption`
and run `cargo build -p luad-cli --bin luad`, then
`cargo test -p luad-oracle --test test_machine_interface test_export_record_family_`.
Require official Lua 5.1.5, fail if absent, and retain the old failing schema result.
The test compiles small public source templates, exports actual CLI records, and checks:

- The default linked stream exercises every counted/control/diagnostic variant,
  including `parameter_field`, callee, origin, relation, prototype identity and link.
- Selected origin facts still validate and contain parameter fields; mixed source/read
  failures and capped terminal records validate without losing their explicit status.
- Each record validates against both live and checked-in schemas; variants are asserted
  by observed output. Corrupted parameter access/type/context and unknown tags fail.

Register the executed test in `gate-machine-contract`, record the now-required official
compiler/version hashes using the accepted Lua 5.1 authority, and run that existing gate
on the clean candidate plus one pinned-Rust `bash scripts/check.sh`. Require no failed
or ignored tests. Stop at a CI-green merged correction with a neutral checkpoint.
Select the public reference-reader/caller workflow separately after acceptance.
