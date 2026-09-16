# Sprint contract: retire the `luajit` planned tier

Lane: product. Roadmap position: item 3 under [next steps](../ROADMAP.md#next).

## Public outcome

`luad capabilities` stops advertising a LuaJIT dialect. The product boundary states that
LuaJIT is a separate bytecode system outside the product, so a `planned` tier for it is a
promise the product will not keep, and a reader comparing the manifest against the
roadmap gets two different answers.

After this change the capability manifest contains the five stock Lua dialects and
nothing else, and `planned_dialects` is empty.

## Target boundary

The `SupportTier::Planned` variant and the `planned_dialects` field stay. They are part
of the capabilities schema vocabulary at major 2, a future dialect may legitimately
occupy that tier, and emptying the list is the honest statement that nothing does today.
Removing the variant is a schema change with no current need.

## Paths allowed to change

- `crates/luad-core/src/capabilities.rs` — the dialect table and its unit tests.
- `crates/luad-oracle/tests/test_cli_e2e.rs`, `crates/luad-oracle/tests/test_release_lua54.rs`
  — assertions naming the retired dialect.
- `README.md`, `CHANGELOG.md`, `ROADMAP.md` — the limitations table, the release entry,
  and the retired roadmap item.

## Proof

- `test_capabilities_manifest_shape` and `test_capabilities_readme_status_consistency`
  assert the manifest's dialect set and its agreement with the README.
- A regression asserting no manifest dialect sits in the `Planned` tier and that
  `planned_dialects` is empty, exercised through the public CLI rather than the library,
  so the check follows the path a consumer actually takes.
- `bash scripts/check.sh` for the aggregate.

## Non-goals

No LuaJIT parsing, no dialect added, no schema major change, no removal of the
`SupportTier::Planned` variant or the `planned_dialects` field, and no change to any
other dialect's tier or evidence.

## Stop condition

Stop when the manifest no longer names a LuaJIT dialect and the documentation agrees.
Do not take any other roadmap item in this batch, and do not adjust another dialect's
tier because the table is open in the editor.
