# Sprint contract: constant-key table-literal origins (R-1a)

Lane: product lane. Base: `9b8f0a1`.

## Outcome and public claim

Consumers inspect request-shaped objects passed between Lua functions without
manual construction tracing.

A bounded `NEWTABLE` plus constant-key `SETTABLE` sequence emits a deterministically
ordered `table-literal` origin expression:

```json
{
  "kind": "table-literal",
  "fields": [
    {
      "key": {"type": "string", "value": {"display": "a", "is_utf8": true, "raw_bytes": [97]}},
      "key_id": "proto:0:k:0",
      "value": {
        "kind": "literal",
        "value": {"type": "string", "value": {"display": "x", "is_utf8": true, "raw_bytes": [120]}},
        "evidence": ["proto:0:pc:1", "proto:0:k:1"]
      },
      "evidence": ["proto:0:pc:2"]
    }
  ],
  "incomplete": false,
  "evidence": ["proto:0:pc:0"]
}
```

Fields retain typed keys, value origins, and write evidence. A safe partial
reconstruction sets `incomplete: true` and never claims a partial object is complete.

## Allowed boundary

- `crates/luad-core/src/model.rs`: derive `PartialOrd, Ord` on `LuaString`.
- `crates/luad-analysis/src/origins.rs`: add `OriginExpressionKind::TableLiteral`,
  `TableLiteralField`, bounded backward scan reconstruction, deterministic sorting,
  and alias tracking.
- `crates/luad-analysis/src/query.rs`: query support for `table-literal`.
- `crates/luad-cli/src/render/text.rs`: render `table-literal` in human text output.
- `tests/schemas/origins.schema.json` and `tests/schemas/export.schema.json`: regenerated schemas.
- `tests/fixtures/origins.lua`: table-literal fixtures (complete object, dynamic-key, escape, alias).
- `crates/luad-oracle/tests/test_argument_origins_lua51.rs`: assertions for JSON, text, partial cutoffs, and omitted/substituted field negative controls.
- `tests/gates/gate-argument-origins-lua51.json`: updated fixture hash and expected tests.
- `README.md`, `docs/MACHINE-INTERFACE.md`, `docs/examples/RECIPES.md`, and this contract: truthful documentation.

## Evidence

Run these focused checks against the candidate:

```console
cargo test -p luad-analysis --lib origins::tests
cargo test -p luad-oracle --test test_argument_origins_lua51 -- --nocapture
bash scripts/gates/gate-argument-origins-lua51.sh
```

- Assert exact JSON, JSONL, text, and export output for complete and partial table literals.
- Schemas regenerated and validated against `luad schema origins` and `luad schema export`.
- Negative controls: omitted-field and substituted-field mutations in `gate-argument-origins-lua51`.
- Run `bash scripts/check.sh` once on a clean candidate; report named gates, official compiler versions, and skips.

## Non-goals and stop condition

No CFG alternatives (R-1b), convention linking (R-2), dynamic-key evaluation, array
semantics synthesis, or decompiler changes. Stop when constant-key table literals
report exact fields, origins, and visible `incomplete: true` cutoffs, and all checks pass.
