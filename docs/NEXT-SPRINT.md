# Sprint contract: closure-valued argument origins (R-1c)

Lane: product lane. Base: `cfadac0` (v0.2.0).

## Outcome and public claim

Consumers identify callbacks passed as arguments rather than receiving an
`unknown{overwritten}` value.

A proven `CLOSURE` definition of an argument register emits a closed `prototype`
expression containing the child `ProtoPath` and closure-site evidence:

```json
{"kind":"prototype","prototype":"0/6/0","evidence":["proto:0/6:pc:6"]}
```

Render the identical typed fact across `origins` and `export --facts origin`.
Closure identity does not imply inference of captured values; existing mutable-
and ambiguous-capture safeguards remain unchanged.

## Allowed boundary

- `crates/luad-analysis/src/origins.rs`: add `OriginExpressionKind::Prototype`,
  transfer logic for `CLOSURE` recording child prototype path, and origin formatting.
- `crates/luad-cli/src/render/text.rs`: render `prototype <proto_path>` in human text output.
- `tests/schemas/origins.schema.json` and `tests/schemas/export.schema.json`: regenerated schemas.
- `docs/examples/origins.json`: updated example if affected.
- `tests/fixtures/origins.lua`: compiler-produced callback-argument fixture `f(function() end)`.
- `crates/luad-oracle/tests/test_argument_origins_lua51.rs`: exact JSON, JSONL, text, and export assertions.
- `tests/gates/gate-argument-origins-lua51.json`: gate specification, tests, and negative comparator mutation.
- `README.md`, `docs/MACHINE-INTERFACE.md`, `docs/examples/RECIPES.md`, and this contract: truthful documentation.

## Evidence

Run these focused checks against the candidate:

```console
cargo test -p luad-analysis --lib origins::tests
cargo test -p luad-oracle --test test_argument_origins_lua51 -- --nocapture
bash scripts/gates/gate-argument-origins-lua51.sh
```

- Assert exact JSON, JSONL, text, and export output for callback arguments.
- Schemas regenerated and validated against `luad schema origins` and `luad schema export`.
- Negative comparator mutation: prove that mutating or substituting the child prototype path or evidence is detected by `gate-argument-origins-lua51`.
- Run `bash scripts/check.sh` once on a clean candidate; report named gates, official compiler versions, and skips.

## Non-goals and stop condition

No CFG alternatives (R-1b), table-literal origins (R-1a), convention linking (R-2),
caller-unioned parameter substitution (R-3), or decompiler changes. Stop when proven
closure arguments report prototype expressions with exact child paths and PC evidence,
actual overwrites and ambiguity retain explicit unresolved reasons, and all named
checks pass on a clean candidate.

