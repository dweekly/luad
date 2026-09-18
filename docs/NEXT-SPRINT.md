# Sprint contract: CFG alternatives for bounded definitions (R-1b)

Lane: product lane. Base: `d157878`.

## Outcome and public claim

Consumers see bounded definitions reaching a control-flow join instead of an opaque
`control-flow-conflict`.

If all retained reaching definitions are bounded, `origins` emits a closed `alternatives`
expression containing a deduplicated, deterministically ordered list of candidate origin
expressions, each with its reaching evidence:

```json
{
  "kind": "alternatives",
  "options": [
    {
      "kind": "literal",
      "value": {"type": "string", "value": {"display": "left", "is_utf8": true, "raw_bytes": [108, 101, 102, 116]}},
      "evidence": ["proto:0:pc:1", "proto:0:k:0"]
    },
    {
      "kind": "literal",
      "value": {"type": "string", "value": {"display": "right", "is_utf8": true, "raw_bytes": [114, 105, 103, 104, 116]}},
      "evidence": ["proto:0:pc:3", "proto:0:k:1"]
    }
  ],
  "evidence": ["proto:0:pc:1", "proto:0:k:0", "proto:0:pc:3", "proto:0:k:1"]
}
```

The union represents reaching definitions across CFG paths, not a path-feasibility or
taint assertion. Structurally equal options are deduplicated with their evidence unioned;
if all reaching definitions are structurally equal, a single merged origin is emitted
rather than a redundant singleton alternative.

## Allowed boundary

- `crates/luad-analysis/src/origins.rs`: add `OriginExpressionKind::Alternatives`,
  join transfer logic in `meet_value`, structural deduplication, evidence unioning,
  loop fixed-point bounds, and canonical option sorting.
- `crates/luad-analysis/src/query.rs`: query support for `alternatives`.
- `crates/luad-cli/src/render/text.rs`: render `alternatives(...)` in human text output.
- `tests/schemas/origins.schema.json` and `tests/schemas/export.schema.json`: regenerated schemas.
- `tests/fixtures/origins.lua`: CFG join fixtures (two literals over `if`, literal vs parameter, equivalent predecessors, loops, overflow, unresolved).
- `crates/luad-oracle/tests/test_argument_origins_lua51.rs`: assertions for JSON, text, deduplication, loops, and negative controls.
- `tests/gates/gate-argument-origins-lua51.json`: updated fixture hash and expected tests.
- `README.md`, `docs/MACHINE-INTERFACE.md`, and this contract: truthful documentation.

## Evidence

Run these focused checks against the candidate:

```console
cargo test -p luad-oracle --test test_argument_origins_lua51 -- --nocapture
bash scripts/gates/gate-argument-origins-lua51.sh
```

- Assert exact JSON, JSONL, text, and export output for alternatives.
- Negative controls: omitted-option, substituted-option, and dropped-evidence mutations in `gate-argument-origins-lua51`.
- Algorithmic review packet: conducted per `docs/DEVELOPMENT-WORKFLOW.md` line 99.
- Run `bash scripts/check.sh` once on a clean candidate.

## Non-goals and stop condition

No convention linking (R-2), caller-unioned substitution (R-3), path-condition solving,
symbolic execution, or decompiler changes. Stop when bounded CFG joins report closed
deterministic alternatives with exact evidence, unresolved or overflowing joins emit
explicit cutoffs, and all named checks pass.
