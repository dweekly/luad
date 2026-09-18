# Sprint contract: Export fact-family discovery (R-5)

Lane: product lane. Base: `83a3772`.

## Outcome and public claim

Consumers discover every accepted `export --facts` value at runtime through machine
interfaces, help, and actionable error messages without guessing or source inspection.

- The 9 selectable counted fact families are: `prototype`, `prototype_identity`,
  `instruction`, `constant`, `upvalue`, `xref`, `callee`, `origin`, `call_relation`.
- `diagnostic` is an always-emitted control record (along with `export_start`,
  `file_start`, `file_end`, `export_end`), not a selectable counted family.
- A canonical registry in `luad-core` (`ExportFactFamily`, `EXPORT_FACT_FAMILIES`) is
  the single source of truth for:
  - Argument parsing in `export --facts`.
  - CLI help text for `export --facts`.
  - Invalid fact family error messages, which list the sorted valid set:
    `unknown export fact family '{name}'. Valid families: call_relation, callee, constant, instruction, origin, prototype, prototype_identity, upvalue, xref`.
  - `CapabilityManifest` exposing `export: ExportCapability` (with `command: "export"`,
    `schema: "export"`, `formats: ["jsonl"]`, and `fact_families: [...]`).
  - `luad capabilities` JSON and text output.
  - Public schemas (`capabilities.schema.json`).

## Allowed boundary

- `crates/luad-core/src/export.rs`: canonical `ExportFactFamily` definition,
  `EXPORT_FACT_FAMILIES`, `EXPORT_FACT_FAMILY_NAMES`, `SORTED_FACT_FAMILY_NAMES`,
  and `ExportCapability`.
- `crates/luad-core/src/capabilities.rs`: add `export: ExportCapability` to
  `CapabilityManifest` and `get_canonical_capabilities`.
- `crates/luad-core/src/lib.rs`: export `ExportFactFamily`, `ExportCapability`, and constants.
- `crates/luad-cli/src/args.rs`: update `ExportArgs` docstring/help for `--facts` to list valid families.
- `crates/luad-cli/src/main.rs`: use canonical `ExportFactFamily` from `luad-core` and include
  sorted valid set in invalid family error.
- `crates/luad-cli/src/render/text.rs`: render export capability in `render_capabilities`.
- `tests/schemas/capabilities.schema.json`: regenerated schema with `export`.
- `crates/luad-oracle/tests/test_batch_export.rs`: add tests asserting help text,
  capabilities JSON/text, error messages with sorted valid families, and rejection of
  invented/unknown/duplicate families.
- `tests/gates/gate-batch-export.json`: update expected tests.
- `docs/NEXT-SPRINT.md`, `docs/MACHINE-INTERFACE.md`, `README.md`, `CHANGELOG.md`.

## Evidence

- `cargo test -p luad-oracle --test test_batch_export -- --nocapture`
- `bash scripts/gates/gate-batch-export.sh`
- `bash scripts/check.sh`
- Negative controls:
  - Mutation of advertised fact families (omitting a family or inventing a fake family)
    is rejected by comparator tests.
  - Unknown, empty, and duplicate family selections fail closed with usage error and empty stdout.

## Non-goals and stop condition

No new fact families, decompiler changes, convention linking (R-2), or caller substitution
(R-3). Stop when `export --facts` valid vocabulary is fully discoverable via `--help`,
`capabilities`, error messages, and schemas, and all named gates pass.
