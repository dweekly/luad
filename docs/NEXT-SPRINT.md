# Active sprint: public diagnostic catalog

Lane: machine contract. Target: one frozen acceptance commit, one implementation
commit, and one canonical gate.

## Claim and researcher value

Every diagnostic code that `luad` can emit from production code is discoverable
without supplying a bytecode artifact. Human researchers and external agents can
deterministically retrieve the code's severity, category, semantics, and suggested
next action through a self-documenting CLI and a versioned JSON Schema.

The catalog is descriptive product metadata. It does not classify vulnerabilities,
interpret a research target, retain project state, or make diagnostic emission depend
on a network service or session.

## Public command and schema

Add this public command:

```console
luad diagnostics [CODE] --format text|json
```

With no `CODE`, the command emits the complete catalog in ascending bytewise code
order. With an exact `CODE`, it emits the same response shape containing exactly one
descriptor. An unknown, partial, or case-folded code is a usage error with nonzero
exit status and must never return a successful empty result.

JSON uses a top-level `DiagnosticCatalogResponse` containing:

- `schema_version`, fixed to major `1`;
- `tool_version`;
- `diagnostic_count`, equal to the array length;
- `diagnostics`, an ordered array of `DiagnosticDescriptor` records.

Each descriptor contains exactly these required facts:

- `code`;
- `severity`;
- `category`;
- `semantics`, explaining what condition the code reports;
- `suggested_action`, giving a concrete next step to the caller.

The response has no artificial input identity or dialect interpretation because the
catalog does not analyze an input artifact. `luad schema diagnostics` publishes its
JSON Schema. `luad schema diagnostic` continues to describe an emitted diagnostic
instance.

Text output is deterministic and bounded. Every row begins with the exact code,
severity, and category, followed by its semantics and suggested action. Exact lookup
uses the same renderer as list output.

## Catalog authority and completeness

`luad-core` owns the descriptor type, the canonical catalog, exact lookup, sorting,
and uniqueness validation. The CLI only selects and renders catalog records.

The frozen source inventory contains 108 production-emittable codes, including the
three Lua 5.4 disassembly codes without numeric suffixes. Acceptance independently
walks production Rust sources under `crates/`, excluding test paths and the catalog
module at `crates/luad-core/src/diagnostic_catalog.rs`, and extracts
diagnostic-emission literals. It proves exact set
equality with the public live catalog.

Production calls to `Diagnostic::error` and `Diagnostic::warning`, plus direct
`Diagnostic` records, must use a string literal at the emission site. A bound,
computed, or concatenated emission code
is rejected by acceptance because it cannot be proven catalog-complete. Adding,
removing, or renaming a production emission therefore requires the catalog and its
public evidence to change together.

Every descriptor must have a unique nonempty code, a nonempty specific semantics
sentence, and a nonempty actionable next step. The catalog contains no aliases,
wildcards, family-only placeholders, or entries that production cannot emit.

## Independent acceptance

The frozen acceptance module is
`crates/luad-oracle/tests/test_diagnostic_catalog.rs`. It contains exactly these
non-skipping tests:

- `test_catalog_code_set_matches_independent_production_inventory`;
- `test_production_emitters_use_literal_diagnostic_codes`;
- `test_catalog_descriptors_are_unique_sorted_complete_and_actionable`;
- `test_public_json_list_and_lookup_are_schema_valid_deterministic`;
- `test_public_text_list_and_lookup_golden`;
- `test_unknown_code_fails_closed`;
- `test_catalog_comparator_rejects_killer_mutations`;
- `test_existing_diagnostic_instance_schema_remains_compatible`.

The comparator must reject at least these mutations: omitted production code, extra
catalog-only code, duplicate code, reordered records, wrong severity, wrong category,
blank semantics, blank suggested action, successful empty unknown lookup, nonliteral
emitter code, and a schema that omits a required descriptor field.

Representative exact metadata is pinned for core truncation, Lua 5.1 register spans,
Lua 5.4 invalid opcodes, and unsupported plain Lua source. The complete code set is
pinned independently of production discovery so deleting an emitter and its catalog
entry together cannot silently shrink the contract.

The canonical gate is `gate-diagnostic-catalog`, comprising:

- `tests/gates/gate-diagnostic-catalog.json`;
- `scripts/gates/gate-diagnostic-catalog.sh`;
- the exact eight tests above;
- `gate-proof-harness`, `gate-machine-contract`,
  `gate-validation-null-hypothesis`, and
  `gate-validator-count-spans-lua51` as prerequisites.

A missing test, code, descriptor field, schema check, mutation rejection, or public CLI
probe is a hard failure. The gate executes without network access, skipped tests, or
private corpora.

## Allowed scope

Acceptance author:

- `crates/luad-oracle/tests/test_diagnostic_catalog.rs`.

Steward-owned paths:

- `tests/gates/gate-diagnostic-catalog.json`;
- `scripts/gates/gate-diagnostic-catalog.sh`;
- `docs/NEXT-SPRINT.md`;
- the documentation index freshness entry.

Implementation agent:

- a new catalog module in `crates/luad-core/src/`;
- `crates/luad-core/src/lib.rs` and `crates/luad-core/src/diagnostic.rs` when needed
  for public catalog types;
- `crates/luad-cli/src/args.rs`;
- `crates/luad-cli/src/main.rs`;
- CLI render modules used by the new command;
- `docs/MACHINE-INTERFACE.md`, `README.md`, and `CHANGELOG.md` for the public command
  contract and user-visible change.

The implementation may use a static descriptor table and a small lookup function. It
may not alter when diagnostics are emitted, change existing diagnostic instance
schemas, rewrite dialect parsers or validators, add persistent state, or add runtime
catalog loading.

## Verification and stop condition

Freeze acceptance only after the inventory, comparator, and CLI probes are live and
the focused module fails solely because the public catalog and literal-emitter
normalization are absent. The steward then
runs:

```console
cargo build -p luad-cli --bin luad
cargo test -p luad-oracle --test test_diagnostic_catalog
bash scripts/gates/gate-diagnostic-catalog.sh /tmp/luad-gate-diagnostic-catalog
bash scripts/check.sh
```

Acceptance requires a clean candidate revision, zero skipped or ignored tests, a
tamper-evident gate artifact, unchanged frozen acceptance and gate files during
implementation, exact public/source code-set equality, and successful schema
validation. After merge and remote verification, replace this document with the Area
1 closure sprint and remove the temporary branches and worktrees.
