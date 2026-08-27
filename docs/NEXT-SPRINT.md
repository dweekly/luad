# Sprint contract: freeze the version-1 release boundary

Lane: planning and release policy. Roadmap position: Milestone 0.

## Outcome

A Lua user, package consumer, or downstream tool author can read the maintained public
documentation and find one unambiguous future version-1 support, compatibility, and
distribution promise. This batch freezes that promise in documentation without
promoting a target or changing product behavior.

## Public claim

The documentation will name exactly these independent future 1.0 targets:

1. Lua 5.1.5 profile `lua5.1-lnum32` with
   `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4`;
2. stock Lua 5.1.5 profile `lua5.1` with
   `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0`; and
3. stock Lua 5.4.9 profile `lua5.4`, format 0, with 4-byte instructions, 8-byte
   `lua_Integer`, 8-byte `lua_Number`, and the pinned official compiler's standard
   little-endian representation.

The package platforms are exactly Linux x86-64 and macOS arm64. Complete JSON
documents remain schema major 1; capabilities and streaming JSONL remain schema major
2. Exit codes 0 through 6 retain the meanings already documented in
`docs/MACHINE-INTERFACE.md`.

Existing symbolic-callee, value-origin, call-relation, and related derived-analysis
work remains implemented experimental evidence. It is preserved in product research
but is not a stable 1.0 compatibility promise unless a later Milestone 2 contract
qualifies an exact public surface. The current supported target set remains empty.

The workspace remains dual `MIT OR Apache-2.0`. The release owner is the repository
owner, `dweekly`. Durable accepted qualification, customer-transfer, and final-release
artifacts belong in the `dweekly/luad` GitHub release for the candidate or final version;
ordinary expiring Actions artifacts and local temporary directories are not durable
release evidence.

## Scope

No production or ordinary-test path may change. The implementation batch may change
only:

- `README.md`;
- `PRD.md`;
- `ROADMAP.md`;
- `SECURITY.md`;
- `CHANGELOG.md`;
- `docs/MACHINE-INTERFACE.md`;
- `docs/RELEASING.md`; and
- this file, which returns to the neutral no-work checkpoint at acceptance.

The README documentation-index entries for every changed document must remain accurate
and fresh.

## Evidence

Before editing, the acceptance boundary is:

1. Cross-document review finds no maintained statement that expands the exact target,
   layout, package-platform, schema-major, exit-code, license, owner, retention, or
   derived-analysis promise above.
2. `cargo test -p luad-oracle --test test_cli_e2e
   test_capabilities_readme_status_consistency -- --exact` proves README status remains
   tied to the live experimental capability manifest.
3. `cargo test -p luad-oracle --test test_cli_e2e test_cli_schema_export -- --exact`
   proves the documented schema-major exports exist.
4. `cargo test -p luad-oracle --test test_cli_e2e test_cli_exit_codes_contract --
   --exact` proves the documented process exit meanings at the public CLI.
5. `cargo test -p luad-oracle --test test_machine_interface
   test_live_capabilities_json_and_schema_validation -- --exact` proves capabilities
   remain schema-valid at major 2 with no support promotion.
6. The documentation-index/link audit and `git diff --check` pass, followed by one
   aggregate `bash scripts/check.sh` run from the clean candidate.

No new oracle, gate, fixture, manifest, schema, or self-declared evidence file is
authorized. The existing tests prove the live implementation facts; documentation
review proves that the future promise does not exceed them.

## Non-goals

- No product, schema, CLI, test, gate, workflow, packaging, or capability-status change.
- No release candidate, target promotion, package build, signing key, or publication.
- No Milestone 1 packaging implementation or Milestone 2 command/fact qualification.
- No new dialect, layout, platform, installer, package manager, decompiler, persistent
  state, or policy-bearing security analysis.
- No claim that existing Lua 5.4.8 evidence promotes Lua 5.4.9.

## Stop condition

Stop with one reviewable documentation candidate in which every maintained document
states or defers to the same future version-1 boundary, every current capability remains
experimental, this file has returned to the neutral checkpoint, and no path outside the
scope list changed. Do not begin packaging or public-surface implementation in this
batch.
