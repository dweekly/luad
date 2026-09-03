# Sprint contract: repository bring-up

Lane: infrastructure. This contract authorizes no product, schema, dialect, target, or
capability change.

## Outcome

Someone who has never seen this repository can bring a machine to a working state from
one document, and can verify that state with one command that compares versions rather
than presence.

## Public claim

`docs/BRINGUP.md` covers three machine roles — developer machine, self-hosted GitHub
Actions runner, release builder — and each section ends with one command whose success
is the definition of done. `scripts/bringup.sh --doctor` reports every required tool as
`OK`, `MISSING`, or `WRONG` against the pin that owns it and exits non-zero unless every
row is `OK`; `--install` brings a machine to that state idempotently and without root.
Every tool version has exactly one owning file, and no consumer restates it.

## Scope

Allowed paths:

- `docs/BRINGUP.md`, `docs/NEXT-SPRINT.md`
- `scripts/bringup.sh`, `scripts/pins.env`, `scripts/install_ci_compilers.sh`,
  `scripts/generate_fixtures_manifest.py`
- `crates/luad-oracle/src/lib.rs`, `crates/luad-oracle/src/candidate.rs`,
  `crates/luad-oracle/src/gate_runner.rs`
- `crates/luad-oracle/tests/test_bringup_pins.rs`,
  `crates/luad-oracle/tests/test_compiler_search_pin.rs`, `test_analysis.rs`,
  `test_public_disasm_lua54.rs`, `test_batch_export_bounds.rs`,
  `test_area1_validator_diagnostics.rs`
- `.github/workflows/ci.yml` — the `Test` jobs' step list only
- `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`

## Non-goals

No product behavior, machine contract, schema, diagnostic, dialect, target profile, or
capability status changes. No new gate, evidence layer, or fixture. No test is weakened,
skipped, or deleted. `runs-on` values and matrix definitions in `.github/workflows/ci.yml`
are owned by concurrent work and stay untouched.

## Evidence

1. `bash scripts/bringup.sh --doctor` exits 0 on a machine after
   `bash scripts/bringup.sh --install`, and exits non-zero with a named fix command when
   a pinned tool is absent or at the wrong version.
2. `cargo test -p luad-oracle --test test_bringup_pins --test test_compiler_search_pin`
   — every `find_luac5x` passes over a same-series, different-patch compiler planted at
   the front of the real search order, and the pin file,
   `rust-toolchain.toml`, `Cargo.toml`, `scripts/fuzz_smoke.sh`,
   `scripts/install_ci_compilers.sh`, `.github/workflows/ci.yml`, the `luad-oracle`
   compiler-search constant, and `docs/BRINGUP.md` all name the same versions and
   directories.
3. `CARGO_TARGET_DIR=$(mktemp -d) cargo test -p luad-oracle --test test_analysis --test test_batch_export_bounds --test test_public_disasm_lua54 --test test_area1_validator_diagnostics`
   passes from an empty target directory, building the public CLI on demand rather than
   assuming it is already there.
4. The CI `Test` jobs run `bash scripts/bringup.sh --doctor --scope ci-test` immediately
   after installing the official compilers.
5. `bash scripts/bringup.sh --doctor && bash scripts/check.sh` exits 0. The aggregate
   alone is not enough: it never invokes `cargo-cyclonedx`, the fuzz nightly, or GNU
   `timeout`.

## Stop condition

Stop when the evidence above holds and the documentation index, `CONTRIBUTING.md`, and
`README.md` name `docs/BRINGUP.md` as the only setup path with no duplicated steps.
Product work resumes only after a dedicated planning change replaces this contract with
one unmet outcome selected from `ROADMAP.md`.
