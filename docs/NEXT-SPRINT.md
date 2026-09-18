# Sprint contract: ship one reproducible firmware investigation walkthrough

Lane: product lane. Roadmap position: stage 7 under [0.2 execution and dependencies](../ROADMAP.md#02-execution-and-dependencies).

## Public outcome

Deliver one reproducible firmware investigation walkthrough based on public, redistributable inputs:
- Standalone fixture tree `tests/fixtures/firmware_tree/` with full provenance in `MANIFEST.json`:
  - OpenWrt LNUM32 precompiled bytecode named `.lua` (`dispatcher.lua`)
  - Stock Lua 5.1 precompiled bytecode (`system_service.luac`, decompiler handoff target)
  - Plain text Lua source (`network_setup.lua`)
  - Malformed/truncated input (`corrupted_module.luac`)
  - Unsupported layout (`mips_be_legacy.luac`, Big-Endian Lua 5.1)
- Automated end-to-end replay test `crates/luad-oracle/tests/test_firmware_walkthrough.rs`:
  - Phase 1: Inventory and triage via `luad export` with exact closure assertions.
  - Phase 2: Inspection and dialect layout detection/rejection with truthful exit codes (0, 1, 4).
  - Phase 3: Targeted fact extraction (`constants`, `query`, `disasm`, `callees`, `origins`).
  - Phase 4: Pinned decompiler handoff cross-check and honest boundary reporting.
  - Negative controls: Tampered fixture hash or truncated stream fails closed.
- Concise walkthrough section in `README.md` and detailed recipe in `docs/examples/RECIPES.md`.

## Target boundary

- `tests/fixtures/firmware_tree/MANIFEST.json` — fixture provenance and outcome specification.
- `tests/fixtures/firmware_tree/*` — public redistributable fixture tree.
- `crates/luad-oracle/tests/test_firmware_walkthrough.rs` — automated walkthrough replay test.
- `docs/examples/RECIPES.md` — detailed firmware investigation recipe.
- `README.md` — concise reproducible walkthrough.
- `docs/NEXT-SPRINT.md` — active sprint contract.

## Proof

- Dedicated walkthrough test passes:
  - `cargo test -p luad-oracle --test test_firmware_walkthrough`
- Regression test suites pass:
  - `cargo test -p luad-oracle --test test_hostile_containment`
  - `cargo test -p luad-oracle --test test_failure_provenance`
  - `cargo test -p luad-oracle --test test_batch_export`
  - `cargo test -p luad-oracle --test test_cli_e2e`
  - `cargo test -p luad-oracle --test test_cli_broken_pipe`
  - `cargo test -p luad-oracle --test test_analysis_eligibility`
  - `cargo test -p luad-oracle --test test_layout_truth_matrix`
- Zero warnings on workspace formatting and clippy:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`

## Non-goals

No private customer samples, no whole-firmware extraction engine, no database product, no external adapter framework.

## Stop condition

Stop when the public fixture tree is created with complete provenance, the automated walkthrough test passes with negative controls, README and RECIPES documentation are updated, and all regression suites pass cleanly.
