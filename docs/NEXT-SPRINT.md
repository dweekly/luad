# Sprint contract: finish the firmware walkthrough and subprocess deadline fixes

Lane: steward-owned correction to stages 6–7. Base: `912a839`.
Implementation is performed directly, as requested by the user.

## Outcome and public claim

The public firmware-shaped walkthrough verifies luad's inventory closure, inspection,
facts, profile selection, and refusal behavior. Building and testing luad requires no
external decompiler. External decompilation is an optional manual experiment; metadata
alone does not establish compatibility or correct recovered source.

The subprocess tripwire includes stdin completion in its wall-time monitoring and does
not join unfinished I/O workers after its bounded cleanup grace period.

## Allowed boundary

- `crates/luad-oracle/src/tripwire.rs`: completion, bounded cleanup, and regressions.
- `crates/luad-oracle/tests/test_firmware_walkthrough.rs`: retain luad assertions and
  corruption controls; remove assertions against the simulated decompiler.
- `tests/fixtures/firmware_tree/MANIFEST.json`: align the unsupported-layout exit
  expectation with the public CLI and assert declared outcomes during replay.
- `tests/fixtures/tools/unluac`: remove the header-only simulated decompiler.
- `README.md`, `CONTRIBUTING.md`, `docs/examples/RECIPES.md`, `ROADMAP.md`,
  `CHANGELOG.md`, and this contract: truthful evidence and dependency boundaries.

## Evidence

Run these focused checks against the candidate:

```console
cargo build -p luad-cli --bin luad
CARGO_BIN_EXE_luad="$PWD/target/debug/luad" cargo test -p luad-oracle --test test_firmware_walkthrough
cargo test -p luad-oracle --lib tripwire::tests -- --test-threads=1
CARGO_BIN_EXE_luad="$PWD/target/debug/luad" cargo test -p luad-oracle --test test_hostile_containment -- --test-threads=1
```

- Assert fixture identities, exact export completion, expected facts and profile
  rejection, including tampered input and incomplete-stream negative controls.
- A descendant holding only stdin must produce a wall-time error before its natural
  exit. A deliberately blocked I/O worker must not defeat the cleanup deadline.
- A successful subprocess must preserve its complete output.
- Replay the documented inventory and fact filters; no decompiler is invoked by any
  required test, and no decompiler result is claimed without executing a real tool.
- Run `bash scripts/check.sh` once on a clean candidate; report named gates, official
  compiler versions, and skips. Official compiler evidence requirements are unchanged.

## Non-goals and stop condition

No dialect changes, decompiler integration framework, dependency downloads, target
promotion, release publication, or stage 8 work. Stop after the focused checks and
aggregate check pass with truthful documentation, at a neutral no-work checkpoint.
