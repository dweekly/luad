# Sprint contract: Convention-gated cross-chunk linking (R-2)

Lane: product lane. Base: `9a9027a`.

## Outcome and public claim

A corpus consumer connects a proved LuCI module label to its defining artifact and prototype when a named convention applies.

- Default analysis and batch export remain strictly bytecode-local without synthetic reaches.
- The explicit opt-in flag `--link-convention luci-module-setglobal` enables corpus indexing for the literal `module("...")` plus literal exported `CLOSURE`/`SETGLOBAL` shape in Lua 5.1 chunks.
- Connects a symbolic call-site to its target prototype only when there is a unique matching definition in the corpus (`status: "resolved"`).
- Non-unique or unresolvable call-sites retain explicit auditable statuses:
  - `absent`: no matching module export found in the provided corpus.
  - `duplicate`: multiple conflicting definitions found in the corpus for the same export label.
  - `dynamic`: dynamic or non-literal module declaration or call target.
  - `unsupported`: non-Lua-5.1 chunk or invalid bytecode where convention analysis cannot apply.
- Cross-chunk link records carry:
  - `call_id`: `StableId` of the call instruction.
  - `caller_path`: file path of the calling artifact.
  - `caller_proto`: `ProtoPath` of the calling prototype.
  - `call_pc`: physical PC of the call instruction.
  - `label_segments`: symbolic path segments (e.g. `["luci", "sys", "exec"]`).
  - `status`: `resolved`, `absent`, `duplicate`, `dynamic`, or `unsupported`.
  - `target_artifact`: optional `InputIdentity` (sha256, path) of defining artifact when resolved.
  - `target_proto`: optional `ProtoPath` of defining prototype when resolved.
  - `evidence`: deterministic list of defining and calling `StableId`s.
- Deterministic output ordered by caller path, caller proto path, and call PC.
- Bounded indexing: hard limits on total indexed modules (10,000) and link facts.

## Allowed boundary

- `crates/luad-analysis/src/linking.rs`: `LinkConvention`, `CrossChunkLinkFact`, `LinkStatus`, module indexing and linking engine.
- `crates/luad-analysis/src/lib.rs`: re-export linking module and public types.
- `crates/luad-cli/src/args.rs`: add `--link-convention` argument to `ExportArgs`.
- `crates/luad-cli/src/main.rs`: wire `--link-convention` into batch export and schema output.
- `tests/schemas/link.schema.json`: schema for cross-chunk link records.
- `tests/fixtures/cross_chunk/`: mini-corpus of compiled Lua 5.1 bytecode fixtures covering:
  - `mod_sys.luac`: defines `module("luci.sys")` exporting `exec`.
  - `caller_sys.luac`: calls `luci.sys.exec()`.
  - `mod_sys_dup.luac`: conflicting duplicate definition of `luci.sys.exec`.
  - `caller_missing.luac`: calls `luci.missing.func()`.
  - `mod_dynamic.luac`: dynamic non-literal module declaration.
- `crates/luad-oracle/tests/test_cross_chunk_linking.rs`: test suite covering success, duplicate conflict, absent definition, dynamic declaration, order invariance, and negative mutation controls.
- `tests/gates/gate-cross-chunk-link.json` & `scripts/gates/gate-cross-chunk-link.sh`: dedicated gate.
- `docs/NEXT-SPRINT.md`, `docs/MACHINE-INTERFACE.md`, `README.md`, `CHANGELOG.md`.

## Evidence

- `cargo test -p luad-oracle --test test_cross_chunk_linking -- --nocapture`
- `bash scripts/gates/gate-cross-chunk-link.sh`
- `bash scripts/check.sh`
- Negative controls:
  - Mutation of target path or target prototype in comparator is rejected.
  - Duplicate module definitions must never resolve to either candidate; status must be `duplicate`.
  - Unknown link convention name fails closed with usage error and lists valid conventions.
  - Reversed input file order produces identical sorted link records.

## Non-goals and stop condition

No caller parameter substitution (R-3), runtime reachability speculation, or whole-program decompilation.
Stop when `--link-convention luci-module-setglobal` indexes the corpus, emits verifiable link facts with correct statuses, and all tests and the named gate pass.
