# Active product batch: executed hostile-input safety baseline

Lane: product. Roadmap position: cross-cutting robustness and release evidence.

## Public claim

The repository will enforce its memory-safety boundary and execute, rather than merely
compile, a bounded hostile-input fuzz smoke suite in Linux CI. Every maintained stock-Lua
detection and parser target will run, and successfully parsed Lua 5.1 and Lua 5.4 inputs
will continue through the deterministic disassembly and analysis surfaces used by the
public tool.

No production crate may compile `unsafe` code. A missing fuzz toolchain, target, seed
corpus, or successful target execution is a hard CI failure rather than a skip.

## Acceptance matrix

### Safety enforcement

- Apply a workspace-owned `unsafe_code = "forbid"` policy to `luad-core`, every dialect,
  `luad-analysis`, and `luad-cli` without local opt-outs.
- Keep the fuzz and oracle crates under the same policy unless a documented external
  harness boundary makes an exception unavoidable; any exception remains outside
  production crates and names the exact dependency boundary.
- Add a negative control proving that a temporary `unsafe` block is rejected by the
  repository's ordinary lint command.

### Executed fuzz surfaces

- Run the existing detection target and all five stock-Lua parser targets with their
  maintained seed corpora.
- Add one Lua 5.1 and one Lua 5.4 post-parse target. On successful decode, each target
  traverses every prototype, constructs public disassembly facts, exercises validation
  and the applicable CFG/xref analysis, and serializes the resulting fact records to
  JSON. Invalid inputs remain ordinary rejected data.
- Seed the post-parse targets from the maintained exact-target fixtures so a smoke run
  cannot spend its entire budget outside successful parse paths.
- Keep each target deterministic and independently runnable through one documented
  script. The script owns a fixed run-count and maximum-input-size budget plus an outer
  timeout, reports per-target executions, and fails unless all eight targets complete.

### CI and evidence

- Add one Linux fuzz-smoke job using an explicitly pinned Rust and `cargo-fuzz`
  toolchain. The job invokes the same repository script contributors use locally.
- Preserve the complete target list, tool versions, run budgets, exit statuses, and
  corpus identities in the CI log or uploaded compact artifact.
- Add an ordinary contract test that rejects target-list omission, zero executions,
  success inferred from missing output, and an unpinned toolchain.
- Run the smoke command once from a clean candidate and retain its compact evidence.
  Run the aggregate repository check separately.

## Scope

Production changes are limited to crate-level safety policy and the minimum reusable
analysis entry points needed by the two post-parse fuzz drivers. Fuzz targets, corpus
wiring, one runner script, CI configuration, focused contract tests, contributor and
security documentation, and the aggregate check are in scope.

New bytecode semantics, parser recovery behavior, public commands or schemas, support
promotion, broad benchmark infrastructure, sanitizer matrices, coverage percentages,
continuous long-running campaigns, and release publication are non-goals.

## Stop condition

Stop after one reviewable batch makes all eight targets execute under the pinned bounded
smoke command and proves the unsafe-code policy. Do not split parser targets into
separate sprints, and do not turn the smoke baseline into a general fuzzing platform.
