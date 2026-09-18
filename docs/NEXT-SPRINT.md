# Sprint contract: close concrete hostile-input containment gaps

Lane: product lane. Roadmap position: stage 6 under [0.2 execution and dependencies](../ROADMAP.md#02-execution-and-dependencies).

## Public outcome

Close concrete hostile-input containment gaps and establish tripwire qualification:
- Bound regular-file reads while reading with `Read::take`, not solely with a preceding metadata check.
- Bound validator diagnostic accumulation across all dialects (Lua 5.1, 5.2, 5.3, 5.4, 5.5) by `ResourceLimits::max_diagnostics`.
- Replace the Lua 5.1 validator's $O(N^2)$ linear scan deduplication with an $O(N)$ bounded set deduplication preserving insertion order.
- Audit and bound debug-vector allocations (`line_info`, `abs_line_info`, `loc_vars`, `upvalue_names`) using `safe_capacity` checks against remaining input bytes.
- Ensure analysis traversal refuses before any expensive traversal or lifter execution when analysis eligibility fails.
- Subprocess tripwire matrix with frozen budgets:
  - Tiny malformed input (< 10ms, < 20MB)
  - Large instruction count vector (< 50ms, < 20MB, exits 5)
  - Deep prototype nesting recursion (< 50ms, < 20MB, exits 5)
  - Long string length (< 50ms, < 20MB, exits 5)
  - Repeated invalid operands (< 100ms, diagnostics capped at 10,000, < 30MB)
  - Unbounded regular/stream input (capped at 16MB+1, exits 5, < 30MB)
  - Mixed batch containment (bounded memory, framed JSONL completion)
  - Over-budget control proving tripwire monitor catches resource breaches.

## Target boundary

- `crates/luad-cli/src/main.rs` — bounded regular-file streaming read using `BufReader` and `take`.
- `crates/luad-dialect-lua51/src/validator.rs` — $O(N)$ bounded deduplication and diagnostic accumulation cap.
- `crates/luad-dialect-lua52/src/validator.rs` — diagnostic accumulation cap.
- `crates/luad-dialect-lua53/src/validator.rs` — diagnostic accumulation cap.
- `crates/luad-dialect-lua54/src/validator.rs` — diagnostic accumulation cap.
- `crates/luad-dialect-lua55/src/validator.rs` — diagnostic accumulation cap.
- `crates/luad-oracle/tests/test_hostile_containment.rs` — dedicated hostile input tripwire test suite.
- `docs/NEXT-SPRINT.md` — active sprint contract.

## Proof

- Dedicated hostile-input containment and tripwire test suite passes:
  - `cargo test -p luad-oracle --test test_hostile_containment`
- Regression test suites pass:
  - `cargo test -p luad-oracle --test test_failure_provenance`
  - `cargo test -p luad-oracle --test test_cli_e2e`
  - `cargo test -p luad-oracle --test test_batch_export`
  - `cargo test -p luad-oracle --test test_cli_broken_pipe`
  - `cargo test -p luad-oracle --test test_analysis_eligibility`
  - `cargo test -p luad-oracle --test test_layout_truth_matrix`
- Zero warnings on workspace formatting and clippy:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`

## Non-goals

No general benchmark service or profiling server, no all-version corpus generator, no unbounded fuzz campaigns.

## Stop condition

Stop when regular-file reads are bounded while streaming, Lua 5.1 validator uses bounded $O(N)$ deduplication, all validators cap diagnostic accumulation, the hostile tripwire matrix passes with verified budgets and over-budget negative controls, and all regression suites pass cleanly.
