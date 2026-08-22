# Contributing to `luad`

Thank you for helping make Lua bytecode analysis more trustworthy. Correctness and evidence take priority over feature count.

## Start here

Before changing parser, decoder, validator, analysis, evidence, or capability code, read:

1. [The current correctness review](docs/REVIEW-2026-08-22.md)
2. [Architecture and invariants](ARCHITECTURE.md)
3. [Remediation roadmap](ROADMAP.md)
4. [The coding plan](docs/CODING-AGENT-PLAN.md)

The repository is under a correctness stop line. Do not add new dialects or composability features until the fact-layer gates in the coding plan pass.

## Development setup

The contributor toolchain is pinned in `rust-toolchain.toml`.

```console
cargo build --workspace
bash scripts/check.sh
```

`scripts/check.sh` is intended to run formatting, strict Clippy, workspace tests, rustdoc, and fuzz-target compilation. The coding plan includes making it executable and splitting correctness proof into named CI gates; the script alone is not proof that oracle-backed claims are correct.

### Official Lua compilers

Parser fixtures can run from bundled bytecode, but differential proof requires exact official compilers:

```console
bash scripts/install_ci_compilers.sh
```

The compilers are installed beneath `/tmp/lua-tools/bin`. Do not treat this installer as supply-chain hardened until pinned archive checksums have been added and verified. A required oracle compiler missing from CI must fail the gate; it must never cause a silent skip.

## Repository map

| Path | Responsibility |
|---|---|
| `crates/luad-core` | Shared models, stable IDs, provenance, diagnostics, limits, safe reader |
| `crates/luad-dialect-lua5*` | Version-specific detection, parsing, opcodes, lifting, validation |
| `crates/luad-analysis` | CFGs, dominators, xrefs, queries, diffs |
| `crates/luad-cli` | CLI contracts, input handling, exit behavior, rendering, schemas |
| `crates/luad-oracle` | Official-compiler harness, listing parser, differential assertions |
| `tests/fixtures` | Source corpus and bundled compiled chunks |
| `fuzz` | Coverage-guided parser and detector targets |

See [ARCHITECTURE.md](ARCHITECTURE.md) for data flow and invariants.

## Test taxonomy

Not all green tests prove the same thing.

### Static and build checks

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
- `cargo check --manifest-path fuzz/Cargo.toml`

### Structural and hostile-input tests

- parser fixtures for debug and stripped chunks;
- every-byte truncation tests;
- resource-limit and adversarial-count tests;
- property tests over arbitrary bytes;
- persistent coverage-guided fuzzing.

These establish safety properties, not semantic correctness.

### Differential gates

The official `luac -l -l` comparator must verify, at minimum:

- prototype structure and metadata;
- opcode identity at every PC;
- encoded and interpreted operands;
- typed constant values;
- line information, locals, and upvalues.

Each comparator needs negative controls proving that a one-field corruption is detected. An oracle with no failing control is not a proof gate.

### Semantic-effect gates

Register reads/writes, ranges, multireturn, metamethod fallbacks, and analyzer preconditions are not fully covered by `luac -l -l`. Do not describe them as verified until a suitable independent oracle—preferably an instrumented Lua VM—or equivalent executable evidence exists.

## Making a dialect change

Follow the entire chain:

```text
official source/layout
  → opcode definition and mode
  → raw field decoder
  → interpreted operands
  → semantic lifter
  → validator
  → provenance citation
  → golden word tests
  → encode/decode property
  → differential fixture
  → negative oracle control
  → capability evidence
```

Requirements:

- Preserve raw encoded values separately from interpreted signed values.
- Use explicit or generated opcode matches; do not use `unsafe transmute`.
- Include a golden test whose expected word and operands come from an official source or independently compiled fixture.
- Do not copy a decoder into its encoder and call the result independent.
- Update capability status only after the dialect's named CI gate passes.

## Fixtures and provenance

Bundled `.luac` files are evidence artifacts, not ordinary test data. Do not regenerate them casually.

Any regenerated fixture set must record:

- exact Lua release;
- upstream archive URL and SHA-256;
- platform, architecture, endianness, integer and number sizes;
- source fixture SHA-256;
- compiler arguments, including stripping;
- output SHA-256;
- generation command or script revision.

Historical fixtures whose generator details are unknown must say so explicitly. Never infer provenance from a bytecode version byte alone.

## Machine-contract changes

When changing JSON, JSONL, IDs, diagnostics, exit codes, or capabilities:

- update or version the corresponding schema;
- add deterministic-output tests;
- keep machine stdout free of commentary and color codes;
- send human diagnostics to stderr;
- fail closed on invalid selectors and unsupported values;
- update [docs/MACHINE-INTERFACE.md](docs/MACHINE-INTERFACE.md);
- do not make capability claims stronger than their evidence.

## Definition of done

A change is complete only when:

- the relevant named proof gate passes;
- an appropriate negative control fails before the fix and passes after it;
- malformed input remains bounded and panic-free;
- documentation describes the actual behavior;
- capability/evidence status is updated from verified results;
- no required oracle silently skips;
- unrelated user changes are preserved.

Commit messages and phase labels do not establish completion; executable gates do.
