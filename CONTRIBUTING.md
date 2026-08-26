# Contributing to `luad`

Thank you for helping make Lua bytecode analysis more trustworthy. Correctness and evidence take priority over feature count.

## Start here

Before changing parser, decoder, validator, analysis, evidence, or capability code, read:

1. [The customer-outcome development workflow](docs/DEVELOPMENT-WORKFLOW.md)
2. [The product roadmap](ROADMAP.md)
3. [The active sprint](docs/NEXT-SPRINT.md)
4. [The embedded-firmware requirements](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md)
5. [Architecture and invariants](ARCHITECTURE.md)
6. [The machine interface](docs/MACHINE-INTERFACE.md)

Do not work outside the single active `docs/NEXT-SPRINT.md`. Product-lane agents write
the bounded implementation and ordinary tests together. Qualification acceptance,
fixture provenance, release evidence, and shared gate definitions remain frozen unless
the steward explicitly authorizes an amendment.

## Development setup

The contributor toolchain is pinned in `rust-toolchain.toml`.

```console
cargo build --workspace
bash scripts/check.sh
```

`scripts/check.sh` runs the aggregate repository checks. It is necessary before handoff, but it is not proof that oracle-backed claims are correct; each work package must also pass its canonical gate.

### Official Lua compilers

Parser fixtures can run from bundled bytecode, but differential proof requires exact official compilers:

```console
bash scripts/install_ci_compilers.sh
```

The compilers are installed beneath `/tmp/lua-tools/bin`. Canonical gates must verify the exact compiler version and binary/archive hashes they claim. A required compiler missing from CI must fail the gate; it must never cause a silent skip.

## Repository map

| Path | Responsibility |
|---|---|
| `crates/luad-core` | Shared models, stable IDs, provenance, diagnostics, limits, safe reader |
| `crates/luad-dialect-lua5*` | Version-specific detection, parsing, opcodes, lifting, validation |
| `crates/luad-analysis` | CFGs, dominators, xrefs, queries, diffs, symbolic callees, argument origins, call relations |
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

The accepted Lua 5.4.8 raw-fact oracle compares the exact official `luac -l -l` listing with an independent reference decoder. Any extended or new comparator must verify, at minimum:

- prototype structure and metadata;
- opcode identity at every PC;
- encoded and interpreted operands;
- typed constant values;
- line information, locals, and upvalues.

Each comparator needs negative controls proving that a one-field corruption is detected. An oracle with no failing control is not a proof gate.

Public behavior needs an additional boundary test. For disassembly, compare the typed public JSON record with both independent fact paths and maintain normalized text goldens. An internal decoder or lifter test cannot establish a CLI or schema claim.

### Semantic-effect gates

Register reads/writes, ranges, multireturn, metamethod fallbacks, and analyzer preconditions are not fully covered by `luac -l -l`. Do not describe them as verified until a suitable independent oracle—preferably an instrumented Lua VM—or equivalent executable evidence exists.

## Making a dialect change

Follow the entire chain:

```text
official source/layout
  → header-derived ChunkLayout and explicit profile
  → opcode definition, physical-word role, and mode
  → raw field decoder
  → interpreted operands
  → semantic lifter
  → capture and other cross-prototype relations
  → validator
  → provenance citation
  → golden word tests
  → encode/decode property
  → differential fixture
  → negative oracle control
  → capability evidence
```

Requirements:

- Never assume the build host's pointer width, integer width, byte order, or number representation. Validate the artifact header and drive every layout-dependent read from it.
- Treat vendor formats such as Lua 5.1 LNUM as explicit profiles with their own positive and negative fixtures; do not broaden the stock profile silently.
- Preserve raw encoded values separately from interpreted signed values.
- Preserve non-executable physical words and classify their role. In Lua 5.1, `CLOSURE` binding descriptors are not standalone `MOVE` or `GETUPVAL` effects.
- Use explicit or generated opcode matches; do not use `unsafe transmute`.
- Include a golden test whose expected word and operands come from an official source or independently compiled fixture.
- Do not copy a decoder into its encoder and call the result independent.
- Update capability status only after the dialect's named CI gate passes.

## Fixtures and provenance

Bundled `.luac` files are evidence artifacts, not ordinary test data. Do not regenerate them casually.

The stock cross-version corpus is recorded in
`tests/fixtures/precompiled/MANIFEST.json`. Public firmware-shaped qualification
cases use `tests/fixtures/embedded/MANIFEST.json`; each entry names its redistribution
license and pins the source, binary, compiler, layout, and expected stress properties.

Any regenerated fixture set must record:

- exact Lua release;
- dialect/vendor profile, including how it was detected or selected;
- upstream archive URL and SHA-256;
- platform, architecture, endianness, integer and number sizes;
- declared `sizeof(int)`, `sizeof(size_t)`, instruction width, Lua-number width, and number-integrality flag;
- source fixture SHA-256;
- compiler arguments, including stripping;
- output SHA-256;
- generation command or script revision.

Historical fixtures whose generator details are unknown must say so explicitly. Never infer provenance from a bytecode version byte alone.

The Lua 5.1 fixture matrix must include both 32-bit and 64-bit `size_t`, supported byte orders and number layouts, stripped and debug-bearing chunks, and stock-versus-LNUM negative controls. Closure fixtures must cover register captures, parent-upvalue captures, zero and multiple upvalues, nested closures, and malformed descriptor sequences.

Private firmware corpora can provide valuable field evidence, but they cannot be the only regression input. Record artifact counts and aggregate hashes where disclosure permits, and contribute a minimized, redistributable reproducer for each distinct defect.

## Machine-contract changes

When changing JSON, JSONL, IDs, diagnostics, exit codes, or capabilities:

- update or version the corresponding schema;
- add deterministic-output tests;
- keep machine stdout free of commentary and color codes;
- send human diagnostics to stderr;
- preserve the deepest known byte offset as the primary diagnostic location and keep structural context separate;
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

## Documentation lifecycle

The [README documentation index](README.md#documentation-index) owns discovery and
freshness for every maintained Markdown document. Any documentation change must keep
its summary, last-fresh date, and stale trigger accurate. A new unindexed document is
incomplete work.

Plans and roadmaps are replaceable statements of future work. They contain no completed
checklists, implementation retrospectives, or comparisons with superseded behavior.
Move user-visible implementation history to `CHANGELOG.md`; use release notes, pull
requests, and commits for additional historical detail.

Apply the same rule to source comments: explain the invariant or reason that is true
for the present code. Version history and migration narratives do not belong in code
comments.
