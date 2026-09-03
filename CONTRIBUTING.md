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

Install the toolchains, tools, and official compilers once, following
[docs/BRINGUP.md](docs/BRINGUP.md). It is the single setup document and names the file
that owns every pinned version; do not install these by hand from memory.

```console
bash scripts/bringup.sh --install
cargo build --workspace
bash scripts/check.sh
```

The stable workspace MSRV is Rust 1.85. The contributor and release-builder toolchain is
separately pinned in `rust-toolchain.toml`; the fuzz workspace uses its own pinned
nightly and does not declare a stable `rust-version`. Changes that raise the MSRV must
update package metadata, CI evidence, release documentation, and the changelog together.

`scripts/check.sh` runs the aggregate repository checks. It is necessary before handoff, but it is not proof that oracle-backed claims are correct; each work package must also pass its canonical gate.

Dependency changes must also pass the pinned `cargo-deny` policy:

```console
cargo deny --locked check advisories licenses
```

Do not add an advisory ignore, license exception, clarification, or graph exclusion as
a routine way to restore CI. A rejected dependency requires its own bounded disposition.

Release dependency inventories use the exact pinned `cargo-cyclonedx` generator:

```console
CARGO_CYCLONEDX="$(command -v cargo-cyclonedx)" \
  scripts/generate-release-sbom.sh /tmp/luad-sbom
cargo test -p luad-oracle --test test_release_sbom
```

The command requires a clean revision and a new or empty output directory. It emits one
canonical CycloneDX 1.5 source inventory and independently compares it with locked Cargo
metadata. Do not describe it as proof of either platform binary's linked contents or as
a replacement for the dependency audit.

Release archive changes must preserve the accepted host-native packaging boundary:

```console
./scripts/package-release.sh /tmp/luad-release
cargo test -p luad-oracle --test test_release_package
```

The required `Release Archives` check repeats that command in two independent Rust
1.97.1 jobs for each of `linux-x86_64` and `macos-aarch64`, then requires exact archive
and sidecar bytes plus verified combined checksums. Its seven-day upload is diagnostic
transport, not publication or durable evidence. Do not suppress a replica mismatch or
describe equality within those runner classes as reproducibility across arbitrary
hosts, toolchains, or targets.

Release-bundle composition uses the accepted archive and SBOM outputs without copying
their internal semantic gates:

```console
scripts/assemble-release-bundle.sh \
  /tmp/release-archives \
  /tmp/release-sbom/luad-<version>.cdx.json \
  /tmp/release-prerequisites.json \
  /tmp/release-bundle
cargo test -p luad-oracle --test test_release_bundle
```

The `Release Bundle` check creates the prerequisite document from actual same-revision
job results, assembles twice, compares and verifies the exact five-file output, and runs
a corruption probe. Local prerequisite JSON is composition input, not evidence that a
hosted check passed. The seven-day result remains diagnostic and non-promoting.

Release publication mechanics have an offline regression and a manually dispatched
hosted rehearsal:

```console
cargo test -p luad-oracle --test test_release_publication
gh workflow run release-publication.yml --ref main \
  -f revision=<full-main-revision> \
  -f ci_run_id=<successful-main-ci-run-id>
```

The hosted command is maintainer-only and runs after the named `main` CI result is
accepted. It retains one clearly labeled non-production prerelease, verifies fresh
downloads and GitHub source archives, and deletes its corruption and withdrawal probes.
It must not create or change a `v*` tag, latest-release pointer, target manifest,
capability status, or signing claim.

The bounded hostile-input campaign uses an independently pinned nightly and
`cargo-fuzz` release, both installed by bring-up:

```console
scripts/fuzz_smoke.sh artifacts/fuzz-smoke
```

The runner requires GNU `timeout` (`coreutils` on macOS), executes every canonical
target with fixed deterministic budgets under a pinned detection envelope (`address`
sanitizer, 512 MB RSS, 128 MB allocation), and writes its evidence beneath the selected
persistent output directory. The budgets, envelope, and toolchain pins live in the
runner alone; CI invokes the same script rather than restating its flags.

### Official Lua compilers

Parser fixtures can run from bundled bytecode, but differential proof requires the exact
official compilers that [docs/BRINGUP.md](docs/BRINGUP.md) installs beneath
`$HOME/.cache/luad/lua-tools/bin`. Canonical gates must verify the exact compiler version and binary/archive hashes they claim. A required compiler missing from CI must fail the gate; it must never cause a silent skip.

## Repository map

| Path | Responsibility |
|---|---|
| `crates/luad-core` | Shared models, stable IDs, provenance, diagnostics, limits, safe reader |
| `crates/luad-dialect-lua5*` | Version-specific detection, parsing, opcodes, lifting, validation |
| `crates/luad-analysis` | CFGs, dominators, xrefs, queries, diffs, symbolic callees, argument origins, call relations |
| `crates/luad-cli` | CLI contracts, input handling, exit behavior, rendering, schemas |
| `crates/luad-oracle` | Official-compiler harness, listing parser, differential assertions |
| `tests/fixtures` | Source corpus and bundled compiled chunks |
| `fuzz` | Coverage-guided detection, stock parser, and post-parse analysis targets (8 canonical targets) |

See [ARCHITECTURE.md](ARCHITECTURE.md) for data flow and invariants.

## Test taxonomy

Not all green tests prove the same thing.

### Static and build checks

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
- `cargo check --manifest-path fuzz/Cargo.toml`
- Workspace-level `unsafe_code = "forbid"` enforced across every package with an executable negative control.

### Structural and hostile-input tests

- parser fixtures for debug and stripped chunks;
- every-byte truncation tests;
- resource-limit and adversarial-count tests;
- property tests over arbitrary bytes;
- bounded hostile-input fuzz smoke suite across all 8 canonical targets via `scripts/fuzz_smoke.sh` (detection, 5 stock parsers, and Lua 5.1/5.4 post-parse analysis) generating compact JSON evidence artifacts;
- persistent coverage-guided fuzzing with maintained seed corpora.

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
