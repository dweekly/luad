# `luad`

`luad` is a memory-safe, dialect-aware Rust CLI and library for inspecting, disassembling, validating, and analyzing compiled Lua bytecode.

## Project status

`luad` is a pre-release research tool. It is not currently suitable as the sole basis
for security conclusions or production reverse-engineering decisions. No dialect or
profile is promoted to the supported tier.

The repository has public-boundary evidence for exact Lua 5.4.8 disassembly and a broad
experimental Lua 5.1 surface. The OpenWrt-derived Lua 5.1.5 LNUM32 public read contract
and compiler authority are qualified as prerequisites, but the retained RC1 candidate
is non-promoting and predates later correctness and machine-interface changes. Lua 5.2,
5.3, 5.5, stock Lua 5.1 layouts, and every other target remain experimental.

The [release procedure](docs/RELEASING.md#frozen-version-1-boundary) records the exact
future 1.0 targets, layouts, package platforms, machine-contract majors, owner, and
evidence location. The [path to 1.0](ROADMAP.md) keeps the existing explorations while
ordering the remaining packaging, public-contract, hostile-input, exact-target,
workflow-transfer, and publication work. Future target names are obligations, not
present support claims.

The architectural boundary is deliberate: `luad` owns deterministic VM facts that
competent analysts should agree on, while callers own investigation-specific judgments
such as whether a callee is dangerous, whether a value is attacker-controlled, or
whether a path is exploitable. The CLI should make an external security layer easy to
write correctly without absorbing that layer's policy or persistent state.

## Documentation index

This is the canonical index for every maintained Markdown document. “Fresh as of”
means the document's purpose and claims were reviewed against the repository on that
date; it does not replace executable evidence. When a listed trigger occurs, update or
delete the document in the same change and update this index.

| Document | Purpose | Fresh as of | Revalidate or delete when |
|---|---|---:|---|
| [`README.md`](README.md) | Project status, entry points, documentation index, build, and first-use commands. | 2026-08-27 | Public scope, support status, setup, primary commands, or the documentation set changes. |
| [`AGENTS.md`](AGENTS.md) | Binding repository instructions, product-batch boundaries, and safety constraints for coding agents. | 2026-08-27 | Development workflow, proof policy, current priority, or repository invariants change. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Crate responsibilities, model boundaries, trust layers, and architectural invariants. | 2026-08-27 | Crates, ownership boundaries, core representations, or evidence layers change. |
| [`CHANGELOG.md`](CHANGELOG.md) | Backward-facing record of unreleased and released user-visible changes. | 2026-08-27 | Every user-visible change or release; never use it as a forward plan. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor setup, test taxonomy, fixture provenance, and definition of done. | 2026-08-27 | Toolchain, test commands, gates, fixture policy, or contribution workflow changes. |
| [`PRD.md`](PRD.md) | Product users, firmware-tree workflows, factual analysis boundary, requirements, non-goals, and release outcomes. | 2026-08-27 | Product scope, target users, supported workflows, factual-analysis boundary, or product-level requirements change. |
| [`ROADMAP.md`](ROADMAP.md) | Detailed dependency-ordered path to a narrow, exact, robust, documented, and obtainable 1.0 release. | 2026-08-27 | Product targets, milestone order, release acceptance, package platforms, compatibility boundary, or exclusions change. |
| [`SECURITY.md`](SECURITY.md) | Supported-version policy, vulnerability reporting, and hostile-input threat model. | 2026-08-27 | Support policy, reporting channel, trust boundary, or threat model changes. |
| [`docs/DEVELOPMENT-WORKFLOW.md`](docs/DEVELOPMENT-WORKFLOW.md) | Customer-outcome batches, separate product and qualification CI lanes, proportional evidence, process budgets, and agent orchestration. | 2026-08-27 | Planning artifacts, CI lanes, customer cadence, agent roles, evidence policy, process budgets, provider interfaces, or sprint-advance mechanics change. |
| [`docs/NEXT-SPRINT.md`](docs/NEXT-SPRINT.md) | Active release-infrastructure contract for assembling and verifying the five-file non-promoting release bundle and evidence index. | 2026-08-27 | Replace with the neutral checkpoint when bounded bundle composition, prerequisite references, checksum and corruption controls, hosted dry run, and documentation close, or revise before implementation if that boundary changes. |
| [`docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md`](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md) | Present factual-tool requirements derived from the TP-Link/OpenWrt reverse-engineering use case. | 2026-08-27 | New corpus evidence changes target authority, fact boundaries, or workflows, or all unique requirements move into the PRD. |
| [`docs/MACHINE-INTERFACE.md`](docs/MACHINE-INTERFACE.md) | Machine formats, schemas, identities, commands, diagnostics, and exit behavior. | 2026-08-27 | Any public command, schema, record, stable ID, diagnostic, or exit contract changes. |
| [`docs/RELEASING.md`](docs/RELEASING.md) | Release stop, exact-target order, qualification checklist, evidence bundle, packaging, compatibility, publication, and rollback policy. | 2026-08-27 | Release targets, qualification lifecycle, package platforms, artifact channel, compatibility, signing/checksum policy, ownership, or rollback changes. |
| [`docs/LUA51-LNUM32-CANDIDATE.md`](docs/LUA51-LNUM32-CANDIDATE.md) | Archived verification and firmware-handoff guide for the immutable, non-promoting Lua 5.1 LNUM32 RC1 artifact. | 2026-08-27 | RC1 evidence is retired, its retained artifacts become unverifiable, or a new LNUM32 candidate guide replaces it. |
| [`docs/examples/RECIPES.md`](docs/examples/RECIPES.md) | Practical command-line and composition recipes for consuming machine JSON and JSONL output. | 2026-08-27 | Machine interface envelopes, export records, or CLI subcommands change. |
| [`docs/reviews/2026-08-25-roadmap-review.md`](docs/reviews/2026-08-25-roadmap-review.md) | Archived point-in-time roadmap and release-readiness critique retained as planning provenance, not current status. | 2026-08-27 | Delete only when its planning provenance is intentionally retired; never revalidate it as current release evidence. |

## Intended scope

`luad` aims to provide deterministic facts derived from Lua bytecode:

- lossless structural parsing with byte provenance;
- dialect-specific instruction decoding and validation;
- semantic instruction effects;
- control-flow graphs, dominators, cross-references, queries, and diffs;
- stable machine-readable output and schemas;
- bounded behavior on malformed or adversarial input.

Researcher judgment, persistent interpretations, project state, and agent planning
belong outside `luad`. The CLI exports deterministic facts for external tools and
agents to interpret.

## Implemented dialect surface

This table describes code present in the repository, not verified support status.

| Dialect | Opcode table | Parser/lifter present | Current evidence status |
|---|---:|---|---|
| Lua 5.1 | 38 | Yes | Experimental; the exact LNUM32 public read surface and compiler authority are qualified, while stock layouts and release promotion remain independent |
| Lua 5.2 | 40 | Yes | Experimental; proof gates incomplete |
| Lua 5.3 | 47 | Yes | Experimental; proof gates incomplete |
| Lua 5.4 | 83 | Yes | Experimental; public disassembly, validation, analysis, lossless, and machine-contract evidence exists; exact target promotion remains pending |
| Lua 5.5 | 85 | Yes | Experimental; independent proof gates incomplete |
| LuaJIT 2.x | — | No | Planned; not supported |

The embedded Lua 5.1 release scope is driven by a 252-file TP-Link corpus: header-declared 32-bit `size_t`, an explicit LNUM profile, correct closure-binding records, precise offsets, and inline resolved constants. Private-corpus results supplement—but never replace—redistributable fixtures and public-boundary proof. See the [embedded-firmware requirements](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md).

## Build

The stable workspace MSRV is Rust 1.85. The repository separately pins Rust 1.97.1 in
`rust-toolchain.toml` for contributors and release builders, and the fuzz suite uses
its own pinned nightly. All production crates inherit the workspace's
`unsafe_code = "forbid"` policy.

```console
git clone https://github.com/dweekly/luad.git
cd luad
cargo build --workspace
```

A checked-out source tree can install the `luad` binary into Cargo's normal install root:

```console
cargo install --path crates/luad-cli --locked
```

This is a source install, not a crates.io channel. All workspace packages are marked
`publish = false`; `cargo install luad` is not supported or advertised for 1.0. The
primary planned 1.0 channel remains the verified GitHub release archives.

For the complete contributor check:

```console
bash scripts/check.sh
```

The required dependency-policy job uses `cargo-deny` 0.20.2 against the locked Linux
and macOS graph:

```console
cargo deny --locked check advisories licenses
```

The reviewed policy is [`deny.toml`](deny.toml). This gate checks declared dependency
licenses and current RustSec advisories; it is not a legal opinion, manual source-license
review, SBOM, or binary-composition proof.

To run the bounded hostile-input fuzz smoke suite:

```console
rustup toolchain install nightly-2026-08-25
cargo install cargo-fuzz --version 0.13.2 --locked
scripts/fuzz_smoke.sh artifacts/fuzz-smoke
```

The full differential suite requires the exact official Lua compilers pinned by each gate:

```console
bash scripts/install_ci_compilers.sh
```

The aggregate check is necessary repository evidence, not instruction-level proof. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test taxonomy and required gates.

## Local release archive dry run

From a clean checkout on Linux x86-64 or macOS arm64, the maintained packaging command
builds the host binary, creates the deterministic archive and sidecars, independently
verifies them, extracts into a fresh temporary directory, and runs the packaged version
and capabilities smokes:

```console
./scripts/package-release.sh /tmp/luad-release
```

The output directory must be new or empty. It receives
`luad-<version>-<platform>.tar.gz`, its JSON member ledger, `SHA256SUMS`, and a JSON
installation transcript. The archive contains only a top-level
`luad-<version>-<platform>/` directory with `luad`, `README.md`, `LICENSE`,
`LICENSE-APACHE`, and `VERSION.json`.

This is a local, non-promoting packaging check. It does not publish an artifact, qualify
a host or Lua target, or include the separately generated SBOM.

The required `Release Archives` CI check runs the same command in two independent Rust
1.97.1 jobs for each planned release platform. It requires byte-identical archives,
ledgers, one-entry checksums, and installation transcripts for each platform, verifies
a combined two-entry `SHA256SUMS`, and exercises archive-byte and checksum corruption
controls. Its seven-day `release-archives` upload is diagnostic transport, not a
published release or durable authority. The result proves repeatability only within the
named GitHub runner classes and pinned toolchain; the remaining release work is tracked
in the [roadmap](ROADMAP.md).

## Release SBOM dry run

With the exact `cargo-cyclonedx` 0.5.9 executable installed, a clean checkout can write
and independently verify the release dependency inventory:

```console
CARGO_CYCLONEDX="$(command -v cargo-cyclonedx)" \
  ./scripts/generate-release-sbom.sh /tmp/luad-sbom
```

The new or empty output directory receives exactly `luad-<version>.cdx.json`: canonical,
path-independent CycloneDX 1.5 JSON bound to the clean source revision and `Cargo.lock`
digest. The verifier compares components, scopes, licenses, registry checksums, and
dependency edges with locked Cargo metadata. CI pins the official Linux generator asset
and compares output from two clean checkout paths.

This is a conservative source inventory for the `luad` executable's normal and build
dependency graph across all Cargo target conditions. It is not a platform-specific
binary-composition attestation, vulnerability result, published release asset, or target
promotion record.

## First use

The repository includes precompiled fixtures, so no Lua compiler is needed for a basic smoke test:

```console
cargo run -q -p luad-cli -- \
  inspect tests/fixtures/precompiled/lua54/hello.luac --summary

cargo run -q -p luad-cli -- \
  disasm tests/fixtures/precompiled/lua54/hello.luac --raw --effects
```

Common commands:

```console
luad inspect chunk.luac
luad disasm chunk.luac --raw --debug-info --effects
luad validate chunk.luac --strict
luad explain chunk.luac 'proto:0:pc:3'
luad cfg chunk.luac --proto 'proto:0' --format dot
luad callees chunk.luac --format jsonl
luad callgraph chunk.luac --format jsonl
luad origins chunk.luac --format jsonl
luad xrefs chunk.luac --to 'proto:0:upvalue:0' --format json
luad query chunk.luac --where 'opcode == "CALL"' --format json
luad diff old.luac new.luac --semantic --format json
luad export firmware/*.lua --format jsonl --max-facts-per-file 10000
luad diagnostics L51-REG-SPAN-001
```

`luad` analyzes bytecode as data and does not invoke external compilers.

## Machine interface

Discover the live command and schema surface instead of scraping human-readable output:

```console
luad --help
luad capabilities --format json
luad diagnostics --format json
luad schema capabilities
luad schema diagnostics
luad schema chunk
luad schema instruction
```

Machine consumers should read [docs/MACHINE-INTERFACE.md](docs/MACHINE-INTERFACE.md), including the stability warning, exit codes, stable-ID scope, truncation behavior, and stdout/stderr contract.

## Contributing

- Human contributors: [CONTRIBUTING.md](CONTRIBUTING.md)
- Coding agents: [AGENTS.md](AGENTS.md)
- Architecture and invariants: [ARCHITECTURE.md](ARCHITECTURE.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Release procedure: [docs/RELEASING.md](docs/RELEASING.md)
- Product requirements: [PRD.md](PRD.md)

## License

Licensed under either the [MIT License](LICENSE) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
