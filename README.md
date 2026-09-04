# `luad`

`luad` is a memory-safe, dialect-aware Rust CLI and library for inspecting, disassembling, validating, and analyzing compiled Lua bytecode.

## Project status

`luad` is a pre-release research tool. It is not currently suitable as the sole basis
for security conclusions or production reverse-engineering decisions. No dialect or
profile is promoted to the supported tier.

`luad` is the Lua bytecode verifier and fact source: it tells the truth about a chunk's
layout and internal consistency across Lua releases and vendor layouts, proves each
claim against the producing compiler's listing, and exports the facts under a machine
contract that decompilers and reverse-engineering platforms consume. It does not
decompile and does not compete on breadth of dialect parsing. Today it does not yet
meet its own bar: a header that declares a width the body does not use is reported
valid in Lua 5.2 and 5.3, and EdgeTX firmware chunks fail inside the body. Layout truth
is the first roadmap milestone.

The repository has public-boundary evidence for exact Lua 5.4.8 disassembly and a broad
experimental Lua 5.1 surface. The OpenWrt-derived Lua 5.1.5 LNUM32 public read contract
and compiler authority are qualified as prerequisites, but the retained RC1 candidate
is non-promoting and predates later correctness and machine-interface changes. Lua 5.2,
5.3, 5.5, stock Lua 5.1 layouts, and every other target remain experimental.

The [release procedure](docs/RELEASING.md#frozen-version-1-boundary) records the exact
future 1.0 targets, layouts, package platforms, machine-contract majors, owner, and
evidence location. The [path to 1.0](ROADMAP.md) keeps the existing explorations while
ordering layout truth, authority and corpus, exact targets, the minimal machine
contract, hostile-input evidence, and the final candidate. Future target names are obligations, not present support
claims.

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
| [`README.md`](README.md) | Project status, entry points, documentation index, build, and first-use commands. | 2026-09-03 | Public scope, support status, setup, primary commands, or the documentation set changes. |
| [`AGENTS.md`](AGENTS.md) | Binding repository instructions, product-batch boundaries, and safety constraints for coding agents. | 2026-08-27 | Development workflow, proof policy, current priority, or repository invariants change. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Crate responsibilities, model boundaries, trust layers, and architectural invariants. | 2026-08-27 | Crates, ownership boundaries, core representations, or evidence layers change. |
| [`CHANGELOG.md`](CHANGELOG.md) | Backward-facing record of unreleased and released user-visible changes. | 2026-09-03 | Every user-visible change or release; never use it as a forward plan. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor verification commands, test taxonomy, fixture provenance, and definition of done. | 2026-09-03 | Toolchain, test commands, gates, fixture policy, or contribution workflow changes. |
| [`PRD.md`](PRD.md) | Product users, firmware-tree workflows, factual analysis boundary, requirements, non-goals, and release outcomes. | 2026-09-03 | Product scope, target users, supported workflows, factual-analysis boundary, or product-level requirements change. |
| [`ROADMAP.md`](ROADMAP.md) | Dependency-ordered path to 1.0: the verifier-and-fact-source destination, the four-target support boundary, milestones from layout truth through the frozen candidate, acceptance, and post-1.0 research. | 2026-09-03 | Product targets, milestone order, release acceptance, package platforms, compatibility boundary, or exclusions change. |
| [`SECURITY.md`](SECURITY.md) | Supported-version policy, vulnerability reporting, and hostile-input threat model. | 2026-08-27 | Support policy, reporting channel, trust boundary, or threat model changes. |
| [`docs/BRINGUP.md`](docs/BRINGUP.md) | Setup for a developer machine, a self-hosted Actions runner, and a release builder, with the owning file for every tool pin. | 2026-09-02 | A tool pin, its owning file, the doctor's checks, runner labels or security boundary, or the release dry-run and rehearsal entry points change. |
| [`docs/DEVELOPMENT-WORKFLOW.md`](docs/DEVELOPMENT-WORKFLOW.md) | Customer-outcome batches, separate product and qualification CI lanes, proportional evidence, process budgets, and agent orchestration. | 2026-08-27 | Planning artifacts, CI lanes, customer cadence, agent roles, evidence policy, process budgets, provider interfaces, or sprint-advance mechanics change. |
| [`docs/NEXT-SPRINT.md`](docs/NEXT-SPRINT.md) | Neutral checkpoint authorizing no product implementation while the next stage of the release execution sequence is selected. | 2026-09-03 | The first unmet stage of the roadmap sequence replaces it with its contract: a qualification stage through a dedicated planning change, any other stage in the first commit of its own pull request. |
| [`docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md`](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md) | Present factual-tool requirements derived from the TP-Link/OpenWrt reverse-engineering use case. | 2026-08-27 | New corpus evidence changes target authority, fact boundaries, or workflows, or all unique requirements move into the PRD. |
| [`docs/PRIOR-ART-AND-CORPORA.md`](docs/PRIOR-ART-AND-CORPORA.md) | External tools, datasets, and bytecode-emitting ecosystems evaluated against the product scope, candidate fixture sources with license and provenance constraints, and the fidelity gaps they expose. | 2026-09-02 | A listed project changes license or status, a candidate corpus or vendor profile is adopted or rejected, or the PRD prior-art table is revised. |
| [`docs/MACHINE-INTERFACE.md`](docs/MACHINE-INTERFACE.md) | Machine formats, schemas, identities, commands, diagnostics, and exit behavior. | 2026-08-27 | Any public command, schema, record, stable ID, diagnostic, or exit contract changes. |
| [`docs/RELEASING.md`](docs/RELEASING.md) | Release stop, exact-target order, qualification checklist, evidence bundle, packaging, compatibility, publication, and rollback policy. | 2026-09-03 | Release targets, qualification lifecycle, package platforms, artifact channel, compatibility, signing/checksum policy, ownership, or rollback changes. |
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
| LuaJIT 2.x | — | No | Not supported and out of scope for the product; the capability manifest still reports the Planned tier until the machine-contract milestone retires the entry |

The embedded Lua 5.1 release scope is driven by a 252-file TP-Link corpus: header-declared 32-bit `size_t`, an explicit LNUM profile, correct closure-binding records, precise offsets, and inline resolved constants. Private-corpus results supplement—but never replace—redistributable fixtures and public-boundary proof. See the [embedded-firmware requirements](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md).

## How `luad` compares on non-stock chunks

[docs/PRIOR-ART-AND-CORPORA.md](docs/PRIOR-ART-AND-CORPORA.md) keeps a matrix of every
runnable Lua bytecode tool against chunks that stock desktop Lua never produces,
starting with EdgeTX radio firmware (32-bit Lua 5.3, 4-byte floats, a header slot that
does not describe the body). The honest summary as of 2026-09-02: tools built on the
stock loader (official `luac`, luadec, rizin, ChunkSpy) refuse those chunks by name; the
two unluac lineages read them correctly; `luad` accepts the header and then fails inside
the body with a diagnostic anchored at the wrong offset. Closing that row is tracked in
the [roadmap](ROADMAP.md) under vendor-profile candidates. The matrix is the acceptance
picture for that work, and this section is updated when a row changes.

## Build

The stable workspace MSRV is Rust 1.85. The repository separately pins a newer Rust
release in `rust-toolchain.toml` for contributors and release builders, and the fuzz
suite uses its own pinned nightly. All production crates inherit the workspace's
`unsafe_code = "forbid"` policy.

Machine setup is one document: [docs/BRINGUP.md](docs/BRINGUP.md). It covers the
toolchains, the dependency-policy and SBOM tools, the fuzz nightly and `cargo-fuzz`, the
five official Lua compilers, and the OpenWrt LNUM32 authority compiler, and it names the
file that owns each pinned version.

```console
git clone https://github.com/dweekly/luad.git
cd luad
bash scripts/bringup.sh --install
bash scripts/check.sh
```

`scripts/bringup.sh --doctor` reports every required tool with its expected and found
version at any time, and exits non-zero if one is missing or wrong.

A checked-out source tree can install the `luad` binary into Cargo's normal install root:

```console
cargo install --path crates/luad-cli --locked
```

This is a source install, not a crates.io channel. All workspace packages are marked
`publish = false`; `cargo install luad` is not supported or advertised for 1.0. The
primary planned 1.0 channel remains the verified GitHub release archives.

The required dependency-policy job runs the pinned `cargo-deny` release against the
locked Linux and macOS graph:

```console
cargo deny --locked check advisories licenses
```

The reviewed policy is [`deny.toml`](deny.toml). This gate checks declared dependency
licenses and current RustSec advisories; it is not a legal opinion, manual source-license
review, SBOM, or binary-composition proof.

To run the bounded hostile-input fuzz smoke suite:

```console
scripts/fuzz_smoke.sh artifacts/fuzz-smoke
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
named `luad-linux` and `luad-macos` self-hosted runner classes and pinned toolchain;
each job also verifies its declared OS, architecture, and Rust host triple. The
remaining release work is tracked in the [roadmap](ROADMAP.md).

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

## Release bundle dry run

The required `Release Bundle` CI check combines the accepted two-platform archive
artifact and SBOM with references to the successful dependency-audit, Linux archive
oracle, SBOM, and hosted archive checks from the same clean revision. The maintained
entry point is:

```console
./scripts/assemble-release-bundle.sh \
  /tmp/release-archives \
  /tmp/release-sbom/luad-<version>.cdx.json \
  /tmp/release-prerequisites.json \
  /tmp/release-bundle
```

The output is exactly the two archives, the SBOM, `evidence-index.json`, and a
`SHA256SUMS` covering those four payload files. The index preserves each archive's
member ledger and installation transcript, binds every input and prerequisite reference
to one revision, and requires an empty promoted-target set. CI assembles twice, compares
all five files byte for byte, verifies them, and exercises a corruption control.

The hosted workflow creates the prerequisite-reference document from actual job
results. A locally authored document or seven-day `release-bundle` upload is not proof
of those results or target promotion.

## Non-production publication rehearsal

Maintainers can dispatch `Release Publication` from `main` with one full source
revision and its successful `CI` run ID. The workflow reuses that run's exact bundle,
exercises failed-publication cleanup and valid-release withdrawal, then retains one
plainly labeled prerelease:

```text
publication-rehearsal-<version>-<12-revision-hex>
```

The retained release contains the same five custom files plus GitHub's normal source
archives. Fresh downloads, checksums, bundle identity, tag target, release metadata, and
both source archive forms are verified. It is not latest, not signed, names no supported
target, and is not a product release or 1.0 candidate. The exact dispatch and withdrawal
commands are in the [release procedure](docs/RELEASING.md#non-production-publication-rehearsal).

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
