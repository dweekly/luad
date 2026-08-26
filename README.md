# `luad`

`luad` is a memory-safe, dialect-aware Rust CLI and library for inspecting, disassembling, validating, and analyzing compiled Lua bytecode.

## Project status

`luad` is a pre-release research tool. It is not currently suitable as the sole basis for security conclusions or production reverse-engineering decisions.

Lua 5.4.8 public disassembly has normalized typed agreement with the official
listing and an independent decoder. Embedded Lua 5.1 profile selection,
disassembly, operand-role validation, bounded register spans, closure captures,
prototype identity, public diagnostics, queries, and machine output close under the
Area 1 validator-and-diagnostic gate. The exact OpenWrt-derived Lua 5.1.5 LNUM32 public
read surface is qualified against reproducible macOS and Linux compiler authorities;
the target remains experimental until a release evidence bundle promotes it.
Streaming facts carry their own artifact and interpretation identity for stateless
firmware-tree ingestion.
Lua 5.1 calls expose bounded symbolic global/module labels, direct closure identities,
typed constant-key `GETTABLE`/`SELF` labels, stable instruction evidence, and explicit
unresolved reasons through `callees` and recursive export. Fixed call arguments expose
bounded, owner-qualified value-expression
origins through `origins`, including eager `CONCAT`, Lua `MOD`, and explicit cutoff
reasons without sink or taint policy. `callgraph` links calls to exact child prototypes
when direct closure flow or one literal global store establishes a unique relation;
unresolved relations remain explicit. Batch export treats readable non-bytecode inputs
as explicit skips, reports every input path, and returns default success when a mixed
firmware tree produces at least one complete file result.
Lua 5.1 prototype records also carry a versioned subtree-content identity for ordinary
cross-firmware joins without conflating the digest with source or runtime identity.
Lua 5.1 physical words are classified once from executable context: closure bindings
and `SETLIST C == 0` list-batch data remain physically auditable but cannot become CFG
nodes or invented calls. Callee and origin analysis share a bounded whole-tree capture
mutation summary, so a sibling or descendant write prevents stale closure resolution.
Recursive export emits the `luad-prototype-v2` identity scheme, which commits these
physical roles; the v1 encoder remains available as a compatibility definition.

All stock-Lua dialects remain **experimental** unless an exact release artifact
for the current revision and profile says otherwise. Internal library gates do not
substitute for public CLI and schema evidence.

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
| [`README.md`](README.md) | Project status, entry points, documentation index, build, and first-use commands. | 2026-08-25 | Public scope, support status, setup, primary commands, or the documentation set changes. |
| [`AGENTS.md`](AGENTS.md) | Binding repository instructions, product-batch boundaries, and safety constraints for coding agents. | 2026-08-25 | Development workflow, proof policy, current priority, or repository invariants change. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Crate responsibilities, model boundaries, trust layers, and architectural invariants. | 2026-08-25 | Crates, ownership boundaries, core representations, or evidence layers change. |
| [`CHANGELOG.md`](CHANGELOG.md) | Backward-facing record of unreleased and released user-visible changes. | 2026-08-25 | Every user-visible change or release; never use it as a forward plan. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor setup, test taxonomy, fixture provenance, and definition of done. | 2026-08-25 | Toolchain, test commands, gates, fixture policy, or contribution workflow changes. |
| [`PRD.md`](PRD.md) | Product users, firmware-tree workflows, factual analysis boundary, requirements, non-goals, and release outcomes. | 2026-08-25 | Product scope, target users, supported workflows, factual-analysis boundary, or product-level requirements change. |
| [`SECURITY.md`](SECURITY.md) | Supported-version policy, vulnerability reporting, and hostile-input threat model. | 2026-08-23 | Support policy, reporting channel, trust boundary, or threat model changes. |
| [`docs/DEVELOPMENT-WORKFLOW.md`](docs/DEVELOPMENT-WORKFLOW.md) | Customer-outcome batches, risk-triggered model diversity, proportional qualification, process budgets, and agent orchestration. | 2026-08-25 | Planning artifacts, customer cadence, agent roles, evidence policy, process budgets, or provider interfaces change. |
| [`ROADMAP.md`](ROADMAP.md) | Customer-led path through composable factual analysis and stable release. | 2026-08-25 | Product priorities, dependencies, customer evidence, qualification order, or exclusions change. |
| [`docs/NEXT-SPRINT.md`](docs/NEXT-SPRINT.md) | The sole active sprint contract for one measurable, independently gated unit of work. | 2026-08-25 | The sprint is accepted, respecified, or replaced; delete obsolete sprint content rather than retaining history. |
| [`docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md`](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md) | Present factual-tool requirements derived from the TP-Link/OpenWrt reverse-engineering use case. | 2026-08-25 | New corpus evidence changes target authority, fact boundaries, or workflows, or all unique requirements move into the PRD. |
| [`docs/MACHINE-INTERFACE.md`](docs/MACHINE-INTERFACE.md) | Machine formats, schemas, identities, commands, diagnostics, and exit behavior. | 2026-08-25 | Any public command, schema, record, stable ID, diagnostic, or exit contract changes. |
| [`docs/RELEASING.md`](docs/RELEASING.md) | Exact-target authority prerequisites, independent customer validation, evidence bundle, versioning, and publication policy. | 2026-08-25 | Release gates, target authority, customer-validation boundary, artifact channels, version policy, signing, or publication procedure changes. |
| [`docs/LUA51-LNUM32-CANDIDATE.md`](docs/LUA51-LNUM32-CANDIDATE.md) | Operational procedure for obtaining, verifying, and using the reproducible Lua 5.1 LNUM32 release candidate on unpacked firmware. | 2026-08-25 | Revalidate or delete when the LNUM32 candidate is promoted to stable release, candidate specification/schema changes, or real-firmware workflows change. |
| [`docs/examples/RECIPES.md`](docs/examples/RECIPES.md) | Practical command-line and composition recipes for consuming machine JSON and JSONL output. | 2026-08-25 | Machine interface envelopes, export records, or CLI subcommands change. |

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

The repository currently pins its contributor toolchain in `rust-toolchain.toml`. The long-term MSRV has not yet been established independently of that development-toolchain pin.

```console
git clone https://github.com/dweekly/luad.git
cd luad
cargo build --workspace
```

For the complete contributor check:

```console
bash scripts/check.sh
```

The full differential suite requires the exact official Lua compilers pinned by each gate:

```console
bash scripts/install_ci_compilers.sh
```

The aggregate check is necessary repository evidence, not instruction-level proof. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test taxonomy and required gates.

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

Licensed under either the MIT License or the Apache License, Version 2.0, at your option.
