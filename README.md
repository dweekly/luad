<p align="center">
  <a href="https://dweekly.github.io/luad/">
    <img src="site/logo.png" alt="luad: a smiling crescent moon inside a magnifying glass" width="160" height="160">
  </a>
</p>

<h1 align="center">luad</h1>

<p align="center">
  <a href="https://github.com/dweekly/luad/actions/workflows/ci.yml"><img src="https://github.com/dweekly/luad/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://codecov.io/gh/dweekly/luad"><img src="https://codecov.io/gh/dweekly/luad/branch/main/graph/badge.svg" alt="Codecov coverage"></a>
  <a href="https://github.com/dweekly/luad/releases/latest"><img src="https://img.shields.io/github/v/release/dweekly/luad" alt="Latest release"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0"></a>
</p>

`luad` reads compiled Lua bytecode and tells you what is in it: the exact format it was
built for, the instructions, the constants, the closure bindings, and where every one of
those facts lives in the original bytes. It is a memory-safe Rust CLI and library for
inspecting, disassembling, validating, and analyzing Lua chunks — including the
non-standard ones that turn up inside extracted router and embedded firmware.

It does not decompile. When you want source back, `luad` tells you exactly which profile
the chunk uses so you can hand it to a decompiler that reads that profile.

## Status: 0.3.1, experimental

This is an early release of a tool built for fun. It works, and it gives real answers on
real firmware, but no dialect is promoted to a supported tier and nothing here is
qualified as a basis for security conclusions. Lua 5.2, 5.3, and 5.5 provide structural
facts and validation; derived analysis is refused for these dialects. Please file issues.

See [limitations](#limitations) for what specifically does not work yet.

## What it does

Every command below runs against a fixture in this repository, so you can reproduce it
after cloning.

```console
$ luad inspect tests/fixtures/precompiled/lua51_lnum32/hello.luac
=== Chunk Overview ===
SHA-256:           8376be37ec3042d3b0a87aa39db7d7396fb54ae390abe346d885e1527d23e353
Byte Length:       249 bytes
Dialect:           lua5.1-lnum32
Profile:           lua5.1-lnum32
Selection Mode:    Detected
Layout:            int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4
Verdict:           ValidForParser
```

That `Layout` line is the point. This chunk is an OpenWrt-style build with a 32-bit
`size_t` and an integer-flavored number representation — stock desktop Lua never emits
it, and tools built on the stock loader refuse it or read it wrong. The command prints
the full header and prototype summary below this; the overview is the first block.

```console
$ luad disasm tests/fixtures/precompiled/lua51_lnum32/hello.luac
; ==========================================================================
; proto:0 (source: @tests/fixtures/hello.lua, lines 0-0, stack: 4)
; params: 0, is_vararg: 2, instructions: 9, constants: 4
; ==========================================================================
; Constants:
;   k[0] = "print"
;   k[1] = "Hello, luad!"
;   k[2] = "Lua 5.4 bytecode analysis"
;   k[3] = 42

   0  GETGLOBAL    R(0) K(0) ; "print"
   1  LOADK        R(1) K(1) ; "Hello, luad!"
   2  CALL         R(0) 2 1
   3  LOADK        R(0) K(2) ; "Lua 5.4 bytecode analysis"
   4  LOADK        R(1) K(3) ; 42
   5  MOVE         R(2) R(0)
   6  MOVE         R(3) R(1)
   7  RETURN       R(2) 3
   8  RETURN       R(0) 1
```

Constants are resolved inline at their use sites. Add `--raw` for the encoded words and
`--effects` for each instruction's semantic effect.

Most of this is also available as JSON and JSONL with published schemas, so you can
build on it without scraping text. Supported formats vary by command — see
[machine interface](#machine-interface).

## Install

Prebuilt archives for `linux-x86_64` and `macos-aarch64` are attached to each
[GitHub release](https://github.com/dweekly/luad/releases). Download, verify the
checksum, and extract.

From source, with a Rust 1.85 or newer toolchain:

```console
git clone https://github.com/dweekly/luad.git
cd luad
cargo install --path crates/luad-cli --locked
```

This is a source install. Workspace packages are marked `publish = false`, so
`cargo install luad` from crates.io is not a supported channel.

Contributors setting up the full toolchain, the official Lua compilers, and the fuzz
suite should use [docs/BRINGUP.md](docs/BRINGUP.md) instead.

## Commands

```console
luad inspect chunk.luac                     # identify format and summarize
luad disasm chunk.luac --raw --effects      # faithful listing with byte provenance
luad validate chunk.luac --strict           # structural and VM-invariant checks
luad explain chunk.luac 'proto:0:pc:3'      # explain one field or instruction
luad export firmware/*.lua --format jsonl   # deterministic batch export
luad diagnostics L51-REG-SPAN-001           # look up a diagnostic code
```

Also present, and explicitly experimental: `cfg`, `callees`, `callgraph`, `origins`,
`xrefs`, `query`, and `diff`. These produce useful output but their schemas and
semantics may change without notice. `callees`, `callgraph`, and `origins` currently
require a Lua 5.1 profile and say so when given anything else.

Output formats are not uniform across commands:

| Command | `text` | `json` | `jsonl` |
|---|:--:|:--:|:--:|
| `inspect`, `disasm`, `explain` | yes | yes | yes |
| `cfg`, `xrefs`, `query`, `diff` | yes | yes | yes |
| `validate` | yes | yes | no |
| `diagnostics` | yes | yes | no |
| `export` | no | no | **jsonl only** |

`export` is the streaming batch interface and deliberately emits JSONL only.

The repository ships precompiled fixtures, so you can try it without a Lua compiler:

```console
cargo run -q -p luad-cli -- inspect tests/fixtures/precompiled/lua54/hello.luac
```

`luad` analyzes bytecode as data. It never invokes an external compiler and never
executes the chunk.

## Firmware investigation walkthrough

A reproducible four-phase investigation using the public firmware-shaped fixture
tree at `tests/fixtures/firmware_tree/`:

```console
# 1. Inventory and triage mixed artifacts via streaming JSONL export:
luad export tests/fixtures/firmware_tree/*.lua tests/fixtures/firmware_tree/*.luac --format jsonl | \
  jq -c 'select(.record_type == "export_end") | {processed: .files_processed, succeeded: .files_succeeded, skipped: .files_skipped, failed: .files_failed}'
# {"processed":5,"succeeded":2,"skipped":3,"failed":0}

# 2. Inspect layout and dialect authority (OpenWrt LNUM32 vs stock vs unsupported):
luad inspect tests/fixtures/firmware_tree/dispatcher.lua
# Dialect: lua5.1-lnum32, Layout: int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4

# 3. Extract constants, search global lookups, and disassemble with effects:
luad export tests/fixtures/firmware_tree/dispatcher.lua --format jsonl --facts constant
luad query tests/fixtures/firmware_tree/dispatcher.lua --where "mnemonic == 'GETGLOBAL'"
luad disasm tests/fixtures/firmware_tree/dispatcher.lua --raw --effects

# 4. Informed decompiler handoff:
# system_service.luac declares stock Lua 5.1 (sizet=8, integral_flag=0).
# dispatcher.lua declares LNUM32 (sizet=4, integral_flag=4).
# Choose a decompiler that accepts the exact profile; compatibility is tool-specific.
```

See [docs/examples/RECIPES.md](docs/examples/RECIPES.md#13-reproducible-firmware-investigation-walkthrough)
for the complete recipe and optional decompiler experiment. No external decompiler is
required to build or test luad; the walkthrough verifies luad facts and refusal behavior.

## Limitations

Current scope in 0.3.1:

| Dialect | Opcodes | Tier | State |
|---|---:|---|---|
| `lua5.1` | 38 | Experimental | Best exercised. LNUM32 firmware profile and stock layouts both read. |
| `lua5.2` | 40 | Experimental | Declared widths validated; implemented layouts decoded, other layouts refused. Derived analysis unavailable. |
| `lua5.3` | 47 | Experimental | Declared widths and numeric canaries validated. Unsupported numeric layouts refused; no EdgeTX profile or derived analysis. |
| `lua5.4` | 83 | Experimental | Reads well; exact-disassembly evidence exists for 5.4.8. |
| `lua5.5` | 85 | Experimental | Header/count bounds and operands checked. Derived analysis unavailable. |

LuaJIT and Luau are separate bytecode systems and are out of scope. The capability
manifest does not list them in any tier.

No dialect is in the `supported` tier and the supported set is empty, which is what
`luad capabilities` reports. Experimental means the code is present and gives useful
answers, not that its correctness has been qualified.

Lua 5.2, 5.3, and 5.5 are limited to structural facts and validation. Derived analysis
commands refuse these dialects rather than presenting unqualified semantic results.
Layout, operand, analysis-eligibility, and malformed-input regressions cover the fixes
in 0.3.1; they do not establish complete semantic correctness or support for every
vendor layout. See [the changelog](CHANGELOG.md#031--2026-09-18) for release details.

`luad` also does not do firmware extraction, decompilation, source reconstruction,
exploitability judgment, or persistent research state. Those belong in other tools, and
[the roadmap](ROADMAP.md) lists which ones to reach for.

"Valid" from `luad validate` means consistent with the selected format and the named
checks. It does not mean the chunk is safe to execute, or that its producer is known.

## Machine interface

Discover the live surface rather than scraping human output:

```console
luad capabilities --format json
luad diagnostics --format json
luad schema capabilities
luad schema chunk
```

Consumers should read [docs/MACHINE-INTERFACE.md](docs/MACHINE-INTERFACE.md) for exit
codes, stable-ID scope, truncation behavior, and the stdout/stderr contract. Schemas are
versioned, but at 0.3.1 nothing carries a compatibility promise yet.

[docs/examples/RECIPES.md](docs/examples/RECIPES.md) has practical composition recipes.

## How `luad` compares on non-stock chunks

[docs/PRIOR-ART-AND-CORPORA.md](docs/PRIOR-ART-AND-CORPORA.md) keeps a matrix of every
runnable Lua bytecode tool against chunks that stock desktop Lua never produces,
starting with EdgeTX radio firmware (32-bit Lua 5.3, 4-byte floats, a header slot that
does not describe the body). The honest summary as of 2026-09-02: tools built on the
stock loader (official `luac`, luadec, rizin, ChunkSpy) refuse those chunks by name; the
two unluac lineages read them correctly. luad 0.3.1 refuses unsupported numeric layouts
at the header; it does not provide an EdgeTX profile.

This dated comparison informs the work. No goal here requires other tools to remain
deficient — an upstream project fixing a defect is a good outcome.

## Documentation index

This is the canonical index for every maintained Markdown document. “Fresh as of”
means the document's purpose and claims were reviewed against the repository on that
date; it does not replace executable evidence. When a listed trigger occurs, update or
delete the document in the same change and update this index.

| Document | Purpose | Fresh as of | Revalidate or delete when |
|---|---|---:|---|
| [`README.md`](README.md) | What `luad` is, install, first commands, honest limitations, and the documentation index. | 2026-09-18 | Public scope, support status, setup, primary commands, or the documentation set changes. |
| [`AGENTS.md`](AGENTS.md) | Binding repository instructions, product-batch boundaries, and safety constraints for coding agents. | 2026-08-27 | Development workflow, proof policy, current priority, or repository invariants change. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Crate responsibilities, model boundaries, trust layers, and architectural invariants. | 2026-08-27 | Crates, ownership boundaries, core representations, or evidence layers change. |
| [`CHANGELOG.md`](CHANGELOG.md) | Backward-facing record of released and unreleased user-visible changes. | 2026-09-18 | Every user-visible change or release; never use it as a forward plan. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor verification commands, test taxonomy, fixture provenance, and definition of done. | 2026-09-18 | Toolchain, test commands, gates, fixture policy, or contribution workflow changes. |
| [`PRD.md`](PRD.md) | Product users, firmware-tree workflows, factual analysis boundary, requirements, non-goals, and release outcomes. | 2026-09-06 | Product scope, target users, supported workflows, factual-analysis boundary, or product-level requirements change. |
| [`ROADMAP.md`](ROADMAP.md) | Release completion boundary, future researcher outcomes, sequencing, and target support boundaries. | 2026-09-17 | Release scope, dependencies, parallel ownership, acceptance criteria, support boundaries, or exclusions change. |
| [`SECURITY.md`](SECURITY.md) | Supported-version policy, the planned 1.0 target matrix, vulnerability reporting, and hostile-input threat model. | 2026-09-16 | Support policy, the planned target matrix, reporting channel, trust boundary, or threat model changes. |
| [`docs/ROADMAP-1.0.md`](docs/ROADMAP-1.0.md) | The full qualification program a future 1.0 would need: milestones, evidence gates, target promotion, and release acceptance. | 2026-09-16 | The 1.0 destination, milestone order, release acceptance, or the qualification lifecycle changes. |
| [`docs/BRINGUP.md`](docs/BRINGUP.md) | Setup for a developer machine, a self-hosted Actions runner, and a release builder, with the owning file for every tool pin. | 2026-09-02 | A tool pin, its owning file, the doctor's checks, runner labels or security boundary, or the release dry-run and rehearsal entry points change. |
| [`docs/DEVELOPMENT-WORKFLOW.md`](docs/DEVELOPMENT-WORKFLOW.md) | Customer-outcome batches, separate product and qualification CI lanes, proportional evidence, process budgets, and agent orchestration. | 2026-08-27 | Planning artifacts, CI lanes, customer cadence, agent roles, evidence policy, process budgets, provider interfaces, or sprint-advance mechanics change. |
| [`docs/NEXT-SPRINT.md`](docs/NEXT-SPRINT.md) | No-feature-work checkpoint; select the next contract separately. | 2026-09-18 | A stage replaces it with its contract: a qualification stage through a dedicated planning change, any other stage in the first commit of its own pull request. |
| [`docs/FEATURE-REQUEST-PLAN.md`](docs/FEATURE-REQUEST-PLAN.md) | Proposed boundaries and evidence for the remaining Deco-derived VM-fact requests. | 2026-09-18 | The active sprint selects, rejects, or materially rescopes a listed outcome; a public fact boundary, evidence gate, or feature-request priority changes. |
| [`docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md`](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md) | Present factual-tool requirements derived from the TP-Link/OpenWrt reverse-engineering use case. | 2026-08-27 | New corpus evidence changes target authority, fact boundaries, or workflows, or all unique requirements move into the PRD. |
| [`docs/PRIOR-ART-AND-CORPORA.md`](docs/PRIOR-ART-AND-CORPORA.md) | External tools, datasets, and bytecode-emitting ecosystems evaluated against the product scope, candidate fixture sources with license and provenance constraints, and the fidelity gaps they expose. | 2026-09-06 | A listed project changes license or status, a candidate corpus or vendor profile is adopted or rejected, or the PRD prior-art table is revised. |
| [`docs/MACHINE-INTERFACE.md`](docs/MACHINE-INTERFACE.md) | Machine formats, schemas, identities, commands, diagnostics, and exit behavior. | 2026-09-18 | Any public command, schema, record, stable ID, diagnostic, or exit contract changes. |
| [`docs/RELEASING.md`](docs/RELEASING.md) | Release policy for 0.x and 1.0, exact-target order, qualification checklist, packaging, publication, and rollback. | 2026-09-17 | Release targets, qualification lifecycle, package platforms, artifact channel, compatibility, signing/checksum policy, ownership, or rollback changes. |
| [`docs/LUA51-LNUM32-CANDIDATE.md`](docs/LUA51-LNUM32-CANDIDATE.md) | Archived verification and firmware-handoff guide for the immutable, non-promoting Lua 5.1 LNUM32 RC1 artifact. | 2026-08-27 | RC1 evidence is retired, its retained artifacts become unverifiable, or a new LNUM32 candidate guide replaces it. |
| [`docs/examples/RECIPES.md`](docs/examples/RECIPES.md) | Practical command-line and composition recipes for consuming machine JSON and JSONL output. | 2026-09-18 | Machine interface envelopes, export records, CLI subcommands, or external handoff guidance change. |
| [`docs/reviews/2026-08-25-roadmap-review.md`](docs/reviews/2026-08-25-roadmap-review.md) | Archived point-in-time roadmap and release-readiness critique retained as planning provenance, not current status. | 2026-08-27 | Delete only when its planning provenance is intentionally retired; never revalidate it as current release evidence. |

## Contributing

Issues and pull requests welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) for the
test taxonomy and required gates, [ARCHITECTURE.md](ARCHITECTURE.md) for the crate
boundaries, and [AGENTS.md](AGENTS.md) if you are driving a coding agent.

Security policy and the hostile-input threat model: [SECURITY.md](SECURITY.md).
Release mechanics: [docs/RELEASING.md](docs/RELEASING.md).

To run the aggregate check:

```console
bash scripts/check.sh
```

## License

Licensed under either the [MIT License](LICENSE) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
