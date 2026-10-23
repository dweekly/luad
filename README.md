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

Development follows the [customer-outcome workflow](docs/DEVELOPMENT-WORKFLOW.md):
small reviewed product batches, focused verification, and separate qualification for
support or compatibility promises. Experimental status does not relax the repository
invariants in [`AGENTS.md`](AGENTS.md). Passing CI establishes only what its assertions
cover; public counterexamples take priority over feature expansion.

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

Current development scope (unreleased):

| Dialect | Opcodes | Tier | State |
|---|---:|---|---|
| `lua5.1` | 38 | Experimental | Best exercised. LNUM32 firmware profile and stock layouts both read. |
| `lua5.2` | 40 | Experimental | Structural inspection/export and unverified text listing. Structured disassembly, effects, explanation and derived facts unavailable. |
| `lua5.3` | 47 | Experimental | Structural inspection/export and unverified text listing. No EdgeTX profile; structured disassembly, effects and explanation unavailable. |
| `lua5.4` | 83 | Experimental | Reads well; exact-disassembly evidence exists for 5.4.8. |
| `lua5.5` | 85 | Experimental | Structural inspection/export and unverified text listing. Structured disassembly, effects, explanation and derived facts unavailable. |

LuaJIT and Luau are separate bytecode systems and are out of scope. The capability
manifest does not list them in any tier.

No dialect is in the `supported` tier and the supported set is empty, which is what
`luad capabilities` reports. Experimental means the code is present and gives useful
answers, not that its correctness has been qualified.

`diff` compares exact decoded content by position, including constant bytes and numeric
representations, prototype shape, capture descriptors, headers/layouts, and physical
instruction words. `--semantic` adds decoded instruction fields and physical roles;
it retains unused bits and companion words. `--ignore debug` excludes names, line data,
and local scopes. Equality means no compared content changed, not behavioral equivalence
or byte identity; use the artifact hash for byte identity. See the
[machine interface](docs/MACHINE-INTERFACE.md#cfg-xrefs-query-and-diff) and
[public comparison regressions](crates/luad-oracle/tests/test_diff_cli.rs).

Convention-based linking requires explicit `--link-convention luci-module-setglobal`
and admits straight-line root initialization with one literal module declaration.
It uses final root closure stores, refuses ambiguous initialization and clobbering
operations, and cannot claim a unique target from an incomplete index. A binding is
conditional on that convention, not runtime reachability. See the
[exact admitted shapes, statuses and budgets](docs/MACHINE-INTERFACE.md#export)
and [executable controls](crates/luad-oracle/tests/test_cross_chunk_linking.rs).

Development callee/origin analysis invalidates call-frame temporaries before retaining
returned results. It also refuses stale captures across overlapping calls and generic
iterator control updates. Ordinary live locals, fresh definitions and exact literal
`require` results retain their facts. See the [call-frame evidence](crates/luad-oracle/tests/test_symbolic_callees_lua51.rs).
These are conditional static facts under the ordinary VM ABI and symbolic lookup
assumptions. Arbitrary C/reflection/debug mutation and all implicit metamethod effects
are not qualified; capture analysis can also lose precision after a closed cell's
register is reused. Derived records carry no runtime call-edge guarantee.

Development machine floats use JSON numbers for finite values and the exact strings
`nan`, `inf`, `-inf` for nonfinite classes. Raw source bits remain separate, including
NaN payloads; decoded NaN classes carry no host payload/sign promise. Typed finite
round trips use exact float parsing. Lua 5.3-5.5 format-check numbers must match exactly.
See [machine float semantics](docs/MACHINE-INTERFACE.md#floating-values).

Lua 5.2, 5.3, and 5.5 retain raw words and child structure through `inspect` and
`export --facts prototype,constant,upvalue`. Unverified text listings remain available without `--effects`; structured disassembly,
instruction effects and explanation refuse these profiles. Default export includes instruction facts and reports per-file
failure; explicit unavailable families also fail before emitting any facts. Use the
selected structural path when inventorying a mixed-version corpus. Derived analysis
commands retain their explicit refusal boundary.
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

[docs/PRIOR-ART-AND-CORPORA.md](docs/PRIOR-ART-AND-CORPORA.md) distinguishes dated
executed comparisons from source/documentation observations. Rizin's development
branch includes OpenWrt/TP-Link handling; unluac-rs provides a Rust library, CLI, and
browser workspace. Exact profile compatibility and comparative correctness require
task-specific runs with pinned versions. `luad` does not provide an EdgeTX profile.

The [roadmap](ROADMAP.md) requires useful public workflows and outside trials before
an experimental announcement. The intended contribution combines format interpretation,
byte evidence, explicit uncertainty, and a reliable machine interface. It does not
depend on other tools remaining deficient.

## Documentation index

This is the canonical index for every maintained Markdown document. “Fresh as of”
means the document's purpose and claims were reviewed against the repository on that
date; it does not replace executable evidence. When a listed trigger occurs, update or
delete the document in the same change and update this index.

| Document | Purpose | Fresh as of | Revalidate or delete when |
|---|---|---:|---|
| [`README.md`](README.md) | What luad is, installation, current limitations, first workflows, and the documentation index. | 2026-10-22 | Public scope, known analysis defects, support status, setup, workflows, or the documentation set changes. |
| [`AGENTS.md`](AGENTS.md) | Binding instructions, bounded implementation scope, completeness discipline, and safety constraints. | 2026-10-22 | Development workflow, proof policy, current priority, or repository invariants change. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Crate responsibilities, representations, completeness and context boundaries, and evidence layers. | 2026-10-22 | Crates, ownership, effect completeness, identity/context boundaries, or evidence layers change. |
| [`CHANGELOG.md`](CHANGELOG.md) | Backward-facing record of released and unreleased user-visible changes. | 2026-10-22 | Every user-visible change or release; never use it as a forward plan. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor verification commands, test taxonomy, fixture provenance, and definition of done. | 2026-10-22 | Toolchain, test commands, gates, fixture policy, or contribution workflow changes. |
| [`PRD.md`](PRD.md) | Community and firmware users, factual-composition requirements, scope, and release outcomes. | 2026-10-22 | Target users, workflows, factual boundary, prior-art claims, or product requirements change. |
| [`ROADMAP.md`](ROADMAP.md) | Ordered outcomes for reliable answers, the firmware consumer, public workflows, outside utility trials, announcement, and stabilization. | 2026-10-22 | A milestone closes, user evidence changes priorities, or scope, dependencies, release boundaries, or stop conditions change. |
| [`SECURITY.md`](SECURITY.md) | Supported-version policy, the planned 1.0 target matrix, vulnerability reporting, and hostile-input threat model. | 2026-09-16 | Support policy, the planned target matrix, reporting channel, trust boundary, or threat model changes. |
| [`docs/ROADMAP-1.0.md`](docs/ROADMAP-1.0.md) | Stable-release qualification obligations, exact targets, minimal machine contract, hostile-input evidence, and transfer. | 2026-10-22 | The stable target set, qualified surface, acceptance obligations, or qualification lifecycle changes. |
| [`docs/BRINGUP.md`](docs/BRINGUP.md) | Setup for a developer machine, a self-hosted Actions runner, and a release builder, with the owning file for every tool pin. | 2026-10-22 | A tool pin, its owning file, the doctor's checks, runner prerequisites, labels or security boundary, or the release dry-run and rehearsal entry points change. |
| [`docs/DEVELOPMENT-WORKFLOW.md`](docs/DEVELOPMENT-WORKFLOW.md) | Customer-outcome batches, evidence-based selection, proportional verification, qualification lanes, and orchestration. | 2026-10-22 | Selection criteria, planning ownership, CI lanes, roles, evidence policy, or sprint mechanics change. |
| [`docs/NEXT-SPRINT.md`](docs/NEXT-SPRINT.md) | Active contract for SETUPVAL operand classification in the Lua 5.2/5.3 validators (issue #108). | 2026-10-23 | A bounded contract replaces the checkpoint or the first roadmap outcome changes. |
| [`docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md`](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md) | Present factual-tool requirements derived from the TP-Link/OpenWrt reverse-engineering use case. | 2026-10-20 | New corpus evidence changes target authority, fact boundaries, or workflows, or all unique requirements move into the PRD. |
| [`docs/PRIOR-ART-AND-CORPORA.md`](docs/PRIOR-ART-AND-CORPORA.md) | Dated executed comparisons and source observations, corpus candidates, provenance, and research leads. | 2026-10-22 | A comparison is executed, a cited project/profile changes, or a candidate corpus is selected; source checks do not refresh older experiments. |
| [`docs/MACHINE-INTERFACE.md`](docs/MACHINE-INTERFACE.md) | Machine formats, identities, schemas, limits, completion, current analysis caveats, and exit behavior. | 2026-10-22 | Public commands, schemas, known limitations, identities, diagnostics, or completion/exit contracts change. |
| [`docs/RELEASING.md`](docs/RELEASING.md) | Release policy for 0.x and 1.0, exact-target order, qualification checklist, packaging, publication, and rollback. | 2026-09-17 | Release targets, qualification lifecycle, package platforms, artifact channel, compatibility, signing/checksum policy, ownership, or rollback changes. |
| [`docs/LUA51-LNUM32-CANDIDATE.md`](docs/LUA51-LNUM32-CANDIDATE.md) | Archived verification and firmware-handoff guide for the immutable, non-promoting Lua 5.1 LNUM32 RC1 artifact. | 2026-08-27 | RC1 evidence is retired, its retained artifacts become unverifiable, or a new LNUM32 candidate guide replaces it. |
| [`examples/export_reader/README.md`](examples/export_reader/README.md) | Bounded capture and schema/context/completion verification before consuming corpus facts. | 2026-10-22 | Reader behavior, bundle format, dependencies, limits, verified profiles, or commands change. |
| [`docs/examples/RECIPES.md`](docs/examples/RECIPES.md) | Practical command-line and composition recipes for consuming machine JSON and JSONL output. | 2026-10-22 | Machine interface envelopes, export records, CLI subcommands, or external handoff guidance change. |
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
