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

`luad` reads compiled Lua bytecode and tells you what's in it: the exact format it was
built for, its instructions, constants and closure bindings, and where each of those
sits in the original bytes. It's a Rust command-line tool and library, written without
`unsafe` code, and it handles the nonstandard Lua chunks that turn up in router and other
embedded firmware.

It doesn't decompile. If you want source code back, `luad` tells you exactly which
profile the chunk uses, so you can give it to a decompiler that reads that profile.

## Status: 0.4.1, experimental

This is an early release of a tool built for fun. It works and gives real answers on
real firmware, but no Lua version is officially supported yet, and you shouldn't base
security conclusions on it alone. For Lua 5.2, 5.3 and 5.5 it reads file structure and
validates it, but refuses the deeper analysis. Please file issues.

Work happens in small reviewed batches (see the
[development workflow](docs/DEVELOPMENT-WORKFLOW.md)), and support or compatibility
promises need their own qualification. Being experimental doesn't loosen the rules in
[`AGENTS.md`](AGENTS.md). Passing CI proves only what the tests assert, and a public
counterexample gets fixed before new features get added.

[Limitations](#limitations) lists what doesn't work yet.

## What it does

Every command below runs on a test file in this repository, so you can reproduce it
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

Look at the `Layout` line. This chunk is an OpenWrt-style build with a 32-bit `size_t`
and an integer-based number format. Stock desktop Lua never produces that, and tools
built on the stock loader either refuse it or misread it. The command goes on to print
the full header and a summary of each function; the overview above is just the first
block.

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

Constants are shown where they're used. Add `--raw` to see the encoded instruction
words and `--effects` to see what each instruction does.

Most of this is also available as JSON and JSONL with published schemas, so your
scripts don't have to parse text. Which formats each command supports is listed under
[machine interface](#machine-interface).

## Install

Each [GitHub release](https://github.com/dweekly/luad/releases) has prebuilt archives
for `linux-x86_64` and `macos-aarch64`. Download one, check its checksum, and extract it.

From source, with a Rust 1.85 or newer toolchain:

```console
git clone https://github.com/dweekly/luad.git
cd luad
cargo install --path crates/luad-cli --locked
```

That builds from source. luad isn't published on crates.io, so `cargo install luad`
won't work.

If you're contributing and need the full toolchain, the official Lua compilers and the
fuzz suite, follow [docs/BRINGUP.md](docs/BRINGUP.md) instead.

## Commands

```console
luad inspect chunk.luac                     # identify format and summarize
luad disasm chunk.luac --raw --effects      # faithful listing with byte provenance
luad validate chunk.luac --strict           # structural and VM-invariant checks
luad explain chunk.luac 'proto:0:pc:3'      # explain one field or instruction
luad export firmware/*.lua --format jsonl   # deterministic batch export
luad diagnostics L51-REG-SPAN-001           # look up a diagnostic code
```

Also available, and more experimental still: `cfg`, `callees`, `callgraph`, `callers`,
`origins`, `xrefs`, `query` and `diff`. Their output is useful, but its format and
meaning may change without notice. `callees`, `callgraph`, `callers` and `origins` only
work on Lua 5.1 for now, and say so if you give them anything else. `callers` lists the
direct callers it finds for one function across a set of files, with where each
argument came from and how much of each file it covered. An empty list doesn't prove
nothing calls the function.

Not every command supports every output format:

| Command | `text` | `json` | `jsonl` |
|---|:--:|:--:|:--:|
| `inspect`, `disasm`, `explain` | yes | yes | yes |
| `cfg`, `xrefs`, `query`, `diff` | yes | yes | yes |
| `validate` | yes | yes | no |
| `diagnostics` | yes | yes | no |
| `export` | no | no | **jsonl only** |

`export` is the batch interface and only writes JSONL, one record per line.

The repository includes precompiled test files, so you can try it without a Lua
compiler:

```console
cargo run -q -p luad-cli -- inspect tests/fixtures/precompiled/lua54/hello.luac
```

`luad` treats bytecode as data. It never runs an external compiler and never runs the
chunk.

## Firmware investigation walkthrough

A four-step investigation you can reproduce, using the small fake firmware tree in
`tests/fixtures/firmware_tree/`:

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

[docs/examples/RECIPES.md](docs/examples/RECIPES.md#13-reproducible-firmware-investigation-walkthrough)
has the full recipe, plus an optional decompiler experiment. You don't need a
decompiler to build or test luad; the walkthrough checks luad's own answers and the
cases where it refuses.

## Limitations

What the current code reads:

| Dialect | Opcodes | Tier | State |
|---|---:|---|---|
| `lua5.1` | 38 | Experimental | Best tested. Reads both the LNUM32 firmware profile and stock layouts. |
| `lua5.2` | 40 | Experimental | File structure through inspect and export, plus an unchecked text listing. No structured disassembly, effects, explain or analysis. |
| `lua5.3` | 47 | Experimental | File structure through inspect and export, plus an unchecked text listing. No EdgeTX profile, structured disassembly, effects or explain. |
| `lua5.4` | 83 | Experimental | Reads well. Disassembly is checked against official Lua 5.4.8. |
| `lua5.5` | 85 | Experimental | File structure through inspect and export, plus an unchecked text listing. No structured disassembly, effects, explain or analysis. |

LuaJIT and Luau use different bytecode formats, and luad doesn't read them.
`luad capabilities` doesn't list them at all.

Nothing is in the `supported` tier yet, and `luad capabilities` says so. Experimental
means the code is there and gives useful answers, not that its correctness has been
formally checked.

`diff` compares decoded content position by position: constant bytes and number
formats, the shape of each function, capture descriptors, headers and layouts, and the
raw instruction words. `--semantic` adds decoded instruction fields and what role each
word plays, and still compares unused bits and companion words. `--ignore debug` skips
names, line numbers and local scopes. "Equal" means nothing it compared changed. It
doesn't mean the two chunks behave the same, or that their bytes match; compare the
file hashes for that. See the
[machine interface](docs/MACHINE-INTERFACE.md#cfg-xrefs-query-and-diff) and
[public comparison regressions](crates/luad-oracle/tests/test_diff_cli.rs).

Linking calls across files only happens when you ask for it with
`--link-convention luci-module-setglobal`. That convention accepts a module only if its
top level runs straight through, with one `module("name")` declaration and plain
function definitions. It uses each function's final assignment, refuses modules whose
setup it can't follow or that overwrite functions, and won't name a single target when
its index is incomplete. A link means "this is what the convention says," not that the
call happens at run time. The
[exact accepted shapes, statuses and limits](docs/MACHINE-INTERFACE.md#export) and the
[tests behind them](crates/luad-oracle/tests/test_cross_chunk_linking.rs) have details.

`--link-convention luci-module-trusted-init` also accepts modules whose top level runs
other code first, such as `require` calls. It does that by making an assumption
instead of checking, and every answer that depends on the assumption carries
`assumptions: ["trusted-init"]`. The
[machine interface](docs/MACHINE-INTERFACE.md#luci-module-trusted-init-opt-in-assumption-labeled)
spells out the assumption.

The callee and argument-origin analysis throws away a call frame's temporary values
before it keeps a call's results. It also refuses to use a captured value that might be
stale across overlapping calls, or a generic `for` loop's control variables. Ordinary
live locals, new definitions and the results of literal `require` calls keep their
facts. The [call-frame tests](crates/luad-oracle/tests/test_symbolic_callees_lua51.rs)
show the cases. All of these are static facts that hold only under the normal Lua VM
calling rules and luad's assumptions about name lookup. Changes made from C, through
reflection or the debug library, and anything a metamethod might do, aren't covered.
Capture analysis can also get less precise after a closed-over variable's register is
reused. None of these records promise that a call actually happens at run time.

In JSON output, finite floats are JSON numbers, and the other values are the strings
`nan`, `inf` and `-inf`. The raw bits from the file are kept separately, including any
NaN payload; the decoded value doesn't promise a NaN's payload or sign. Finite values
round-trip exactly. The check numbers in Lua 5.3 to 5.5 headers must match exactly.
[Machine float semantics](docs/MACHINE-INTERFACE.md#floating-values) has the details.

For Lua 5.2, 5.3 and 5.5, `inspect` and `export --facts prototype,constant,upvalue`
give you the raw instruction words and how functions nest. You can get an unchecked
text listing as long as you leave off `--effects`; structured disassembly, instruction
effects and `explain` refuse these versions. A plain `export` includes instruction
facts, so it reports these files as failed; asking for an unavailable fact type fails
before any output. When sorting files from mixed Lua versions, use the `--facts` list
above. The analysis commands refuse these versions outright.

Regression tests cover the fixes made through 0.4.1 to layout handling, operands, which
files get analyzed, caller attribution and malformed input. They don't prove every instruction is
interpreted correctly or that every vendor layout works. The
[changelog](CHANGELOG.md#041--2026-10-28) has release details.

`luad` also doesn't extract firmware, decompile, rebuild source, judge whether
something is exploitable, or keep notes between runs. Other tools do those jobs, and
[the roadmap](ROADMAP.md) suggests which.

"Valid" from `luad validate` means the file fits the selected format and passes the
listed checks. It doesn't mean the chunk is safe to run, or tell you who made it.

## Machine interface

Ask luad what it supports instead of parsing its human-readable output:

```console
luad capabilities --format json
luad diagnostics --format json
luad schema capabilities
luad schema chunk
```

If you're writing code against luad, read
[docs/MACHINE-INTERFACE.md](docs/MACHINE-INTERFACE.md) for exit codes, which IDs stay
stable and across what, what happens when output is cut short, and what goes to stdout versus stderr.
Schemas have version numbers, but as of 0.4.1 none of them is promised to stay
compatible.

[docs/examples/RECIPES.md](docs/examples/RECIPES.md) has recipes for combining
commands.

## How `luad` compares on non-stock chunks

[docs/PRIOR-ART-AND-CORPORA.md](docs/PRIOR-ART-AND-CORPORA.md) keeps comparisons we
actually ran, with dates, separate from what we read in other projects' source and
docs. Rizin's development branch handles OpenWrt and TP-Link chunks, and unluac-rs
offers a Rust library, a CLI and a browser workspace. Whether a tool handles a given
profile, and which gets the right answer, can only be settled by running a specific
task with pinned versions. `luad` has no EdgeTX profile.

Before luad is announced, even as experimental, the [roadmap](ROADMAP.md) calls for
public workflows that are actually useful, plus trials by outside users. What luad
offers is the combination: reading the format exactly, pointing at the bytes, saying
plainly when it isn't sure, and output a program can rely on. That stays true even as
other tools improve.

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
| [`CHANGELOG.md`](CHANGELOG.md) | Backward-facing record of released and unreleased user-visible changes. | 2026-10-23 | Every user-visible change or release; never use it as a forward plan. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor verification commands, test taxonomy, fixture provenance, and definition of done. | 2026-10-22 | Toolchain, test commands, gates, fixture policy, or contribution workflow changes. |
| [`PRD.md`](PRD.md) | Community and firmware users, factual-composition requirements, scope, and release outcomes. | 2026-10-22 | Target users, workflows, factual boundary, prior-art claims, or product requirements change. |
| [`ROADMAP.md`](ROADMAP.md) | Ordered outcomes for reliable answers, the firmware consumer, public workflows, outside utility trials, announcement, and stabilization. | 2026-10-23 | A milestone closes, user evidence changes priorities, or scope, dependencies, release boundaries, or stop conditions change. |
| [`SECURITY.md`](SECURITY.md) | Supported-version policy, the planned 1.0 target matrix, vulnerability reporting, and hostile-input threat model. | 2026-09-16 | Support policy, the planned target matrix, reporting channel, trust boundary, or threat model changes. |
| [`docs/ROADMAP-1.0.md`](docs/ROADMAP-1.0.md) | Stable-release qualification obligations, exact targets, minimal machine contract, hostile-input evidence, and transfer. | 2026-10-22 | The stable target set, qualified surface, acceptance obligations, or qualification lifecycle changes. |
| [`docs/BRINGUP.md`](docs/BRINGUP.md) | Setup for a developer machine, a self-hosted Actions runner, and a release builder, with the owning file for every tool pin. | 2026-10-22 | A tool pin, its owning file, the doctor's checks, runner prerequisites, labels or security boundary, or the release dry-run and rehearsal entry points change. |
| [`docs/DEVELOPMENT-WORKFLOW.md`](docs/DEVELOPMENT-WORKFLOW.md) | Customer-outcome batches, evidence-based selection, proportional verification, qualification lanes, and orchestration. | 2026-10-22 | Selection criteria, planning ownership, CI lanes, roles, evidence policy, or sprint mechanics change. |
| [`docs/NEXT-SPRINT.md`](docs/NEXT-SPRINT.md) | Contract for the opt-in `luci-module-trusted-init` link convention: its assumption, transfer rules, gates and design-review history. | 2026-10-27 | The convention merges and a new bounded contract replaces it, or the assumption changes. |
| [`docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md`](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md) | Present factual-tool requirements derived from the TP-Link/OpenWrt reverse-engineering use case. | 2026-10-20 | New corpus evidence changes target authority, fact boundaries, or workflows, or all unique requirements move into the PRD. |
| [`docs/TRIALS.md`](docs/TRIALS.md) | Outside-trial kit: participant roles, inputs to hand over, pre-registered questions with hashed answer keys, and what to record. | 2026-10-23 | A trial is run, the trial inputs or questions change, or roadmap D closes. |
| [`docs/PRIOR-ART-AND-CORPORA.md`](docs/PRIOR-ART-AND-CORPORA.md) | Dated executed comparisons and source observations, corpus candidates, provenance, and research leads. | 2026-10-23 | A comparison is executed, a cited project/profile changes, or a candidate corpus is selected; source checks do not refresh older experiments. |
| [`docs/MACHINE-INTERFACE.md`](docs/MACHINE-INTERFACE.md) | Machine formats, identities, schemas, limits, completion, current analysis caveats, and exit behavior. | 2026-10-23 | Public commands, schemas, known limitations, identities, diagnostics, or completion/exit contracts change. |
| [`docs/RELEASING.md`](docs/RELEASING.md) | Release policy for 0.x and 1.0, exact-target order, qualification checklist, packaging, publication, and rollback. | 2026-09-17 | Release targets, qualification lifecycle, package platforms, artifact channel, compatibility, signing/checksum policy, ownership, or rollback changes. |
| [`docs/LUA51-LNUM32-CANDIDATE.md`](docs/LUA51-LNUM32-CANDIDATE.md) | Archived verification and firmware-handoff guide for the immutable, non-promoting Lua 5.1 LNUM32 RC1 artifact. | 2026-08-27 | RC1 evidence is retired, its retained artifacts become unverifiable, or a new LNUM32 candidate guide replaces it. |
| [`examples/export_reader/README.md`](examples/export_reader/README.md) | Bounded capture and schema/context/completion verification before consuming corpus facts. | 2026-10-23 | Reader behavior, bundle format, dependencies, limits, verified profiles, or commands change. |
| [`tests/corpus/luci-23.05/NOTICE.md`](tests/corpus/luci-23.05/NOTICE.md) | Provenance, license and per-file SHA-256 of the unmodified LuCI subset used for source-checked caller answers. | 2026-10-23 | A vendored file, the upstream commit or the license changes, or the corpus is retired. |
| [`tests/corpus/luci-22.03/NOTICE.md`](tests/corpus/luci-22.03/NOTICE.md) | Provenance, license and SHA-256 of the unmodified LuCI 22.03 `util.lua` used to test release comparison. | 2026-10-23 | The vendored file, its upstream commit or the license changes, or the comparison corpus is retired. |
| [`docs/examples/RECIPES.md`](docs/examples/RECIPES.md) | Practical command-line and composition recipes for consuming machine JSON and JSONL output. | 2026-10-23 | Machine interface envelopes, export records, CLI subcommands, or external handoff guidance change. |
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
