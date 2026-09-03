# Prior art and corpus sources

This document records which external tools, datasets, and bytecode-emitting ecosystems
have been evaluated against `luad`'s scope, what each one means for the project, and
where new kinds of `.luac` files can be obtained with clean provenance. It exists so
that nobody re-evaluates a dismissed tool from scratch or vendors a sample whose
license or origin would poison the fixture tree.

Read it when choosing the next fixture corpus, the next vendor profile, or the next
prior-art row in `PRD.md` §1.3. Every row cites a URL. A row marked *unverified* records
what a source claims, not what this repository has reproduced; promote it only after
reproducing it. The "fresh as of" date in the `README.md` index is the date these
claims were last checked against the live URLs.

## 1. Surveyed projects and verdicts

| Project | What it is | Ships `.luac`? | Verdict for `luad` |
|---|---|---|---|
| [bartholomort/lua-obfuscator-corpus](https://huggingface.co/datasets/bartholomort/lua-obfuscator-corpus) (Hugging Face; there is no GitHub repository of that name) | 26,357 obfuscated Lua/Luau **source** files across 16 obfuscator families with per-version and per-preset labels, plus 1,244 unobfuscated baselines. CC BY-SA 4.0, gated, "research purposes only". | No. Extension census of the full file manifest: 26,275 `.lua`, 82 `.luau`, zero `.luac`. | **Influence, do not vendor.** Useful as a compile-then-analyze benchmark for CFG and dominator behaviour under control-flow flattening, with a monotonic preset-difficulty axis (Weak/Medium/Strong, Minimal/Default/Maximum). The share-alike license and the unclear copyright of "decompiled Roblox scripts" keep it out of this tree. Regenerate labeled samples instead with [Prometheus](https://github.com/prometheus-lua/Prometheus) over this repository's own MIT sources. |
| [EdgeTX/edgetx-sdcard](https://github.com/EdgeTX/edgetx-sdcard) | SD-card contents for EdgeTX radio firmware: 379 `.lua` scripts, no repository-level license (spot-checked files carry "Copyright (C) EdgeTX, License GPLv2" headers; others carry none). | No `.luac` in the repository. The **radio** compiles these scripts to `.luac` on the SD card, and upstream EdgeTX ships a host compiler for the same dialect (section 4). | **New corpus source, and a fidelity gap.** EdgeTX bytecode is a 32-bit Lua 5.3 dialect with a 4-byte `lua_Number` and a non-standard header slot. `luad` accepts the header today and then fails inside the body with a misleading diagnostic (section 5). |

## 2. Prior art the PRD table does not cover

`PRD.md` §1.3 lists twelve tools. The entries below are absent from that table or are
described there in a way that no longer matches the tool. "Competitor" means the tool
produces facts that overlap `luad`'s output; "consumer" means it needs such facts and
currently derives them itself.

### Reverse-engineering platforms with native Lua bytecode support

- [rizin](https://github.com/rizinorg/rizin) (LGPL-3.0, active): a first-class `luac`
  architecture with per-version ISA tables under `librz/arch/isa/luac/{v50,v51,v52,v53,v54,v55,luajit}`,
  a `bin_luac` loader, and rizin's own CFG, xref, and graph machinery. **Competitor.**
  The PRD's "radare2 Lua support" row understates this; rizin, not radare2, is the
  platform to differentiate against. `luad`'s distinct ground is memory safety,
  embedded and vendor layouts, hostile-input bounds, and machine-readable diff and
  query facts rather than an interactive session.
- [Cerbero Suite `Pkg.LUAC`](https://sdk.cerbero.io/latest/Pkg.LUAC.html) (commercial):
  parses Lua 5.0 through 5.4 with version-specific opcode sets and exposes the prototype
  tree and debug metadata. Competitor, closed source.
- Ghidra, IDA Pro, and Binary Ninja: no PUC-Rio Lua bytecode processor or loader was
  found for any of them (Binary Ninja has [Binja-Luau](https://github.com/Rerumu/Binja-Luau),
  Luau only). This is a negative search result, not proof of absence. If it holds,
  `luad`'s disassembly, CFG, and xref output is one exporter away from being the backend
  for such a processor.

### Rust neighbours

- [x3zvawq/unluac-rs](https://github.com/x3zvawq/unluac-rs) (MIT, pushed 2026-08-31):
  multi-dialect decompilation library. The PRD calls it "testing-stage"; it is actively
  maintained and MIT-licensed, which makes it the one neighbour whose code could be
  reused. Competitor for parsing, consumer for facts.
- [metaworm/luac-parser-rs](https://github.com/metaworm/luac-parser-rs) (no license
  file): parses 5.1 through 5.4, LuaJIT, and Luau; custom parsers compile to WASM and are
  hot-loaded by a hosted decompiler to handle unofficial dialects. The plugin-parser
  idea is the relevant design precedent for vendor profiles. Unlicensed, so reference
  only.
- [shrimp-nz/medal](https://github.com/shrimp-nz/medal) (MIT, dormant since 2024): Rust
  lifter with SSA and control-flow restructuring. Reference for structuring, consumer
  for facts.
- [Coldzer0/LuaDecompiler](https://github.com/Coldzer0/LuaDecompiler) (Pascal, AGPL-3.0,
  active): the only other public tool claiming Lua 5.5 alongside 5.1 through 5.4.
  Competitor; AGPL means reference only.

### The `luadec` lineage and its reusable ideas

[viruscamp/luadec](https://github.com/viruscamp/luadec) (no license file, last commit
2017) descends from Hisham Muhammad's LuaDec via
[sztupy/luadec51](https://github.com/sztupy/luadec51), vendors ChunkSpy and
[LuaAssemblyTools](https://github.com/mlnlover11/LuaAssemblyTools) as submodules, and
borrows unluac's regression test names. Firmware forks exist for
[OpenWrt](https://github.com/HandsomeYingyan/luadec-openwrt),
[TP-Link](https://github.com/superkhung/luadec-tplink), and
[Pgy routers](https://github.com/H4lo/luadec-for-pgy). Three ideas transfer to a
fact-extractor; the decompiler itself does not:

- `luaopswap -gs/-gf` derives a modified VM's opcode permutation by comparing a
  compiled "every opcode" canary against a reference chunk, then rewrites the input into
  standard opcode order. As a `luad` fact this is an opcode-map profile with recorded
  provenance, never a silent guess.
- `compare/luadecguess.rb` scores recompile-and-compare fitness on a graded ladder (all
  opcodes identical, 75%, 50%, "at least loads"). The same ladder shape suits a
  differential round-trip gate.
- `test/unluac-test/` enumerates one micro-case per construct (`adjust01..05`,
  `booleanassign01..10`, `combinebexpression01..04`). A systematically enumerated
  micro-corpus is a better skeleton for CFG and dominator goldens than topical files.

The unlicensed real-world chunks under `test-compiled/` (game and client binaries with
`.lua` extensions) must not be vendored.

### Explicit remapping facilities in other tools

- [unluac (Jeong-Min-Cho fork)](https://github.com/Jeong-Min-Cho/unluac) documents
  `--opmap <file>` for VMs with shuffled opcodes and `--typemap` for modified
  [xLua](https://github.com/Tencent/xLua) builds found in shipped Unity games, which
  keep the opcode table but swap the integer and float constant type tags. Tencent's
  checked-in xLua sources use the stock tags, so the swap comes from a game-side
  modification with no public compiler. Both flags are the kind of dialect knob `luad`
  must express as an explicit, provenance-bound profile.
- [Unshuffling TP-Link's Lua opcodes](https://jhalon.github.io/side-channel/tplink-opcode-shuffle/)
  documents an Archer AX1800 V5.6 build whose `lopcodes.h` enum, `BinOpr`, and `UnOpr`
  were reordered, recovered by diffing the vendor GPL drop against stock 5.1. The same
  vendor family as this repository's private corpus ships differently shuffled tables
  across models.
- [PopLua-Disassembler](https://github.com/wxarmstrong/PopLua-Disassembler) (PopCap's
  custom Lua with extra opcodes) and Playdate (section 4) are two more independent
  confirmations that the opcode table is not fixed in the field.

### Bytecode-level obfuscation, deobfuscation, and the academic neighbour

- Luo et al., ["Reverse Engineering of Obfuscated Lua Bytecode via Interpreter Semantics Testing"](https://doi.org/10.1109/TIFS.2023.3289254),
  IEEE TIFS 18 (2023); open-access copy at [NSF-PAR](https://par.nsf.gov/servlets/purl/10540556). IoT malware ships Lua in customized bytecode dialects; the paper
  recovers unknown opcode semantics by mutation testing against a reference
  interpreter. Tool at [hayden-droid/Dev](https://github.com/hayden-droid/Dev) (GPL-3.0),
  no samples shipped. Closest academic neighbour to an opcode-map facility.
- [danielkasprzak/Lua-Bytecode-Deobfuscator](https://github.com/danielkasprzak/Lua-Bytecode-Deobfuscator)
  is the rare bytecode-level deobfuscator; the IronBrew2, MoonSec, and Prometheus
  devirtualizers ([Gork3m/IronBrew2-Deobfuscator](https://github.com/Gork3m/IronBrew2-Deobfuscator),
  [tupsutumppu/MoonsecDeobfuscator](https://github.com/tupsutumppu/MoonsecDeobfuscator),
  [0x251/Prometheus-Deobfuscator](https://github.com/0x251/Prometheus-Deobfuscator))
  each hand-roll their own VM-dispatch recovery. Consumers of `luad`-shaped facts.
- Roblox and FiveM "Lua obfuscators" (Zenfus, Opiens, Zartha, LuaObfuscator "VM"
  preset, Ironbrew) take `source → luac → deserialize → transform → emit Lua source
  containing a custom VM plus encoded bytecode`. Their output is text, so they are not
  `.luac` sources, but their intermediate transform catalogue (constant encryption,
  dead-instruction injection, super-operator fusion) is the list a chunk mutator would
  implement.

### Corpus-generation pattern

[ClaudiuGeorgiu/Obfuscapk](https://github.com/ClaudiuGeorgiu/Obfuscapk) (MIT; paper in
[SoftwareX 11:100403](https://doi.org/10.1016/j.softx.2020.100403)) has no Lua content.
Its contribution is a registry of independently addable, composable transforms that emit
a labeled corpus on demand, so a detector can be measured against known ground truth. The
Lua-bytecode mirror is a chunk mutator (reorder constants, insert dead slots, strip or
restore debug info, permute the opcode table via a map, swap constant type tags, re-emit
under a different layout, wrap in XXTEA) that writes a ground-truth manifest beside each
output, giving regression tests whose expected CFG, dominators, and xrefs are known by
construction. Existing chunk writers that can serve as the mutator's back end:
[ChunkSpy](https://github.com/viruscamp/luadec/tree/master/ChunkSpy) ("write out a
binary chunk to a custom profile"), LuaAssemblyTools (5.1 and 5.2 assembler; ships
`samples/consteval_test.luac` and `etc/StackSteal.luac`), and NodeMCU's retargetable
dumper (section 4).

### Format specifications and editor templates

- [ImHex-Patterns](https://github.com/WerWolv/ImHex-Patterns/tree/master/patterns)
  (GPL-2.0): `lua40`, `lua50`, `lua51`, `lua52`, `lua53`, `lua54` patterns; the 5.4
  pattern implements the LEB128 size decoder. No 5.5 pattern.
- 010 Editor [`Luac.bt`](https://www.sweetscape.com/010editor/repository/templates/file_info.php?file=Luac.bt&type=0):
  Lua 5.2 only; companion `LuaJIT.bt` for LuaJIT 2.0.5.
- [Kaitai Struct format gallery](https://formats.kaitai.io/): **no Lua bytecode spec**
  (it has `python_pyc_27`, `java_class`, `dex`). A `luac.ksy` derived from `luad`'s
  structural model would fill a visible gap.
- [luac.nl](https://www.luac.nl/simple/about.html): web compiler for every official Lua
  version including 4.0-era releases, with listing output. No stated license or terms;
  usable as a cross-check for exotic versions, not as a fixture source.

### Loader fuzzing

- OSS-Fuzz [`projects/lua/fuzz_lua.c`](https://github.com/google/oss-fuzz/tree/master/projects/lua)
  loads with mode `"t"` (text only) and never reaches `luaU_undump`.
- [ligurio/lunapark](https://github.com/ligurio/lunapark) (ISC, active; cloned by the
  OSS-Fuzz Dockerfile) reaches the PUC-Rio loader through `luaL_loadbufferx_test.c` with
  mode `"bt"` on PUC Lua and `"t"` on LuaJIT because LuaJIT's reader asserts on
  malformed input. Its corpus, [lunapark-corpus](https://github.com/ligurio/lunapark-corpus)
  (~4.6 GB, no license file), is curated as Lua source; whether any seed carries the
  `\x1bLua` magic is unverified.
- [luzer](https://github.com/ligurio/luzer) (ISC) fuzzes Lua code, not the chunk loader.
- No published corpus of malformed binary chunks was found. A `luad` seed set of
  hostile chunks (magic, version, width, byte-order, and LNUM32 variants; truncations;
  oversized counts; recursion bombs; jump-past-end) would be a new public artifact with
  a direct upstream path into lunapark-corpus.

### Security posture of the loader, as stated by the runtimes

- [Lua 5.4 manual §6.1, `load`](https://www.lua.org/manual/5.4/manual.html): "It is
  safe to load malformed binary chunks; `load` signals an appropriate error. However,
  Lua does not check the consistency of the code inside binary chunks; running
  maliciously crafted bytecode can crash the interpreter." `luad` validates exactly what
  upstream declines to validate.
- Samuel Groß, ["Pwning Lua through `load`"](https://saelo.github.io/posts/pwning-lua-through-load.html):
  remote code execution from crafted bytecode via out-of-range constant indices.
- ["Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws"](https://memorycorruption.net/posts/rce-lua-factorio/)
  (2024): a hand-written bytecode verifier missed that `JMP` targets are offset by one,
  so bytecode placed in the constant pool became reachable. The vendor's response was to
  disable bytecode loading. The best available case study of a verifier of `luad`'s
  class failing.
- [Luau sandbox documentation](https://luau.org/sandbox/) and
  [SECURITY.md](https://github.com/luau-lang/luau/blob/master/SECURITY.md): bytecode not
  produced by the Luau compiler is unsupported and carries no guarantees.
- Post-2011 CVEs found against Lua (`CVE-2022-28805`, `CVE-2022-33099`) are parser and
  runtime defects, not `lundump.c` defects. No CVE specifically against the chunk loader
  was found, consistent with upstream treating bytecode as trusted input.

### PRD §1.3 rows that need revision

The PRD is not edited by this document. A later change should:

- replace the radare2 row with rizin and its per-version `luac` ISA tables;
- restate unluac-rs as active and MIT-licensed;
- add Coldzer0/LuaDecompiler as the other public 5.5 claimant;
- add metaworm/luac-parser-rs's WASM plugin-parser design as the precedent for vendor
  profiles, with its missing license noted.

## 3. Existing bytecode datasets

No public, licensed dataset of compiled Lua bytecode was found. Hugging Face (datasets
search for `lua` and `bytecode`), Zenodo (`"lua bytecode"` returns one record, a C-Lua
firmware taint-analysis artifact), and Kaggle (web search only) return nothing; a
systematic GitHub sweep for repositories holding many `.luac` files could not be
completed because code search does not index binary extensions well, so that negative is
partial. [Roblox/luau_corpus](https://huggingface.co/datasets/Roblox/luau_corpus) is
Luau source.

A provenance-tracked `.luac` corpus spanning Lua 5.1 through 5.5 plus LNUM32, generated
from MIT and Apache sources by pinned compilers, would be the first of its kind
published.

## 4. Candidate `.luac` sources

Ordered by how cheaply a clean, reproducible fixture can be obtained. "Verified" means
the bytecode-emitting behaviour was confirmed from source or by running it; "unverified"
means a secondary source asserts it.

### 4a. Stock dialects from permissively licensed source

| Source | License | Size | Why it stresses a bytecode analyzer |
|---|---|---|---|
| [Official Lua test suites](https://www.lua.org/tests/) (`lua5.1-tests.tar.gz`, `lua-5.2.0` through `lua-5.5.1-tests.tar.gz`) | "All files are distributed under this license" (Lua MIT); SHA-256 published per tarball | 55 to 150 KB per release, ~40 files each | Per-release packaging means each suite compiles under its own `luac` with no version drift. `verybig.lua` exceeds instruction and constant limits, `code.lua` asserts on generated opcode sequences, `goto.lua` (5.2+) is a jump-density torture, `locals.lua` (5.4+) exercises `<const>` and `<close>`, `coroutine.lua` nests closures deeply. |
| [Kong](https://github.com/Kong/kong) | Apache-2.0 | ~1,300 `.lua` | Largest permissive real-world corpus; deep nesting and large prototypes. |
| [Penlight](https://github.com/lunarmodules/Penlight), [luasocket](https://github.com/lunarmodules/luasocket), [busted](https://github.com/lunarmodules/busted), [luacheck](https://github.com/lunarmodules/luacheck) | MIT | 64 to 135 `.lua` each | Idiomatic closure-heavy library code; luacheck carries large constant tables. |
| [luvit](https://github.com/luvit/luvit), [Neovim `runtime/lua`](https://github.com/neovim/neovim) | Apache-2.0 | 199 and 163 `.lua` | Callback pyramids and dense upvalue graphs; large dispatch tables. |
| [Lapis](https://github.com/leafo/lapis) | MIT | 93 `.lua` | MoonScript-generated Lua has unusual codegen shapes. |

Excluded on license: awesome (GPL-2.0), Nmap NSE scripts (NPSL), Wireshark dissectors
(GPL-2.0). Needs per-file triage before use: tarantool, softdevteam/lua_benchmarking,
moonscript, argparse.

### 4b. Vendor dialects reproducible with a public first-party compiler

| Ecosystem | Dialect and layout | Emits bytecode | Obtain | Why it is a new kind |
|---|---|---|---|---|
| **EdgeTX ≥ 2.11** ([edgetx](https://github.com/EdgeTX/edgetx), GPLv2) | Lua 5.3.6 (NodeMCU-derived tree), `LUA_32BITS` unconditional in `radio/src/thirdparty/Lua/src/luaconf.h`: `lua_Integer` = int32, `lua_Number` = float32; `ldump.c` writes `sizeof(int)` into the `size_t` header slot ("for radio compatability"); debug info stripped unless the load mode contains `d` | **Verified by build and run** (section 5). On-radio `luaU_dump` in `radio/src/lua/interface.cpp`; `LUA_COMPILER` defaults ON | `cmake -S radio/src/thirdparty/Lua -B build-luac && cmake --build build-luac` yields `edgetx-luac`; a WASM build script exists | 4-byte `lua_Number` in 5.3; header slot that does not describe the body; a header-versus-body width inconsistency for long strings |
| **EdgeTX ≤ 2.10.6** | Lua 5.2.2, stock header with endianness byte and integral flag; `size_t` = 4 and `lua_Number` = 8 on the ARM target | Verified from source (same compiler path; stock 5.2 `ldump`); not built here | Same repository at tag `v2.10.6` | Still deployed; a `(5.2, LE, 4,4,4,8, integral 0)` tuple a desktop `luac5.2` never emits |
| **OpenTX** ([opentx](https://github.com/opentx/opentx), GPLv2) | Lua 5.2.2, `LUA_NUMBER double`, `LUA_INTEGER int`, unpatched `ldump`/`lundump` | Verified from source; not built here | Build from source | Same tuple as the row above, from the predecessor firmware |
| **NodeMCU** ([nodemcu-firmware](https://github.com/nodemcu/nodemcu-firmware), MIT) | Lua 5.1 with optional `LUA_NUMBER_INTEGRAL`; Lua 5.3 branch with `LUA_32BITS`; `app/lua/ldump.c` has `luaU_dump_crosscompile` with a `DumpTargetInfo{little_endian, sizeof_int, sizeof_strsize_t, sizeof_lua_Number, lua_Number_integral, is_arm_fpa}` | Verified from source; not built here | Build `luac.cross` | **A retargetable dumper under MIT.** It emits the stock integral-number layout that this repository's pinned compilers cannot, plus byte-swapped and ARM-FPA mixed-endian doubles. LFS images (`luac.cross -f`/`-a`) are a multi-prototype flash container, not a chunk. |
| **Playdate** (Panic) | Lua 5.4.3 with `LUA_32BITS`, three appended opcodes (`OP_LOADFALSE`, `OP_LFALSESKIP`, `OP_LOADTRUE`), non-standard version byte in SDKs before 1.8.0, per [playdate-reverse-engineering](https://github.com/cranksters/playdate-reverse-engineering/blob/main/formats/luac.md) | Unverified here (documented by a third party) | Free Playdate SDK `pdc`; `.pdz` container documented in the same repository | 32-bit Lua 5.4 with a non-standard opcode table and version byte |
| **TP-Link Archer AX1800 V5.6** | Lua 5.1 + OpenWrt patches + reordered opcode enum, `BinOpr`, `UnOpr` ([write-up](https://jhalon.github.io/side-channel/tplink-opcode-shuffle/)) | Unverified here (documented by a third party) | Vendor GPL drop at `static.tp-link.com/upload/gpl-code/2025/202510/20251021/GPL_AX1800v5.tar.gz` | A differently shuffled sibling of the private corpus, obtainable under GPL |
| **Modified xLua builds in shipped Unity games** | Lua 5.3 with integer and float constant tags swapped (unluac's `--typemap` example maps tag 3 to integer and tag 19 to float) | Unverified here; documented by [unluac's README](https://github.com/Jeong-Min-Cho/unluac/blob/main/README.md) against game-extracted chunks | **No public compiler identified.** Tencent's checked-in [xLua](https://github.com/Tencent/xLua) Lua 5.3.5 sources define the stock tags (`LUA_TNUMFLT` 3, `LUA_TNUMINT` 19) and dump them unchanged, so building upstream xLua does not reproduce the swap | Correct opcodes with wrong constant tags: plausible but wrong output if unhandled. Enters only if a reproducible authority is found |

### 4c. Containers around otherwise stock chunks

| Ecosystem | Container | Inner dialect | Notes |
|---|---|---|---|
| Solar2D / Corona ([engine](https://github.com/coronalabs/corona), MIT) | `resource.car` in APK assets; entries `.lu` | Lua 5.1 | Extractor: [corona-archiver](https://github.com/0BuRner/corona-archiver). Build a sample app rather than unpacking third-party titles. |
| Defold ([engine](https://github.com/defold/defold), Apache-2.0) | `.arcd` archives | Lua 5.1 or LuaJIT by platform | Extractor: [arcdEx](https://codeberg.org/cweiske/arcdEx). |
| NodeMCU LFS | flash overlay image | 5.1 / 5.3 | See 4b. |

### 4d. LuaJIT track

LuaJIT `-b` output (`ESC L J` magic, `BCDUMP_VERSION`, flags `BE`, `STRIP`, `FFI`;
[bcsave.lua](https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/jit/bcsave.lua)), Cocos2d-x
`luacompile -e -k KEY -b SIGN` XXTEA envelopes
([reference](https://github.com/xpol/lua-cocos2d-x-xxtea)), and OpenResty belong to the
LuaJIT product decision in `ROADMAP.md`, not to the stock matrix.
[luajit-decompiler-v2](https://github.com/marsinator358/luajit-decompiler-v2) is the
reference implementation to test against if that decision is taken.

### 4e. Hostile-chunk generators

LuaAssemblyTools (hand-written LASM: bad register indices, jumps past end, oversized
constant tables), ChunkSpy profile rewriting (arbitrary `(int, size_t, Instruction,
Number, endian, integral)` tuples from one source), and Prometheus over this
repository's own MIT sources (labeled control-flow flattening at three strengths).

### 4f. Do not source

- Malware samples. Cisco Talos's [LucidRook](https://blog.talosintelligence.com/new-lua-based-malware-lucidrook/)
  (2025) embeds Lua 5.4.8 and checks staged payloads for the `\x1bLua` magic, but the
  payload was published only as encrypted blobs; [Morphisec (2024)](https://www.morphisec.com/blog/threat-analysis-lua-malware/)
  documents delivery moving from compiled bytecode to obfuscated source; SentinelLabs's
  [LuaDream](https://www.sentinelone.com/labs/sandman-apt-a-mystery-group-targeting-telcos-with-a-luajit-toolkit/)
  is LuaJIT. These justify the memory-safety pitch; they do not justify a sample tier.
  Whether MalwareBazaar or VirusTotal expose a `luac` file type is unverified (both are
  auth-gated).
- Proprietary game bytecode (Angry Birds, PopCap, JX3, and the unlicensed blobs in
  viruscamp/luadec `test-compiled/`).
- The CC BY-SA obfuscator corpus (section 1).
- Luau bytecode. It shares no header with PUC Lua or LuaJIT (the first byte is the
  bytecode version; [Bytecode.h](https://github.com/luau-lang/luau/blob/master/Common/include/Luau/Bytecode.h)).
  `luad` does not read it and should say so in one sentence rather than treating it as
  a future row.

## 5. Spike: EdgeTX bytecode against today's `luad`

Performed 2026-09-02 on `aarch64-apple-darwin` (Apple clang, cmake 4.4.3) with
`luad 0.1.0` built from revision `881397b`. Inputs, outputs, and `SHA256SUMS` are
session artifacts, not fixtures; nothing below entered `tests/fixtures/`.

Provenance:

- EdgeTX `main` at `676721fe8f0213bb3ce33202f6acc3cb935ab473`; `edgetx-sdcard` `master`
  at `61e2d49e12e8cd531f0d4037e3d049a29b7c0bfa`.
- `cmake -S edgetx/radio/src/thirdparty/Lua -B build-luac && cmake --build build-luac`;
  the resulting `edgetx-luac -v` reports `Lua 5.3.6`.
- Inputs: this repository's `tests/fixtures/{hello,control_flow,closures,tables,numerics}.lua`
  (MIT), two sdcard scripts (`color/WIDGETS/CellsValues/main.lua`,
  `bw128x64/SCRIPTS/RGBLED/Bback.lua`), and a synthetic file with one 300-byte string
  literal. Each compiled with and without `-s`.

Observed header, every output (first 25 bytes):

```text
1b 4c 75 61  53 00  19 93 0d 0a 1a 0a  04 04 04 04 04  78 56 00 00  00 40 b9 43
signature    ver fmt LUAC_DATA         int st ins Int Num LUAC_INT   LUAC_NUM=370.5 f32
```

Stock `luac5.3` (5.3.6) on the same host and source for comparison:

```text
1b 4c 75 61  53 00  19 93 0d 0a 1a 0a  04 08 04 08 08  78 56 00 00 00 00 00 00  00 00 00 00 00 28 77 40
```

Long-string width skew, confirmed: in the stripped 300-byte-literal chunk, the string
constant is written as `ff` followed by an **8-byte** length `2d 01 00 00 00 00 00 00`
(301, Lua 5.3 stores length plus one) while the header slot claims 4. A chunk produced
by the desktop compiler or simulator therefore cannot be byte-compatible with one
produced on the 32-bit radio whenever a string literal reaches 255 bytes, and no field
in the header distinguishes the two.

`luad` today, on every EdgeTX output (`inspect --summary` and `validate --strict`, exit
code 1 in all cases):

```text
hello.luac            error: Parsing failed at offset 0: Upvalue count 131072 exceeds safety limit
hello.stripped.luac   error: Parsing failed at offset 157: Unexpected EOF: requested 4 bytes at offset 157, only 0 available
longstring.luac       error: Parsing failed at offset 0: Invalid constant tag 65
CellsValues/main.luac error: Parsing failed at offset 0: Invalid constant tag 61
```

The header is accepted (the 4-byte `lua_Number` and the 4-byte `size_t` slot raise no
diagnostic), the body is then read under stock widths, and the failure is reported at
offset 0 with a message that names a downstream symptom. The stock 5.3.6 chunk from the
same source reads cleanly with `Layout: int=4,sizet=8,inst=4,num=8,endian=1` and
`Verdict: ValidForParser`. Bounded behaviour held: no panic, no hang.

Width-byte probes on the repository's own stock fixtures (one header byte changed to
`04`, body left as compiled, so a desynchronised parse means the byte was honoured and
a clean parse reporting `8` means it was ignored):

| Dialect and byte | Result |
|---|---|
| 5.4 `lua_Number` (offset 14) | Rejected: `Parsing failed at offset 14: Unsupported lua_Number size: expected 8, found 4`. The header names the field and the width. |
| 5.5 `lua_Number` (offset 31) | Accepted at the header, test value consumed at the declared width, body fails with `Invalid constant tag 12` at offset 0 or an EOF at a body offset. No diagnostic names the width. |
| 5.3 `lua_Integer` (offset 15) or `lua_Number` (offset 16) | Accepted at the header, body fails with `Instruction count 4210944 exceeds safety limit` at offset 0. |
| 5.3 `size_t` (offset 13) | **Ignored**: reported `sizet=8`, `ValidForParser`, zero diagnostics. |
| 5.2 `lua_Number` (offset 10) | **Ignored**: reported `num=8`, `ValidForParser`, zero diagnostics on a chunk with float constants. |
| 5.2 `size_t` (offset 8) | Honoured: body desynchronises and fails with an EOF at a body offset. |

Header parsing code for reference: `crates/luad-dialect-lua54/src/header.rs` rejects
any `lua_Number` width other than 8; `crates/luad-dialect-lua53/src/header.rs` accepts
4 or 8 for `size_t`, `lua_Integer`, and `lua_Number`; `crates/luad-dialect-lua55/src/header.rs`
and `crates/luad-dialect-lua52/src/header.rs` read the width bytes without validating
them.

## 6. Gaps this survey exposes in `luad`

Stated as present constraints on the tool, each traceable to a source above.

- Lua 5.4 is the model: a header declaring a 4-byte `lua_Number` is refused with a
  diagnostic that names the field and the width. Lua 5.2 ignores the declared
  `lua_Number` width and Lua 5.3 ignores the declared `size_t` width, each reporting
  the stock width and a valid verdict with no diagnostic. Lua 5.3 and 5.5 accept 4-byte
  `lua_Integer` and `lua_Number` widths at the header and then fail inside the body.
  Every dialect must either honour a declared width end to end (`LUAC_NUM` checked as
  an f32, `0x43b94000`, and float constants decoded at 4 bytes) or refuse it the way
  5.4 does.
- A body parse failure caused by a layout mismatch is reported at offset 0 with the
  first downstream symptom. The diagnostic should name the header field that the body
  contradicts.
- A header whose declared `size_t` width disagrees with the width of a long-string
  length field is a detectable, reportable inconsistency (EdgeTX host builds). No
  diagnostic exists for it.
- Opcode-table permutation (TP-Link AX1800, Playdate, PopCap) and constant-type-tag
  remapping (modified xLua builds) have no profile representation. Both must be explicit,
  provenance-bound profiles; auto-guessing from a canary is a separate tool, never a
  default.
- No fact identifies the likely origin ecosystem of a chunk from its layout tuple,
  although `(5.3, 4,4,4,4,4)` and `(5.2, LE, 4,4,4,8, integral 0)` are near-unique
  signatures.
- `fuzz_lua51_analysis` and `fuzz_lua54_analysis` have no seed corpora, and no
  malformed-chunk seed set exists anywhere public.
- `tests/fixtures/precompiled/lua51_32bit/hello.luac` and
  `tests/fixtures/precompiled/lua51_lnum32/hello.luac` are absent from
  `tests/fixtures/precompiled/MANIFEST.json` while being referenced by many tests, and
  no pinned compiler in CI produces a stock 32-bit `size_t` chunk. `CONTRIBUTING.md`
  requires recorded provenance for every bundled `.luac`.
- The stock integral-number layout, which the active sprint evidences with hand-built
  chunks because the pinned compilers cannot emit it, has an MIT-licensed compiler
  authority available in NodeMCU's `luac.cross`.
- The redistributable corpus is five shared toy programs per stock dialect (debug and
  stripped) plus one Lua 5.1 validator-scale case; Lua 5.2 through 5.5 have no
  validator-scale coverage. The official per-release test suites remove that limit at
  no license cost.

## 7. Recommendations, stack-ranked

Each maps to an entry under "Post-version-1 research" in `ROADMAP.md`, except where
marked as a candidate for an earlier planning change.

1. **Generate the stock regression corpus from the official per-release test suites**,
   pinned by their published SHA-256 and compiled by the matching pinned `luac`, with
   `MANIFEST.json` provenance per `CONTRIBUTING.md`. Seed the two analysis fuzz targets
   from it.
2. **Adopt NodeMCU `luac.cross` as the compiler authority for the stock integral
   layout** and for byte-swapped 5.1 chunks. Candidate for a pre-1.0 planning change
   because it replaces hand-built evidence in an active sprint with an independent
   compiler.
3. **Bring Lua 5.2, 5.3, and 5.5 header-width handling up to the 5.4 model**: honour
   a declared width end to end or refuse it by name, and anchor layout-mismatch
   diagnostics to the contradicted header field. This is a silent
   incorrect answer of the kind the ROADMAP's sequencing rules put ahead of feature
   work.
4. **Qualify EdgeTX 5.3 32-bit as the first vendor profile after LNUM32**, with
   `edgetx-luac` as authority and sdcard scripts (GPLv2, recorded per case) plus this
   repository's MIT sources as inputs; add a header-versus-body width diagnostic.
5. **Express opcode maps and constant-type-tag maps as explicit profiles**, with the
   TP-Link AX1800 GPL drop as the first authority; a type-tag authority is still to be
   identified.
6. **Publish a hostile-chunk seed corpus** and offer it upstream to lunapark-corpus.
7. **Add a chunk mutator** that emits labeled variants with a ground-truth manifest,
   backed by ChunkSpy-style rewriting.
8. **Contribute a `luac.ksy` to Kaitai and a 5.5 ImHex pattern**, both derived from
   `luad`'s model.
9. **Revise PRD §1.3** per section 2.

## 8. Out of scope

Luau bytecode; automatic deobfuscation or devirtualization; vendoring any CC BY-SA,
proprietary, or malware-derived sample; obtaining malware samples; decompilation. These
remain governed by the non-goals in `PRD.md` §3.3 and the product boundaries in
`ROADMAP.md`.

## 9. Sources

Every URL above was fetched on 2026-09-02. Gated or auth-only endpoints
(the Hugging Face dataset files, MalwareBazaar's API, VirusTotal Intelligence) were not
read; claims about their contents come from their public metadata and are marked
accordingly.
