# `luad` roadmap

Status: future priorities after the experimental 0.2 release candidate.

Fresh as of: 2026-09-17.

## Release completion boundary

Publish only a clean, versioned revision with truthful release notes, passing Linux
x86-64 and macOS ARM64 CI, same-revision archives and source SBOM, and verified build
attestations. Consume accepted bytes without rebuilding. Require fresh-download checks
and the public walkthrough on both native platforms before declaring release complete.
Any failed required check blocks publication; corrected published bytes require a new
version rather than moving a version tag.

The [active sprint or checkpoint](docs/NEXT-SPRINT.md) controls implementation scope.
Choose the next researcher outcome separately after release verification. Keep all
dialects experimental until their named evidence gates authorize promotion. The
[1.0 program](docs/ROADMAP-1.0.md) does not gate an experimental 0.x release.
Implementation history belongs in [CHANGELOG.md](CHANGELOG.md) and Git history.

## Later

- Promote an exact target once one profile's evidence is complete end to end. See the
  [version 1 support boundary](#version-1-support-boundary) for which two, and
  [docs/ROADMAP-1.0.md](docs/ROADMAP-1.0.md) for what promotion requires.
- Freeze the machine interface. Today's schemas are versioned but carry no compatibility
  promise; a small external consumer should be able to depend on them through a 1.x line.
- EdgeTX Lua 5.3 32-bit, stock Lua 5.4.9, and vendor opcode-map profiles, each chosen by
  demonstrated need and a public compiler authority rather than for completeness.
- Partial-facts recovery, bounded value and call analysis, and a Rizin or Kaitai adapter,
  each needing a concrete consumer before it is worth building.

### Version 1 support boundary

If and when `luad` reaches 1.0, that release will promote exactly two independently
qualified targets, as defined by the canonical
[release boundary](docs/RELEASING.md#frozen-version-1-boundary):

1. OpenWrt-derived Lua 5.1.5 profile `lua5.1-lnum32` with
   `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4`;
2. stock PUC Lua 5.1.5 profile `lua5.1` with
   `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0`.

Passing one will not imply the other. Each profile, numeric representation, word size,
and byte order remains a separate claim, and no target inherits support from a nearby
layout. This is a future compatibility promise, not a present support claim: the
supported target set is empty today.

## Sequencing: breadth before integration

Expand layout and validation coverage using public compiler authority before embedding
luad facts in another tool. Select vendor profiles by demonstrated researcher need.
Qualify analysis for an exact dialect before exposing it to dependent integrations.
A silent incorrect answer takes priority over an adapter or integration feature.

## Out of scope

Firmware extraction, decompilation, source reconstruction, security policy,
exploitability judgment, target execution, and persistent research state stay outside
the core. LuaJIT and Luau are separate bytecode systems outside the product.

`luad` owns deterministic VM facts that competent analysts should agree on. Callers own
investigation-specific judgments: whether a callee is dangerous, whether a value is
attacker-controlled, whether a path is exploitable.

## Compose with the ecosystem

`luad` identifies the profile and gives you the bytes. These tools do the rest:

| Task | Reach for |
|---|---|
| Extract firmware containers | [Unblob](https://github.com/onekey-sec/unblob) or [Binwalk](https://github.com/ReFirmLabs/binwalk) |
| Recover readable Lua source | [unluac](https://sourceforge.net/projects/unluac/) or [unluac-rs](https://github.com/x3zvawq/unluac-rs), after checking the exact input profile |
| Work with explicit opcode/type maps | The [unluac fork's mapping conventions](https://github.com/Jeong-Min-Cho/unluac), without guessing a map |
| Interactive reverse engineering | [Rizin](https://github.com/rizinorg/rizin) |
| LuaJIT bytecode | [LuaJIT Decompiler v2](https://github.com/marsinator358/luajit-decompiler-v2) |
| Luau | [Luau's own tooling](https://github.com/luau-lang/luau) |

Keep comparisons dated and specific to the measured task; see
[docs/PRIOR-ART-AND-CORPORA.md](docs/PRIOR-ART-AND-CORPORA.md). Share minimized public
reproducers upstream. An upstream project fixing a defect is a good outcome, and no goal
here requires another tool to remain deficient.

## Sequencing rules

- A silent incorrect answer interrupts planned feature work.
- Only an active sprint contract authorizes implementation.
- Documentation states current behavior. Roadmap intent is never promoted into
  present-tense support.
- A private corpus may find defects and measure usefulness, but cannot define or promote
  a format without public authority and redistributable evidence.
