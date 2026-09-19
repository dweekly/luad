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

## Origin precision

Two measured origin-analysis gaps, stack-ranked. Both surfaced from running `luad`
0.3.1 over a private OpenWrt-derived Lua 5.1 LNUM32 firmware corpus (~260 files) as the
whole fact engine under a downstream security-analysis pipeline. A private corpus can
find defects and measure usefulness but cannot promote a format; the acceptance criteria
below therefore pair a public fixture with a re-measurement against that corpus. The
counts are stated once: after the 0.3.x work, `control-flow-conflict` is the largest
remaining origin unknown-reason (2,940 down to 1,016 corpus-wide), and it sits behind 99
of 175 unresolved call-argument origins that reach shell and filesystem sinks.

### Emit a bounded `alternatives` set instead of `control-flow-conflict`

When origin analysis reaches a control-flow join, or widens a loop-carried slot, it
collapses the slot to the opaque `control-flow-conflict` unknown-reason. `alternatives`
already exists for some bounded joins, so where the set of reaching definitions is
finite the origin should be that `alternatives` expression, not the opaque reason. A
consumer cannot see through `control-flow-conflict`; an `alternatives` set it can.

The 0.3.1 loop-widening fix (PR #85) sharpened this rather than caused it. That fix
deliberately widens a loop-carried slot to `control-flow-conflict` after
`MAX_BLOCK_REVISITS` to stop unbounded lattice growth, which was the right call against
the alternative of reporting the whole prototype as `analysis-limit`. But the widened
slots are frequently the sibling expressions of a resolvable argument in the same
constructed command string, so widening to the top of the lattice makes those siblings
unreadable downstream. The gap to close: widen to a bounded `alternatives` set where one
exists (respecting `MAX_ALTERNATIVES`), and reserve `control-flow-conflict` for the
genuinely unbounded case.

The concrete repro prototype (a constructed shell-command argument whose siblings are
loop-widened) is recorded in the consumer's private notes, not here, because it names an
unreleased finding in a shipping product.

**Acceptance.** A public fixture that exercises both a bounded join and a loop-carried
slot in one command-shaped expression; `luad origins` emits `alternatives` with the
candidate set where the reaching set is bounded, and keeps `control-flow-conflict` only
where it is genuinely unbounded (the existing loop-widening regression test still holds
there). Re-run over the private corpus: the `control-flow-conflict` count falls and
previously-blocked bounded sink arguments resolve, with no argument losing an expression
it had in 0.3.1.

### Make the origin unknown-reason cap explicit (B-9)

Two origin unknown-reason totals saturate at exactly 2000 corpus-wide while no single
file approaches that number, which is the signature of a silent global cap on a counted
or de-duplicated set. It is not in the `origins.rs` analysis constants
(`MAX_EXPRESSION_*`, `MAX_TRANSFER_STEPS`, `MAX_ALTERNATIVES`, `MAX_BLOCK_REVISITS`); the
next place to look is the export and records/dedup path. A consumer measuring
release-over-release deltas read `unsupported-value` as falling 2394 to 2000 and
`overwritten` as rising 1976 to 2000, both cap artifacts rather than real movement, and
nearly reported a regression and an improvement that did not happen. Per the sequencing
rule below, a silently clamped count is a correctness defect, not an ergonomics one.

**Acceptance.** Locate the cap; either lift it or make truncation explicit with a
diagnostic and a truncated flag so a clamped total is never presented as a measured one.
A test asserts that when the cap would bind, the output carries the truncation signal
rather than a silently clamped count.

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
