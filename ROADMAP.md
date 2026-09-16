# `luad` roadmap

Status: plan of record.

Fresh as of: 2026-09-16.

Stack-ranked. The top item is what happens next. Nothing below is a commitment, and
nothing here authorizes implementation on its own — a stage places its contract in
[the active sprint](docs/NEXT-SPRINT.md) first, per
[the contract lifecycle](docs/DEVELOPMENT-WORKFLOW.md#12-preservation-documentation-and-escalation).

The full qualification program a 1.0 would need is kept separately in
[docs/ROADMAP-1.0.md](docs/ROADMAP-1.0.md). It is deliberately not the current plan:
`luad` is a 0.x tool and should ship useful improvements without paying 1.0's evidence
cost for each one.

## Next

1. **Layout truth for Lua 5.2 and 5.3.** A declared header width must be honored or
   refused by name, never silently replaced with the reader's preferred one. This is the
   only defect class that produces a confident wrong answer instead of an error, so it
   outranks every feature. Fix 5.2 and 5.3; probe 5.5 the same way.
2. **Fix the offset in body-parse diagnostics.** EdgeTX chunks fail inside the body with
   a diagnostic anchored at offset 0, which sends a reader to the wrong place. Report the
   deepest failure offset reached.
3. **One firmware walkthrough in the README.** Take a real extracted tree, inventory it,
   find a global lookup, inspect the instruction, and hand the chunk to a decompiler.
   Public inputs, exact commands, expected output.
4. **Make the integration tests resolve `luad` once.** Each test binary that shells out
   to the CLI spawns its own nested `cargo build -p luad-cli` when `CARGO_BIN_EXE_luad`
   is unset, so a workspace run races several cargo invocations against each other and
   against the outer build. `test_cli_inspect_and_disasm` was observed failing three
   times on the first run after a rebuild and passing on repeat runs; the mechanism is
   understood but not deterministically reproduced. Resolve the binary through one
   helper that does not build.
5. **Hostile-input bounds.** Runtime and peak-memory tripwires on the exposed paths, and
   minimized regressions from the fuzz corpus. The fuzz smoke suite already runs in CI;
   this makes its findings durable.

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
