# `luad` roadmap

Status: future priorities after the experimental 0.2 release candidate.

Fresh as of: 2026-10-21.

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
of 175 unresolved call-argument origins that reach shell and filesystem sinks, measured over
a corpus 97% of whose files are bytecode this tool parses. A second OpenWrt-derived corpus
shows the same ordering, with `control-flow-conflict` on 19 of 105 unresolved
shell-and-filesystem sink arguments; that corroborates the direction from an independent
corpus and does not restate the figure above, which is not currently reproducible against
the first one.

The second corpus is the weaker of the two and its denominator says why: 175 of its 279
files are bytecode and 104 are plain Lua source this tool does not read, so every count
from it describes 63% of the image rather than the image. The vendor stopped precompiling
much of its Lua tree between the two product generations, which is a packaging difference
between corpora and not a property of any analysis here. Two counts taken over coverages
that far apart are not like-for-like, however closely they agree.

### Re-measure the origin precision changes over the private corpus

Several origin-analysis gaps have closed since 0.3.1, each accepted on a public fixture with a
measured before and after, and none measured corpus-wide:

- a join with one bounded and one unresolved predecessor emits the `alternatives` set rather
  than collapsing to `control-flow-conflict`
- `TESTSET` is modelled, so the `a or b` and `a and b` idioms over locals resolve instead of
  reporting `overwritten`
- an open argument window reports the determinable arguments before its tail, which were
  previously discarded entirely
- a table access whose key register holds only literals names its field rather than reporting
  `dynamic-key`

What is owed is the re-measurement the acceptance criteria named: over the private corpus, the
count per unknown-reason and whether previously-blocked bounded sink arguments resolve, with no
argument losing an expression it had in 0.3.1. The counts above this section predate all of it
and are not restated as current. Any such count must state which field it counted: an earlier
pass reported `control-flow-conflict` as blocking zero sink arguments by searching a consumer
verdict field whose vocabulary cannot contain a `luad` reason, so it would have returned zero
for every reason.

One correctness change moves answers in the other direction and should be expected to: a
table-literal field written before the table reached a callee, a global or an upvalue is no
longer reported, because the holder may have written the same key. Arguments that previously
carried such a field now carry fewer fields or none. That is a 0.3.1 defect corrected, not a
precision regression, and a re-measurement should separate it from the rest.

### Reaching definitions for a rewritten capture: attempted and withdrawn

`mutable-capture` covers a captured register the enclosing prototype writes after building
the closure. Reporting the set of definitions that can reach the closure was implemented,
accepted on a public fixture, and withdrawn; it is not merely unbuilt. The premise is sound
and is worth rebuilding: in Lua 5.1 the closure holds an open upvalue onto the parent's stack
slot, so a later write by the parent is visible to the closure and reporting only the value at
the capture is a wrong answer, while the closure may also run before that write, so no single
value is the answer either. What failed was the method of enumerating the writes.

Two defects, each a wrong answer rather than lost precision, were found by review after the
change was on `main` and neither by its fixture suite:

- Writes were collected by register across a close of the captured cell. Closing the upvalue
  ends the register's identity as that variable, and `luac5.1` reuses the register for the next
  local in scope, so an unrelated variable's value was reported as a possible origin. The
  reproduction is `do local x = "a"; f = function() sink(x) end; x = "b" end; local y = "c"`,
  which reported `alternatives("a" | "b" | "c")` where `"c"` is `y`.
- Writes were collected from `SemanticInstruction::writes`, which is a declared-effect list
  and not an exhaustive enumeration of register modification. `CALL A B 0` declares no writes
  at all, `FORPREP` declares only `R(A)` while converting `A+1` and `A+2`, and `TFORLOOP`
  declares `A+3` upward while writing `A+2`. A capture clobbered by any of those was reported
  as a complete set with that definition missing, which is the failure the never-partial rule
  exists to prevent.

Both are instances of one mistake, which is what withdraws the approach rather than patching
it: the set was built by subtracting writes that could be ruled out, so anything the
enumeration failed to see silently became absent from a set that reads as complete. A rebuild
must invert that default, in the discipline this file already requires of escape analysis: an
allowlist of instructions whose register writes are known to be completely declared, refusing
the capture when any instruction on the path is not on it, with the cell's lifetime bounded by
its close rather than by block reachability.

The work must also be bounded per prototype and not per capture. A budget charged per captured
slot bounds each replay and bounds nothing in aggregate: 50 locals captured by 20 closures in a
3,000-call prototype replayed the parent 1,000 times, each replay under its own limit, taking
30.77 seconds against 0.38 before the change.

`control-flow-conflict` remains correct for one case and keeps that name: a loop-carried value
widened at `MAX_BLOCK_REVISITS`, whose set of reaching definitions is not finite. Widening to a
bounded set there was tried and is not available. The conflict marker has to absorb a join, or
a widened slot becomes one option of a strictly larger set on every pass, the worklist never
reaches a fixpoint, and it stops by exhausting its step budget, which reports every call in the
prototype as `analysis-limit` including the ones that converged at once. That was measured on
`tests/fixtures/origins_loop_widening.lua`, where the non-loop-carried sink argument lost its
concat expression entirely. The two sites are coupled: join precision depends on the widening
marker staying the top of the lattice, so the remaining imprecision there is bounded by an
analysis constant rather than by the lattice, and the constant would be the deliverable.

### What `unsupported-value` and `overwritten` actually mean

Both names read as claims about a value and are not. `overwritten` is the reported reason for
any register write this analysis does not model, which is why it also covers a register
written more than once. `unsupported-value` is almost entirely table invalidation: a table
whose contents may have changed, not a value of an unsupported type. Where a reason's name
misdescribes it, a consumer counts it looking for the wrong thing; both are now documented in
[docs/MACHINE-INTERFACE.md](docs/MACHINE-INTERFACE.md).

The remaining `unsupported-value` population is a blanket invalidation: every `CALL`
invalidates every register holding a table anywhere in its expression, because a callee may
mutate a table it can reach. Bounding that needs an escape analysis — a table constructed
locally, never passed to a call, never stored to a global, upvalue or another table, and never
captured or returned, cannot be mutated by a callee. It is decidable within a prototype and is
sound only if built as an allowlist of known-safe readers, defaulting to escaped, since
enumerating escape routes risks missing one and a missed one reports a stale table. Not
authorized without its own contract: the failure mode is the class that takes priority over
feature work.

### Investigate the origin unknown-reason saturation at 2000 (B-9)

In one downstream aggregation, two origin unknown-reason totals read exactly 2000
corpus-wide while no single file approached that number. That is the shape of a silent
cap, but the responsible layer is not yet identified and this is not confirmed to be a
`luad` defect. It is not in the `origins.rs` analysis constants (`MAX_EXPRESSION_*`,
`MAX_TRANSFER_STEPS`, `MAX_ALTERNATIVES`, `MAX_BLOCK_REVISITS`), and `luad`'s own paths do
not obviously clamp a global unknown-reason count: `handle_origins` serializes every call
site, and `export` uses a per-file `FactEmitter` with an optional `max_facts_per_file`
whose truncation is surfaced explicitly through `file_end.is_truncated`. So the
saturation may be a consumer-side aggregation artifact rather than anything `luad` does.
It still matters because a consumer read the totals as `unsupported-value` falling 2394
to 2000 and `overwritten` rising 1976 to 2000, both of which are suspect if either side
is clamping, and nearly reported movement that may not have happened.

**Acceptance.** First reproduce the 2000 saturation across raw `luad` output and the
consumer aggregation separately, to locate the responsible layer. If it is `luad`, make
the truncation explicit with a diagnostic and a truncated flag, and add a test asserting
the signal is present when the limit binds. If it is the consumer, close this as
not-a-`luad`-defect and record why, so the observation is not re-filed.

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
