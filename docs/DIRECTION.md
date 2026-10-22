# Direction: what would make `luad` maximally useful for reverse engineering

A forward-looking argument about where effort should go, written for whoever picks up the
next sprint. It is not a contract. It names an order, the evidence for that order, and the
decisions that have to be made by a person before parts of it can be contracted.

## The finding

`luad` is a strong fact *producer* with no *answer* layer, and it has twice formally
declined to build one.

Both independent real consumers were blocked above the fact layer, not inside it:

- The firmware-audit consumer named [#89](https://github.com/dweekly/luad/issues/89) "the
  only one blocking finding work." It was closed as not planned, correctly on its own terms:
  the inverse call edge is "a consumer-side regrouping of shipped facts." The close note also
  records that the consumer *had never passed `--link-convention`*, which is opt-in. The
  mechanism existed and resolved 5,416 of 9,013 links; the consumer could not find it.
- [#93](https://github.com/dweekly/luad/issues/93) was declined for the same reason: the
  union over callers is "a two-key join over facts already shipped."
- 96 of that consumer's sink arguments come back `entry-param` — blocked on exactly the join
  declined twice. A further 63 `path-unresolved` and most of 158 `unknown` are their own
  field-path resolver, which they rebuilt because nothing upstream offered it.
- A second reader, auditing firmware from bytecode, ran one command, hit a bare
  unrecognized-subcommand error on `decompile`, read `--help`, and stopped. Its top request
  was per-prototype labeled constant pools: a presentation of data `luad` already holds.

Meanwhile the effort went into fact-level precision. Proportions, measured:

| | lines |
|---|---|
| `luad-oracle` (evidence and test harness) | 61,141 |
| all production `src` across nine crates | 45,904 |
| `luad-analysis` — the engine that answers questions | 9,360 |

The evidence apparatus is larger than everything it tests, and the analysis engine is a
fifth of production code. That ratio is not wrong in itself — it is what makes aggressive
landing safe — but it is currently aimed almost entirely at the precision of individual
facts, which is not where either consumer is stuck.

## The boundary is drawn in the wrong place, by one word

`luad`'s stated boundary is that composition is the caller's job, and the consumer agrees
the boundary is right: their own file says it "deliberately contains no requests for taint
tracking, sink classification, or exploitability judgment: that is the caller's job and the
boundary is in the right place."

That is a boundary against **policy**, and it should hold absolutely. It has been applied as
a boundary against **mechanism**, which is a different thing. "What counts as a sink" is
policy. A join on `(caller_path, call_id)` is arithmetic. Declining the arithmetic does not
protect the factual boundary; it leaves `luad`'s hardest-won precision unreachable without
every consumer writing the same five scripts.

**The test to apply instead:** does this composition require a judgment about what matters?
If yes, refuse it — permanently, and say so. If no, it belongs in `luad`, and labelling it
honestly (a union over *enumerated* callers, with the unenumerated set reported, not
assumed empty) is the whole of the correctness obligation.

## Order of work

### 1. Real-firmware argument-level regression evidence (#94, the local-endian half)

Highest value, and not blocked. [#94](https://github.com/dweekly/luad/issues/94) carries the
proof that this is the defect class that actually reaches users: 0.3.0 shipped an `origins`
precision regression that moved real answers — externally-tainted sink arguments 15 → 23,
`analysis-limit` 144 → 17 — while **instruction, prototype and call-site counts were
identical**. 61,141 lines of oracle did not catch it. The consumer's own gate, which pins
`(file, prototype, pc, argument)` verdicts, did.

Until CI pins argument-level verdicts on a real chunk, every precision change ships on
public fixtures and hope. Build that gate. It is the one piece of rigor that is currently
missing rather than oversupplied.

### 2. Ship the mechanical joins as first-class output

Reopen #89 and #93 against the policy/mechanism test above, and add the consumer's
field-path resolution. Concretely, the compositions every consumer has rebuilt:

- the inverse call edge, per prototype, with an unreached export distinguishable from a
  failed resolution (`gate-cross-chunk-link` already pins this shape — the fact family is
  there, the query is not);
- caller-argument substitution into callee parameters, labelled as a union over enumerated
  callers with the unenumerated remainder reported;
- cross-chunk conventions **detected and reported by default** rather than opt-in, including
  the dotted-submodule shape that `luci-module-setglobal` resolves nothing for and which
  holds 17 of 43 shell sink arguments in one file.

Correctness discipline for all of it, and this is the generalizable lesson from the
withdrawn #97 work recorded in `ROADMAP.md`: **a set that reads as complete must be built by
allowlist, not by subtraction.** That revert happened because writes were collected by
ruling out what could be excluded, so anything the enumeration failed to see became silently
absent from a set presented as whole. Every join here has the same failure shape. This should
be a stated repository invariant in `AGENTS.md`, not a one-off note about one reverted patch.

### 3. Discoverability, as a correctness property

Measured twice as the actual failure mode, and the cheapest item on this list.

- `luad decompile` must exit with a pointer to `inspect` plus the profile hand-off, not a
  clap error. Unknown subcommands that name a real intent deserve an answer. The reader's
  own words: "the error being silent about intent, not the missing feature" cost the time.
- Per-prototype labeled constant pools, the top request from a reader who got as far as
  running `strings` and found it useful only because the pool happens to be roughly in
  source order.
- `--link-convention` on by default, auto-detected, with what it matched reported.
- One worked chain, front and centre in `README.md`, from a firmware tree to an answered
  question. `docs/examples/RECIPES.md` has thirteen recipes and 534 lines; the consumer who
  needed recipe 7 never found it.

Performance is **not** an argument here and should not be used as one: 66 fixtures export to
871 facts in 0.43s, so re-deriving facts per question is cheap at corpus scale. The missing
layer is composition, not caching. Do not build an index to make this faster.

### 4. Big-endian, as a decision rather than a sprint

The largest single coverage unlock, and blocked by policy, not difficulty. `luad` refuses
endianness 0 at header offset 6 and exits 4; `docs/NEXT-SPRINT.md` declares the work not
authorized without its own evidence gate. The second consumer corpus is a QCA9563 MIPS
big-endian platform, 235 files.

**Resolve one question before sizing this:** whether those chunks are big-endian *encoded*,
or little-endian chunks on a big-endian platform. The consumer's note says that corpus
"behaves the same on every item," which is only possible if `luad` reads it — so the
platform being BE may not mean the bytecode is. Ask. If the chunks really are BE, this is
half a corpus and outranks everything in section 2. If they are not, it is a dialect-profile
item with no current consumer and should be deferred openly.

### 5. Stop: origin unknown-reason precision

By the consumer's own measurements, this work is landing where nothing is blocked:

- `luad`'s limit diagnostics fire **2, 6 and 17 times** across 344,120 instructions.
- `control-flow-conflict`, frequent in the export overall, lands on **zero** of 305
  shell-family sink arguments.
- [#97](https://github.com/dweekly/luad/issues/97) is, in the consumer's own taxonomy, a
  reason that costs the *string* while the verdict survives. It does not block a finding.

A sprint went into #97 and was reverted. The revert was the right call and its record is
worth keeping, but the deeper error was selecting it at all: it was chosen because it was a
legible gap in the fact model, not because anything downstream was waiting on it. #96, which
cost the *verdict*, was the right pick and shipped. Use that distinction to choose.

`#97` should stay open and unstaffed, with this reasoning on it, rather than be rebuilt.

## What this implies about how the next sprint is chosen

The repository's machinery for *verifying* a change is excellent and should not be touched.
Its machinery for *choosing* one is a roadmap of internally-visible gaps, which is how a
sprint went to a reason that costs a string while 96 sink arguments waited on a join.

A cheap correction: `docs/NEXT-SPRINT.md` requires acceptance criteria as executable
commands. Require one more line — **which measured consumer blocker this unblocks, with the
number** — and decline any candidate that cannot fill it. Every item in sections 1 through 3
above can; #97 could not, and saying so out loud would have cost a paragraph instead of a
sprint.

## Open questions for a person

1. Big-endian: encoded, or just the platform? (section 4) — the one question gating the
   largest item on this list.
2. Is shipping the mechanical joins (section 2) accepted as inside the factual boundary? It
   reverses two closed issues, so it is a maintainer's call and not an agent's.
3. Does the private-corpus re-measurement owed by four landed precision changes still matter
   if section 5 is accepted and precision work stops? It may be retired rather than owed.
