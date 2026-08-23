# Field report: luad against TP-Link Deco firmware

**Date**: 2026-08-22
**Corpus**: 260 `.lua` files from TP-Link Deco X55 V1.2 firmware 1.4.6 (build 20250211).
252 are stripped Lua 5.1 bytecode from the LuCI admin stack; 8 are plain source.
**Task**: a security audit of the firmware. luad was used to answer real questions, not
as a benchmark. Everything below is grounded in that work.
**luad version**: `0.1.0` at `66d2822`, plus local branch `fix/lua51-lnum-reachable-from-cli`.

> **On redaction**: this document deliberately does not reproduce vendor key material,
> credential hashes, or other extracted secrets, even where they are already public. This
> is a general-purpose tool repository, not a security-research one. The concrete values
> live in the private research repo alongside the audit that produced them. Examples below
> use placeholders; the tooling behaviour they illustrate is unaffected.

The headline: **luad replaced a hand-written disassembler for the hardest part of the
audit** — proving that a hardcoded AES-256 key reaches the config-backup decrypt
function through a three-hop upvalue chain. That is a real win. The `CLOSURE` effects
work does something no other tool I tried does.

---

## Part 1 — Bugs

Ordered by severity. Repro paths assume the corpus above; any OpenWrt-derived Lua 5.1
firmware will do.

### B-1. `query --where 'constant contains "…"'` silently ignores the operand — **critical**

The predicate parses, runs, and returns a plausible result set that is **not filtered by
the needle**.

```sh
luad query crypto.lua --where 'constant contains "<8 chars known to be present>"'  # 184 matches
luad query crypto.lua --where 'constant contains "ZZZZ_NO_SUCH_ZZZZ"'             # 184 matches
```

Identical counts for a present and an absent needle. (184 is not "all constants" either;
the file has 221 across all prototypes, so some filtering happens — just not on the
operand.) Malformed predicates *do* return 0, and `opcode == "OP_CLOSURE"` filters
correctly, so the failure is specific to the operand of `contains`.

**Why this is the worst bug in the list**: it does not error, it answers. In a tool whose
stated purpose is forensics, a predicate that silently matches everything will be
believed. I only caught it because I already knew the key was in that file and the
result set looked too big.

**Suggested fix**: unknown or unapplied predicate operands must be a hard error, not a
degraded match. Fail closed, consistent with the rest of the tool's design.

### B-2. LNUM profile is unreachable from the CLI, so no OpenWrt firmware parses — **critical (fixed on branch)**

Two independent blockers; details in commit `dae12b2`.

1. `ChunkLayout::validate()` takes a `profile` but does not consult it for byte 11.
   Stock Lua 5.1 writes the integral flag (0/1); the LNUM patch reuses the slot for
   `sizeof(lua_Integer)` = 4. Every LNUM chunk therefore died with
   `Invalid integral flag 4` *before* the correctly-gated tag-9 decoder could run.
2. `Lua51Dialect` was a unit struct whose `decode_chunk()` always called the Stock
   path. No `--profile` flag, no LNUM `--dialect` value. The error message advising
   "use profile 'lnum'" pointed at something the CLI could not select.

Net effect: **0 of 260 files parsed**, down from 252 before the profile refactor.

**Note on process**: the `gate-profile-lua51-lnum` capability gate presumably passes via
the library API while the only user-facing path is broken. A corpus test through the CLI
would have caught this immediately. See W-9.

### B-3. `CLOSURE` summary names the wrong prototype — **medium**

```
"CLOSURE  Instantiate closure proto:0 into R(27) with 3 upvalue capture(s)"
"CLOSURE  Instantiate closure proto:1 into R(28) with 4 upvalue capture(s)"
```

The children are `proto:0/0`, `proto:0/1`, `proto:0/2`. The renderer prints the raw `Bx`
index formatted as a top-level path. That is not merely imprecise — `proto:1` is a real
and *different* prototype in most chunks, so the summary points at the wrong object.

`xrefs` gets it right (`proto:0:pc:103 Instantiates proto:0/5`), so this is isolated to
the summary renderer.

### B-4. `CLOSURE` pseudo-instructions still render as executable `MOVE`s — **low (semantics fixed, presentation not)**

The semantics are now correct — `writes: []` rather than the previous bogus
`writes: [R0]`, and `CLOSURE` aggregates the captured registers into its own reads. Good
fix. But the listing still shows:

```
78  MOVE  0 5 0 ; reads: [Register { index: 5 }], writes: []
```

A reader who does not already know that the `nups` instructions after `CLOSURE` are
upvalue bindings will read this as a real move into R0. Rendering it as
`; upvalue[0] <- parent R5` would remove the trap entirely.

### B-5. Dialect variant is not reported in output — **low**

`inspect` prints `Dialect: lua5.1` even when the LNUM path is taken. `Lua51Dialect::name()`
returns `lua5.1-lnum`, so something upstream overwrites it. For a forensics tool the
variant actually used to decode is part of the finding and should be visible.

### B-6. API break introduced by the profile field — **informational**

`Lua51Dialect` is no longer a unit struct (my change). Six call sites needed
`::default()`. Flagging in case that shape matters to you.

---

## Part 2 — Observations

### What works well

- **`CLOSURE` capture aggregation is the standout feature.** The ordered `reads` list maps
  positionally to upvalue indices, which makes upvalue-binding chains mechanical:
  ```
  103  CLOSURE 32 5 ; reads: [R18, R16, R19, R17, R13, R22]
  ```
  Upvalue[5] = R22 = the AES key/IV argument string. That single line replaced a page of
  hand-decoding and is what let me prove the key reaches `dec_file`. I would not have
  thought to ask for this.
- **CFG is correct.** 179 blocks with typed edges and dominators on the LuCI dispatch
  function; correctly one block on a genuinely branch-free module chunk. I checked the
  suspicious case rather than assuming, and it held up.
- **Error offsets are now real** (`offset 12`, not `offset 0`). Previously misleading.
- **Byte accounting and fail-closed parsing** are the right instincts for this domain.
- **Explicit profile gating over auto-reinterpretation** is the right call for forensics.
  It just needs the user-facing escape hatch (B-2).

### Design observations

- **`explain`'s confidence labels are load-bearing and should be audited.** Before the
  `CLOSURE` fix, `explain` reported "Copy R(0) := R(5)" at `Confidence: Fact` for a
  pseudo-instruction. A confidence taxonomy is only useful if `Fact` is never wrong;
  otherwise it actively increases misplaced trust. Worth a pass over every site that
  emits `Fact` asking "could this be wrong for a non-stock chunk?"
- **JSON is currently less useful than text.** Instruction records carry `id`, `pc`,
  `raw_word`, `raw_hex`, `source` — no mnemonic, no decoded operands, no constants. An
  agent consuming JSON has to re-implement the decoder, which defeats the "machine
  interface" goal. The text renderer is strictly more informative today.
- **`capabilities` overstates readiness.** `lua5.1 [experimental] … lossless parse,
  disasm, validate` was advertised while no real-world 5.1 chunk could be parsed. A
  capability claim that is true only for fixtures is misleading to an agent choosing a
  tool.

---

## Part 3 — Wishlist

Ranked by how much each would have accelerated *this* audit. The top three would have
saved hours each.

### W-1. Resolve constants inline, everywhere

The single highest-value change. Today:

```
66  LOADK  20 24
```

Wanted:

```
66  LOADK  20 24    ; "<64 hex chars: the AES-256 key>"
```

Apply to `LOADK`, `GETGLOBAL`, `SETGLOBAL`, `SELF`, and any RK operand (you already do
this for `GETTABLE`'s `k(9)`). Also in `explain` ("Load constant K[24]" should show the
value) and in JSON.

*Why*: finding the hardcoded AES key meant reading the constant table in the header block
and manually counting indices. With inline resolution the key is visible on the line that
loads it. This is the difference between reading a disassembly and decoding one.

### W-2. Make JSON self-describing

Each instruction record should carry `mnemonic`, decoded operands with roles
(`a`, `b`, `c`/`bx`/`sbx`), whether each operand is a register or constant, and the
resolved constant value. Right now an agent must re-implement Lua 5.1 instruction
decoding to use the JSON at all.

*Why*: this is the difference between luad being an agent-facing tool and a
human-facing one. The stated goal is the former.

### W-3. A first-class upvalue binding graph

`luad upvalues <chunk>` emitting, for every prototype, each upvalue slot and its origin
in the parent (`parent register N` or `parent upvalue M`), plus a `Binds` xref relation
so it is queryable:

```
proto:0/5:upvalue:5  <- Binds -  proto:0:register:22
```

*Why*: the whole crypto finding was a three-hop chain — `R22` → `main/5` upvalue 5 →
`dec_file` upvalue 0. The data now exists (B-4/`CLOSURE` reads) but must be reconstructed
positionally by hand. Proving "this constant reaches this function" is *the* recurring
question in firmware RE, and it is currently the most laborious part.

### W-4. Corpus-wide constant search

`luad search <dir> --constant '/regex/'` returning `file:proto:k` hits across a whole
rootfs, with a JSON mode.

*Why*: the standard opening move on unknown firmware is "grep the whole filesystem for
key material, URLs, tokens". I did this with `strings` over 2317 files, which finds the
bytes but loses all structure — you cannot tell a live constant from a comment fragment,
and you get no prototype context. luad knows which constants are real. This turns a noisy
`strings` sweep into a precise one, and it is probably the easiest big win on this list.

### W-5. Call-graph and sink analysis

Report the global functions each chunk reads (`GETGLOBAL`) and calls, and let me query
for known-dangerous sinks: `os.execute`, `io.popen`, `luci.sys.call`, `loadstring`. For
each call site, classify the argument as *constant*, *concatenated*, or *computed*.

*Why*: I catalogued 26 command-execution sinks with string interpolation by grepping
decompiled source, which is exactly the fragile approach luad exists to replace. A
`CONCAT` feeding a `CALL` to `os.execute` is a syntactic pattern luad can see precisely
and a grep cannot. This is the highest-value *new* analysis capability you could add for
security work.

### W-6. Register provenance at a program point

`luad provenance <chunk> 'proto:0/5:pc:23' --register 22` → the chain of instructions that
produced that register's value, terminating at constants, upvalues, or parameters.

*Why*: a bounded backward slice is how you answer "is this argument attacker-controlled?"
It does not need to be a full dataflow engine; even single-block, straight-line provenance
would cover most of what I needed.

### W-7. Cross-version diff of a firmware tree

`luad diff-tree <old_rootfs> <new_rootfs>` summarising which prototypes changed, which
constants were added or removed, and which call sites appeared or disappeared.

*Why*: the X55 V1.2 line has sat on one firmware for eighteen months while V1.6 shipped
four releases. Diffing those trees would reveal silently-fixed bugs — vendors routinely
patch without advisories, and the diff *is* the advisory. This is also how you check
whether a finding survives into the current release before disclosing it.

### W-8. Batch mode

Recursive directory input with a summary table and a non-zero exit if any file fails. I
shell-looped over 260 files three times.

### W-9. Real-firmware corpus in CI

The Deco corpus is 252 files, freely downloadable from TP-Link, and would have caught
B-2 the moment it was introduced. Fixture-only testing is what let a "supported" dialect
ship unable to parse any real chunk of that dialect. Happy to point at the exact image.

### W-10. Rough structured output above disassembly

Not a full decompiler — but block structure, loop recovery, and `if/else` nesting
rendered as pseudo-code would cover most of what I currently need `unluac` for. I used
`unluac` for readability and luad for correctness, and switched between them constantly.
luad's CFG and dominator data already contain most of what a structurer needs.

---

## Appendix — how luad was actually used

| Question | Command | Verdict |
|---|---|---|
| Is this bytecode, and what dialect? | `inspect` | worked after B-2 fix |
| Does the whole corpus parse? | `validate` in a loop | 252/252 after B-2 fix |
| Where is the auth gate's logic? | `disasm --proto` | worked; W-1 would have halved the time |
| Which register feeds this upvalue? | `disasm --effects` | worked, positional decoding by hand (W-3) |
| Which closure instantiates this proto? | `xrefs --from` | worked |
| Is this chunk branch-free? | `cfg` | worked, verified correct |
| Where is the hardcoded key? | `query --where 'constant contains'` | **silently wrong (B-1)**; fell back to `strings` |
| What does this instruction mean? | `explain` | worked; value not shown (W-1) |
