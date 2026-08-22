# Coding-agent feedback — 2026-08-22

Audience: the coding agent working `docs/CODING-AGENT-PLAN.md`.
Scope: verification of the work committed through `d93d469`, and required
corrections before Gate 2 lands. This document does not modify code.

Read with `docs/CODING-AGENT-PLAN.md`. Where the two disagree, this document
takes precedence for the items it names.

---

## 1. Verified state at `d93d469`

Confirmed working:

- Gate 0 is real. `SupportTier` is an enum, all five stock dialects report
  `experimental`, and `capabilities::tests::test_no_supported_dialect_without_completed_gates`
  enforces the rule in code rather than in prose. Text and JSON agree.
- `compare_chunk_with_luac` returns structured `OracleMismatch` values instead
  of asserting inline. This is the right shape.
- Mnemonic comparison re-decodes the opcode independently from the raw word
  rather than trusting the lifter. Correct instinct — keep it.
- Constant, local, upvalue, metadata, line, and count comparisons exist.
- Five negative controls exist and pass.

## 2. Blocking: Gate 1 is not complete

### 2.1 Operand comparison is declared and never performed

`crates/luad-oracle/src/listing_parser.rs:290` declares:

```rust
Operand { proto, pc, raw_word, index, actual, expected },
```

`rg 'OracleMismatch::Operand' crates/` returns no construction site. The
instruction loop at `listing_parser.rs:498-527` compares line number and
mnemonic and then moves on. `LuacInstDump::operands_raw` is still parsed at
`listing_parser.rs:194` and still never read.

This is the original review defect reproduced one level up. Previously the
comparator parsed operand text and discarded it; now the type system asserts an
operand comparison that the code does not perform. In both cases a green test
certified the gap.

Gate 1's own acceptance says:

> The current Lua 5.4 decoder fails the corrected oracle before its fix.

At `d93d469`, `crates/luad-dialect-lua54/src/opcodes.rs:344` still reads `B`
from bit 15, and `test_canonical_differential_oracle_lua54` reports `ok`. The
acceptance criterion was never executed. Mnemonic comparison inspects only the
low 7 bits, which were never wrong, so it passes trivially on precisely the
dialect it was built to catch.

**Required:** implement operand comparison. Compare per-opcode typed operands
derived from the dialect's mode table against the parsed listing operands, not
whitespace-normalized strings. Emit `OracleMismatch::Operand` with the operand
index. Include the `k` flag and jump destinations as comparable operands.

### 2.2 Missing negative control

Gate 1 required four independent mutations: mnemonic, **operand value or field
position**, constant tag/value, and debug/local field. Four negative controls
exist; the operand control is the missing one, and it is the one that detects
2.1.

Add `test_negative_control_operand_mutation`, mutating a register operand in
the parsed chunk and asserting `OracleMismatch::Operand` at the expected PC and
operand index.

### 2.3 Pin the defect before you fix it

The Gate 2 correction is already in the working tree — `k` at bit 15, `B` at
16, `C` at 24, `OFFSET_SB = 127`, and the five comparison opcodes re-typed
`iABC`. That is the right fix. But once it is committed, nobody can demonstrate
that the oracle would have caught the defect, and Gate 1's acceptance becomes
permanently unprovable.

**Before the Gate 2 commit lands**, add a test that pins the review's golden
words against a decoder-independent expectation:

| Word | Expected |
|---|---|
| `0x050100a2` | `ADD 1 1 5` |
| `0x00010180` | `MOVE 3 1` |
| `0x01030146` | `RETURN 2 3 1` |

Commit it in a state that fails against `d93d469`'s field positions, and let
the Gate 2 commit turn it green. Sequence the commits so the history shows the
oracle detecting the defect.

## 3. Further oracle defects found during verification

These are new findings, not restatements of the review. All are in the code
committed as Gate 1.

### 3.1 Unknown opcodes silently pass

`listing_parser.rs:514-527`:

```rust
if let Some(act_mnem) = decode_instruction_mnemonic(&chunk.dialect, act_inst.raw_word) {
    // ... compare
}
```

When `decode_instruction_mnemonic` returns `None`, no mismatch is recorded and
the instruction is treated as matching. An unrecognized opcode number — the
exact condition a vendor-modified or corrupt chunk produces — passes the
oracle. `None` must produce a mismatch variant, never a skip.

Audit the whole comparator for this pattern. Every `if let Some(...)` that
guards a comparison is a place where absence is being read as agreement. The
upvalue-name loop has the same shape.

### 3.2 `check_constant_matches` is unsound

`listing_parser.rs`, `fn check_constant_matches`:

- **Substring matching.** `Integer(2)` is checked with
  `exp_raw.contains("2")` against a line that still includes the constant
  index column. `Integer(0)` at index 10 matches the line `10 I 999`. Parse the
  listing line into `(index, tag, value)` and compare fields.
- **The type tag is never compared.** Lua 5.4/5.5 print `I`, `F`, `S`. An
  integer `2` and a float `2.0` both satisfy the current check. The
  integer/float distinction is the entire reason Lua 5.3 is a separate dialect;
  the comparator cannot be blind to it.
- **Float tolerance is 1e-5 relative.** `luac` prints `%.14g`. A 1e-5 window
  accepts `3.14159` for `3.14160` and defeats FR-PARSE-005 outright — signed
  zero, NaN payloads, and subnormals all compare equal. Compare the decoded
  value re-formatted as `%.14g` against the listing token exactly, and cover
  exact bit patterns with a separate round-trip test rather than through the
  listing.
- **`Nil` and `Boolean` use `contains`.** A `Nil` in `luad` matches an expected
  string constant `"nil_handler"`.

### 3.3 Required tests still skip

All six negative controls in
`crates/luad-oracle/tests/test_oracle_negative_controls.rs` use:

```rust
let Some((chunk, dump)) = get_base_test_pair() else {
    eprintln!("Skipping: luac 5.4 not available on system");
    return;
};
```

The 5.1/5.2/5.3 differential oracles in `test_differential_oracle.rs` do the
same, and skip on any host without those compilers — including, today, this
one. Until this is fixed, every gate in the plan can be self-certified green on
a runner without compilers, including the gates already closed.

The plan places this in Gate 3. **Do it first.** It is roughly ten lines:
replace each skip with a hard failure, and gate the whole oracle test module on
an explicit opt-out for local development that CI never sets. Operating rule 3
already says "never report completion if a required test skipped" — make the
harness enforce it rather than the reporter.

## 4. Correctness of comments and evidence text

The product is trustworthy facts. Comments in the oracle layer are part of the
claim surface.

- `test_oracle_negative_controls.rs:44` — `// Lua 5.4 OP_SUB = 1`. Opcode 1 is
  `LOADI`; `OP_SUB` is 35. The test still works because it only needs a
  different mnemonic, but fix the comment.
- `capabilities` lists `32-bit/64-bit size_t support` and `LNUM integer
  constants` as Lua 5.1 features. Both rest on the field report, not on a
  passing gate. Per Gate 0's own rule, feature strings are a claim surface too;
  either remove them until `gate-layout-lua51-32` and `gate-profile-lua51-lnum`
  pass, or mark them explicitly unverified in the same way support tier is.

## 5. Recommended order for the next commits

1. Make oracle skips fatal (from Gate 3, pulled forward).
2. Add the golden-word pin test and the operand negative control; commit red.
3. Implement operand comparison; fix 3.1 and 3.2.
4. Commit the Gate 2 decoder fix, turning the pins green.
5. Replace the five `unsafe { transmute }` opcode conversions and land
   `#![forbid(unsafe_code)]` — the tree is currently red because
   `deny(unsafe_code)` was added to `luad-dialect-lua54/src/lib.rs` ahead of the
   replacement. Keep that a single atomic commit per operating rule 1.
6. Only then proceed to Gate 3's installer and provenance work.

## 6. Handoff requirements for these commits

Per the plan's final handoff section, and specifically for this batch, state:

- whether `OracleMismatch::Operand` now has a construction site and a negative
  control;
- the exact command and output showing the pin test failing at `d93d469` and
  passing after the Gate 2 fix;
- compiler binaries and versions detected during the run;
- the number of tests that skipped — which must be zero for oracle tests.

Do not describe Gate 1 as complete until 2.1, 2.2, 3.1, 3.2, and 3.3 are
addressed. Gate 1 exists to make the proof system capable of failing; a
comparator with a dead comparison arm does not yet meet that bar.
