# Chairman audit — post plan-v3 state

Date: 2026-08-22
Basis: independent verification at `ba06d68` (clean worktree), not review of claims.
Supersedes the assessment sections of `PLAN-REVIEW-2026-08-22.md`; that document's
amendments are largely adopted.

---

## 1. Verdict

Substantial, real progress. Plan v3 is a better document than plan v2, the audit
in its §2 caught its own prior overclaiming before I did, and the proof
infrastructure it specifies now exists and works.

One structural defect remains, and it is the same species as the original — a
green gate over an unverified thing — but it has moved much closer to the edge
of the system. That is convergence, not stagnation.

## 2. Independently verified as real

Each item below was checked by running the code, not by reading a test name.

| Claim | Verification |
|---|---|
| R0 containment holds | All five stock dialects report `experimental`; versions narrowed to exact patches (`Lua 5.4.8`, not `5.4.0-5.4.8`); every `completed_gates` array is empty; feature strings read `lossless parse (experimental)` |
| Gate harness is executable | `gate-proof-harness.sh` runs `run_gate` against a committed spec, emits `GateSpec`/`GateResult`/`ReleaseManifest` into a temp dir, records a probe-rejection report, enumerates 13 tests, and verifies the result before returning |
| Gate artifacts are substantive | `GateResult` records spec hash, commit, dirty flag, full argv, enumerated tests, compiler path/version/SHA-256, fixture hashes, platform, timestamps, and stdout/stderr hashes; `success` is derived, not accepted |
| R2 oracle is rigorous | 32 enumerated tests: typed operands, exact constant tags, integer-vs-float tag separation, exact float listing tokens, signed zero, unknown-opcode rejection, missing/extra operand, record consumption ledger, and a sweep proving the pre-fix bit-15 decoder fails all 10 fixtures |
| R3 dominators are correct | `luad cfg` on the control-flow fixture now reports `b3←b1`, `b5←b4`, `b6←b4`, `b7←b6`. The prior "everything idoms to b0" behaviour is gone |
| R4 losslessness is a real proof | `encode_chunk_lua54` exists; `parse → serialize` is byte-identical across debug and stripped fixtures, and `test_killer_probe_clearing_raw_spans_remains_byte_identical` proves the writer does not fall back to captured spans |
| Lua 5.4 decode is fixed | `ADD 1 1 5`, `MMBIN 1 5 6`, `FORLOOP 2 3` now match `luac` exactly |
| The lifter is correct | `luad explain proto:0:pc:19` yields `R(1) := R(1) + -5`, matching `luac`'s `ADDI 1 1 -5` |
| All ten gate scripts pass | Run individually; each returns 0 with a verified result package |

The independent Lua 5.4.8 reference decoder (`independent_lua54_oracle.rs`,
transcribed separately from official opcode modes) is the right answer to rule
11 and is the single best piece of engineering added in this round.

## 3. Primary finding: the oracle validates a reference implementation, not the product

### 3.1 The chain that is proven

```
production parser  →  raw instruction words
                          ↓
              IndependentInstruction54::decode      ←→   luac -l -l   ✓ compared
```

### 3.2 The chain that is not

```
production parser  →  RawInstruction54::decode  →  lifter  →  text renderer  →  user
                                       (never compared to either side above)
```

`compare_chunk_with_luac` takes the production `Chunk`, extracts `raw_word`,
and decodes it with the *independent* decoder. The production decoder, lifter,
and renderer never face the oracle. The only CLI disassembly assertion in the
entire suite is:

```rust
assert!(disasm_text.contains("LOADI") || disasm_text.contains("MOVE"));
```

### 3.3 Consequence, demonstrated

`gate-facts-lua54-8` is green. The product's primary output is still wrong:

| PC | `luac -l -l` | `luad disasm` |
|---:|---|---|
| 17 | `GTI 1 0 0` | `GTI 1 127 0` |
| 19 | `ADDI 1 1 -5` | `ADDI 1 1 122` |
| 20 | `MMBINI 1 5 7 0` | `MMBINI 1 132 7` |
| 21 | `EQI 1 15 1` | `EQI 1 142 0 (k=1)` |

Root cause: `crates/luad-cli/src/render/text.rs:320` renders `OpMode54::IABC`
generically as `a b c`. It has no per-opcode operand kinds, so it never learns
that `GTI`/`ADDI`/`MMBINI`/`EQI` carry `sB`. `raw_info.sb` exists and is
correct; the renderer does not use it.

This is narrower than the original defect — decode and lift are right, only the
last mile is wrong — but it is the mile the user sees.

### 3.4 Why the plan permitted it

Rule 11 says do not call model agreement independent evidence. Rule 3 says
tests must call the production boundary. The implementation satisfied rule 11
by introducing a second decoder, and in doing so stopped satisfying rule 3 for
operands: neither side of the comparison is now the product.

**Required correction:** the comparison must be three-way — `luac` ↔
independent reference ↔ production render path — with all three required to
agree. Add a conformance test over every fixture instruction word, plus a
golden text comparison of `luad disasm` against a normalized `luac -l -l`
listing. Commit it red; it fails today.

## 4. Secondary finding: F-series gates are green over absent capabilities

### 4.1 `gate-resolved-constants-lua51`

The gate runs `test_operands_lua51` — four tests against the lifter's internal
operand resolution. None of the plan's own §14 killer probes is wired:

- "`LOADK 1 1` for the hello fixture must include the resolved string preview on
  the same row" — `luad disasm tests/fixtures/precompiled/lua51/hello.luac`
  still prints bare `LOADK 1 1`.
- "JSON must expose a typed constant object" — not asserted.
- "The same semantic operand must agree across disassembly, explanation, and
  xrefs" — not asserted.

The field report's number-one reported time cost is still present in the
product, behind a green gate.

### 4.2 `gate-closures-lua51`

Partially delivered: descriptor PCs are now suppressed from the listing in
places (visible PC gaps). But in the 5.1 closures fixture, `proto:0/0/0` still
renders `6 CLOSURE 1 0` immediately followed by `7 GETUPVAL 0 0 0`, and no
`upvalue[i] <- parent R…` annotations appear anywhere. The plan's §13 probe —
"the existing closures fixture must no longer print descriptor rows as `MOVE` or
`GETUPVAL`" — is not enforced by the gate that claims it.

### 4.3 Pattern

Both F-series gate specs point at pre-existing internal-API test files. The plan
wrote the correct probes; the specs did not adopt them. The gate name now
asserts more than the gate runs — which is the exact failure the artifact
contract was built to prevent, relocated from the comparator into the spec.

## 5. Housekeeping that matters because names are the contract

- Plan §14 ordered `gate-operands-lua51.sh` renamed or removed. Both it and
  `gate-resolved-constants-lua51.sh` exist and drive the same test.
- Plan §15 ordered `gate-corpus-lua51.sh` removed. It is still present, and
  `gate-profile-lua51-lnum` runs `test_corpus_lua51`.
- `gate-analysis-cfg.sh` and `gate-analysis-r3.sh` both exist; the spec is
  `gate-analysis-r3.json`.
- `gate-evidence-field.sh` and `gate-field-evidence-tp-link.sh` both exist;
  neither matches the plan's `gate-field-reproducers-lua51.sh`.
- `scripts/generate_evidence.py` hardcodes every `*_passed: True`, including
  `runtime_semantics_passed: True` at line 60 — which R0 explicitly ordered
  removed and which E1's deferral makes false. The committed evidence files are
  currently clean, so this is latent drift rather than a live false claim.
  Delete the script or rewrite it to consume `GateResult` artifacts only.

Fourteen scripts against ten specs, with four orphans, in a system whose
premise is that gate identity is the unit of truth.

## 6. Rule 12 is still violated at the public boundary

`luad explain proto:0:pc:19` prints:

```text
Confidence:          Fact
Official Source Citations:
  - lvm.c:1218
```

E1 is deferred by §16, so per rule 12 static effects must be labelled
`reviewed` or `unverified`, not `Fact`. The citation carries no release pin,
which §10.1 of the PRD requires. R0's containment sweep covered `capabilities`,
README, and machine-interface docs; it did not reach `explain`.

## 7. Strategic: the first release candidate would ship below `luac`

§18 makes exact Lua 5.4.8 parsing and disassembly the promoted scope. F3
(resolved constants) is scoped only to Lua 5.1. On that path, a "supported"
5.4.8 disassembler would ship with:

- unbiased signed immediates (§3.3);
- no inline constant resolution (`LOADK 1 1` with no string);
- no per-instruction line numbers;
- no jump-target or metamethod annotations.

`luac -l -l` provides all four. Promoting a disassembler whose flagship output
is less informative than the tool it is differentially tested against is not a
defensible first release.

**Recommendation:** add **R6 — public disassembly conformance** as a
prerequisite of `gate-release-lua54-8`, and extend F3's operand resolution to
Lua 5.4 before the RC. The scope decision from `PLAN-REVIEW` still holds —
5.4 is the proof vehicle, embedded 5.1 is the product — but the proof vehicle
still has to be usable, because it is what gets promoted first.

## 8. Next steps, in order

1. **R2a — three-way conformance.** Production render path ↔ independent
   reference ↔ `luac`. Golden text comparison of `luad disasm` against a
   normalized listing, over every maintained fixture. Commit red.
2. **Fix `render/text.rs`** to render from typed semantic operands rather than
   re-decoding by opmode. The lifter is already correct; the renderer should
   consume it. This closes §3.3 and prevents the class recurring in 5.5.
3. **Wire the plan's actual killer probes** into `gate-resolved-constants-lua51`
   and `gate-closures-lua51`; delete the four orphan scripts. A gate spec whose
   `expected_tests` do not include the probes named in the plan section it
   implements should itself fail a consistency check.
4. **Downgrade `Confidence: Fact`** to `reviewed` in `explain`, and either pin
   or remove the `lvm.c` citations.
5. **Delete `scripts/generate_evidence.py`** or rewrite it to derive solely from
   `GateResult` artifacts.
6. **Add R6 to the promotion prerequisites** and extend constant resolution to
   Lua 5.4 before declaring an RC.

Items 1–2 are one focused change and should land next. Items 3–5 are cleanup
that protects the contract. Item 6 is a scope decision for you.

## 9. One structural amendment

The recurring defect across all three audits has been the same shape at
successively smaller scales:

1. the comparator compared nothing;
2. the comparator declared an operand check it never ran;
3. the comparator is exact, and is aimed at a reference implementation rather
   than the product.

Each iteration is closer to the user and less severe. The generalisation worth
writing into the plan as a rule:

> **Every gate must terminate at the public boundary a user or agent actually
> consumes.** Internal-API agreement may support a gate; it may never be the
> gate's terminus. Where a gate's subject is output, its acceptance must
> compare bytes of that output.

That single rule subsumes rule 3, closes §3 and §4 of this audit, and would
have prevented all three instances.
