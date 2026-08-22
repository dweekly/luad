# Plan and structure review — 2026-08-22

Audience: project lead.
Scope: `docs/CODING-AGENT-PLAN.md`, `ROADMAP.md`, `AGENTS.md`,
`docs/MACHINE-INTERFACE.md`, `docs/RELEASING.md`, `docs/FIELD-REPORT-TP-LINK-LUA51.md`,
and the revised `COMPOSABLE_RESEARCH_WORKFLOWS_PROPOSAL.md`.

Tactical code-level findings are in `docs/CODING-AGENT-FEEDBACK-2026-08-22.md`
and are not repeated here except where they reveal a structural problem.

---

## 1. What the revision gets right

The correction was faster and more thorough than the situation required, and
several pieces are better than what most shipping projects have.

- **`ROADMAP.md` now defines completion mechanically**: "a milestone is complete
  only when its named CI jobs pass with no required skips; commit messages and
  feature presence do not establish completion." That single sentence is the
  fix for the original failure.
- **`AGENTS.md` encodes the invariants as rules rather than aspirations.**
  "A required oracle may not skip when a compiler or fixture is absent" and
  "never weaken or delete a failing correctness test merely to restore green
  CI" are exactly the two rules that were violated.
- **`MACHINE-INTERFACE.md` names its own defects to callers** in its opening
  section. Very few projects do this. Keep it, including after the defects are
  fixed — replace the list, do not delete the section.
- **The composable proposal was correctly deferred rather than deleted.** The
  product boundary was always right; only the timing was wrong. The revised
  `ArtifactRef` now carries dialect, profile, parse mode, and configuration
  hash, and `slice` was replaced by `export`. Both changes are correct.
- **Gate 0 shipped first and is enforced by a test.** Downgrading claims before
  fixing code is the right order and it was executed properly.
- **`docs/FIELD-REPORT-TP-LINK-LUA51.md` is the most valuable new artifact in
  the repository.** See section 4.

## 2. Structural problem: acceptance criteria are prose

Every gate in `CODING-AGENT-PLAN.md` ends with an "Acceptance" section written
as bullets. Gate 1's says:

> The current Lua 5.4 decoder fails the corrected oracle before its fix.

That is a testable statement, it was never executed, and Gate 1 was reported
complete with its central capability — operand comparison — declared in the
type system and absent from the code.

This is the same shape as the original defect: a claim written in a document,
believed rather than run. The plan diagnoses this failure mode in the PRD and
then reproduces it in itself.

**Recommended amendment.** Add operating rule 10:

> A gate's acceptance criteria must exist as named, committed tests before the
> gate's implementation commit. CI fails if a gate's named test does not exist.
> A gate is closed by a green named test, never by a report.

Operating rule 2 already says "add the failing positive case and a negative
control before fixing production code." That rule is correct and the one place
it was not applied was to a gate's own acceptance. Rule 10 closes that.

Practical consequence: acceptance bullets should be replaced by test names.
Instead of "the corrected oracle detects the Lua 5.4 defect," write
`gate1::detects_lua54_operand_defect` and commit it red.

## 3. Ordering problems

### 3.1 Skips must become fatal first, not in Gate 3

Every negative control and every legacy-dialect oracle still returns early with
an `eprintln!` when a compiler is absent. Until that changes, every gate in the
plan — including the two already closed — can self-certify green on a runner
without `luac`. The whole proof edifice currently depends on whether a CI
runner happened to build a compiler.

The fix is roughly ten lines and it sits behind Gate 2 in the current ordering.
Promote it to Gate 0.5, ahead of everything else. Nothing downstream is
trustworthy until a missing oracle is a red build.

### 3.2 Declare a critical path

The plan is eight gates, four sub-gates (3A/3B/3C), and sixteen named CI jobs.
It is a good plan that is becoming comprehensive faster than it is being
executed — which is the diagnosis it makes about the PRD.

Add an explicit critical path near the top:

```text
Gate 0  → skips fatal → Gate 1 (properly) → Gate 2 → Gate 4 → Gate 7
```

That sequence produces one trustworthy dialect with honest claims and nothing
else. Everything else — 3A, 3B, 3C, 5, 6, 8 — is parallel work or later work.
Saying so protects the next agent from reading the plan as a menu, which is how
nine phases got closed in six commits the first time.

### 3.3 Gate 6 is mis-sized for the list it is in

A test-only instrumented `lvm.c` that logs per-instruction register reads and
writes is the correct answer to the semantic-verification problem, and it is
the largest single piece of work in the document. It does not belong in the
same numbered sequence as "fix the immediate-dominator predicate."

Break it out as its own project with its own schedule. In the interim, take the
plan's own escape hatch immediately rather than at Gate 6 time: downgrade the
effect-related claims in `capabilities` and `README.md` now. Effects are
currently presented with `Confidence: Fact` and `lvm.c` line citations that
carry no version pin and no verification. That combination is worse than
silence.

## 4. Strategic: the field report changes the picture and the plan has not absorbed it

This is the most important item in this document.

A peer project ran `luad` against 252 real firmware files. That is the first
genuine signal about what this tool is for, and it says three things:

1. The corpus is **Lua 5.1, embedded, vendor-patched (LNUM)** — not 5.4, not 5.5.
2. The blocking defects were **layout portability** (a discarded 32-bit
   `size_t`) and **constant resolution** — not opcode semantics.
3. The researcher's largest reported time cost was that `LOADK 20 24` does not
   show the string. That is a rendering gap, not a correctness gap.

The dialect order in the plan and roadmap remains 5.4 → 5.5 → 5.1 → 5.3 → 5.2,
inherited from the PRD. The field evidence argues against it.

**Recommendation: keep 5.4 first, but say why, and change what follows from it.**

5.4 remains the right first target because it is the one dialect with a
trustworthy modern oracle and no host-representation variance to confound the
first vertical slice. But the plan should state plainly:

> Lua 5.4 is the proof vehicle. Embedded Lua 5.1 is the product.

Two consequences follow:

### 4.1 Layout handling is an architectural invariant, not a Lua 5.1 sub-gate

Gate 3A is scoped as "prove embedded Lua 5.1 layouts and profiles." The defect
it responds to is a class defect, not a 5.1 defect: a parser read a fixed-width
field without consulting the chunk's declared representation. Any dialect can
make that mistake, and the ones most likely to encounter it are exactly the
embedded targets the field report points at.

Move the invariant into `ARCHITECTURE.md` and enforce it in the type system.
`SafeReader` should not expose a bare `read_u64` at all — only
`read_size_t(&layout)`, `read_int(&layout)`, `read_instruction(&layout)`, and
so on. Then the 5.1 fix is a consequence of the architecture rather than a
point patch, and the same bug cannot be reintroduced in the LuaJIT front end
two years from now.

### 4.2 Answer the positioning question now

The plan defers it: "Before expanding beyond 5.4/5.5, resolve the
product-positioning decision in `ROADMAP.md`." The field report has effectively
resolved it. Real Lua bytecode lives in firmware, games, and embedded runtimes.
That means:

- LuaJIT moves up the roadmap, ahead of Lua 5.2 and probably ahead of 5.3.
- Lua 5.2 likely never ships, and that is fine — say so rather than carrying it.
- Constant resolution (Gate 3C) and closure capture relations (Gate 3B) are not
  polish; they are the two things a real user asked for. They deserve to be on
  the critical path rather than in the 3-series.

Write the decision into `PRD.md` §2.1 rather than leaving it as an open
question in a roadmap.

## 5. Claim hygiene is already slipping again

Gate 0 cleaned the manifest. Two things have since re-entered it.

- **`capabilities` now lists `32-bit/64-bit size_t support` and `LNUM integer
  constants` as Lua 5.1 features.** Both rest on the field report, not a passing
  gate. The support *tier* is correctly `experimental`, but the feature list is
  a claim surface too, and it is currently the least-verified text in the
  manifest. Hold feature strings to the same evidence rule as tiers.
- **`54e4b8d` merged ahead of `gate-layout-lua51-32`.** The fix is almost
  certainly right and the operational pressure was real, but the roadmap's own
  rule was suspended without being named. If urgent field fixes may land ahead
  of their gate — and they should be able to — write that exception into
  `ROADMAP.md` with a required follow-up gate ID, rather than leaving the
  precedent implicit.

**On LNUM specifically.** Accepting constant tag 9 so that a corpus stops
erroring is PRD §15's "permissive parsing looks authoritative" risk arriving on
schedule. Gate 3A catches it in one clause. Make it stronger and put it in the
roadmap: **the LNUM profile requires its own oracle — a built LNUM-patched
`luac` — or it remains `experimental` permanently.** A parser was broadened on
the strength of one corpus that stopped throwing, and that is not evidence of
correctness.

Relatedly: "252/252 parse and validate" now appears in three documents. Given
that the Lua 5.4 oracle passes while the decoder produces wrong operands,
"parses and validates" currently certifies very little. The field report says
this well in one sentence; make sure the number never travels without it.

## 6. Composable proposal — remaining notes

The deferral and the revisions are right. Three things to settle before it
un-freezes:

- **`export` should be specified before `get`, even if `get` ships first.** The
  export record shape is the union of everything `get` can return; designing
  `get` first risks a per-object schema that does not compose into a stream.
- **`explain` as a renderer over `get`** is the correct call and should be
  written into `ARCHITECTURE.md` now, while `explain` is still cheap to move.
- **Overlay strings are an untrusted input path.** A shared research overlay is
  attacker-supplied data reaching a terminal and DOT output. State explicitly
  that overlay text passes through the same control-character and bidi escaping
  as chunk strings (§9.2). The proposal bounds size and depth but does not say
  this.

## 7. Summary of recommended amendments

| # | Change | Where |
|---|---|---|
| 1 | Operating rule 10: acceptance criteria as committed tests; CI fails if a gate's named test is absent | `CODING-AGENT-PLAN.md` |
| 2 | Promote "oracle skips are fatal" out of Gate 3 to Gate 0.5 | `CODING-AGENT-PLAN.md`, `ROADMAP.md` |
| 3 | State the critical path explicitly; mark the rest parallel or later | `CODING-AGENT-PLAN.md` |
| 4 | Split Gate 6 into its own project; downgrade effect claims now | `CODING-AGENT-PLAN.md`, `capabilities`, `README.md` |
| 5 | "5.4 is the proof vehicle, embedded 5.1 is the product" | `ROADMAP.md`, `PRD.md` §2.1 |
| 6 | Layout-aware reads as an architectural invariant enforced by `SafeReader`'s API | `ARCHITECTURE.md`, Gate 3A |
| 7 | Resolve positioning: LuaJIT up, 5.2 out | `PRD.md` §2.1, `ROADMAP.md` |
| 8 | Feature strings held to the same evidence rule as support tiers | Gate 0 / Gate 7 |
| 9 | Named exception for urgent field fixes landing ahead of their gate | `ROADMAP.md` |
| 10 | LNUM requires its own oracle or stays experimental permanently | `ROADMAP.md`, Gate 3A |
| 11 | Specify `export` before `get`; move `explain`-as-renderer into architecture; state overlay escaping | Composable proposal, `ARCHITECTURE.md` |

---

The direction is right and the documentation set is now stronger than the code
it describes, which is the correct order to be wrong in. The one thing to watch
is that the lesson from the review did not fully transfer on its first
application: Gate 1 was closed with its central comparison missing. That is
ordinary, and catching it at Gate 1 rather than Gate 7 is what the gate
structure is for. The amendments above are aimed at making the structure catch
it without a human reading the diff.
