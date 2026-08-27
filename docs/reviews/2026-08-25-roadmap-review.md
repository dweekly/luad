# Roadmap and release-readiness review — 2026-08-25

Status: archived point-in-time planning provenance; not current release status or
executable evidence.

Indexed as of: 2026-08-27.

Deletion trigger: remove only when the project intentionally retires this planning
provenance and repairs the README index and inbound roadmap link.

Reviewer: Claude Fable (roadmap reviewer role, `docs/DEVELOPMENT-WORKFLOW.md` §3).

Reviewed at commit `9fba53f`, against `ROADMAP.md`, `docs/NEXT-SPRINT.md`, `PRD.md`,
`docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md`, `docs/DEVELOPMENT-WORKFLOW.md`,
`docs/RELEASING.md`, `docs/LUA51-LNUM32-CANDIDATE.md`, `AGENTS.md`, and `README.md`,
plus a code audit of the current tree.

This is a point-in-time review artifact, not a maintained statement of current truth.
It appears in the `README.md` documentation index so the exploration remains
discoverable without being mistaken for the active roadmap. Current obligations and
ordering live only in `ROADMAP.md` and `docs/NEXT-SPRINT.md`.

"Public release" is read here as promoting `lua5.1-lnum32` and publishing verified
artifacts, since the repository is already public. The "latest evidence" is read as the
corpus statistics that landed in `docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md` §"Current
corpus sizing facts" alongside the reprioritization in `9fba53f`.

---

## Verdict

**The top-ranked item is right and well-derived, but the roadmap is a product-facts
roadmap wearing the label of a release plan.** Every checkpoint in Phase 1 concerns
analysis correctness. Everything else that blocks publishing — robustness evidence, a
working evidence manifest, publication mechanics — lives in `docs/RELEASING.md`
preconditions and `PRD.md` §13.1 and never enters the sequenced plan. The roadmap looks
complete; the release is not.

Credit where due, because it sharpens the contrast: the audit found zero `unsafe`, zero
reachable `panic!`/`unwrap`/`TODO` in roughly 34k lines of production parser code, and a
`safe_capacity` design (`crates/luad-core/src/reader.rs:120-128`) that correctly refuses
to trust header-declared counts for allocation. The documentation is unusually honest —
`docs/RELEASING.md` opens with an explicit release stop, and the PERF gap is stated
plainly rather than papered over. The correctness discipline is excellent. The release
discipline is the gap, and that is a much easier problem.

---

## Blocks promotion

### 1. Open-window callee correction — correctly ranked first; make the replay falsifiable

Endorsed without reservation. The evidence supports it precisely: 1,220 of the 1,272
unresolved calls have a defining opcode the analysis already handles. Roughly 96% of the
residual unresolved set is a false negative, not genuine dynamism. The failure mode is
the worst kind for this product — a confident negative. A consumer reads
`open-register-window` as "this target is not statically determinable" and either skips
the call site or classifies it as dynamic dispatch. Both are wrong conclusions delivered
with the tool's authority. `README.md` and `docs/LUA51-LNUM32-CANDIDATE.md` already say
this.

**Recommendation: pre-register the expected corpus number before the replay runs.** The
sprint's evidence is one fixture shape plus focused tests, which is right for
correctness, but the customer-replay checkpoint carries no numeric expectation. Record
now that `open-register-window` should fall from 1,272 to approximately 50, and that
every survivor must have a defining opcode outside the handled set. If the replay
returns 900, that is a second defect; without a pre-registered number it will be
rationalized as a large improvement. Cost: one sentence in `docs/NEXT-SPRINT.md`.

### 2. Fuzzing is a release criterion that has never run; the analysis layer has zero coverage

Facts from the audit:

- Six fuzz targets exist and **all six stop at parse**. Each constructs a `SafeReader`
  and calls `parse_chunk`. Nothing fuzzes `callees`, `origins`, `callgraph`, `query`,
  `export`, `cfg`, or any renderer.
- `scripts/check.sh:31` runs `cargo check --manifest-path fuzz/Cargo.toml`. That
  compiles the targets. It never runs them.
- `.github/workflows/ci.yml` contains zero fuzz references. No scheduled job, no smoke
  stage.
- The corpus is exactly 10 hand-made seed fixtures per target — no campaign-discovered
  inputs, no minimized crashes.

Against that: `PRD.md` §9.3 requires targets for "detection, every chunk decoder,
instruction decoding, validation, text rendering, and JSON rendering," plus "CI runs a
bounded smoke-fuzz stage," plus published campaign duration at release. §13.1 makes
"maintained fuzz coverage" a first-RC requirement. `docs/RELEASING.md` precondition 6
says to run "configured time-bounded fuzz jobs" — none are configured.
`CONTRIBUTING.md:73` lists "persistent coverage-guided fuzzing" as a live test category.

The gap is not administrative. `luad-analysis` is 7,395 source lines: the largest
non-oracle crate, the newest code, the most algorithmically complex (dataflow across
control-flow joins, alias resolution, closure-capture chains, cycle-safe traversal), and
it consumes attacker-controlled bytecode. It is the code most likely to hold a reachable
defect and the only major subsystem with no fuzz coverage at all. A firmware analyst
points this at an unknown vendor blob; that is the entire pitch.

The roadmap's three Phase 1 checkpoints do not mention robustness once.

**Recommendation: add a fourth Phase 1 checkpoint between the callee fix and promotion.**
An analysis-layer fuzz target (parse, then drive callees/origins/callgraph/query/export
over the parsed chunk), a bounded smoke-fuzz stage in CI, and one time-boxed extended
campaign whose configuration and duration enter the evidence bundle. Days, not a research
project.

### 3. The evidence manifest does not work, and promotion depends on it

`luad capabilities --format json --evidence` on current `main` returns
`"completed_gates": []` for **every** dialect, including `lua5.1` with its eight named
required gates that `CHANGELOG.md` says pass. The manifest also omits nearly everything
`PRD.md` §10.7 requires of the coverage manifest: no oracle/compiler versions, no opcode
semantic coverage percentage, no fixture counts, no differential results, no host
platforms, no fuzz summary, no known-limitations list.

Two release preconditions are therefore unexecutable. `docs/RELEASING.md` step 7 says
review the manifest "against actual gate results" — there are none in it. Step 8 says
README support status must be "generated from or identical to the evidence manifest" —
it cannot be. `PRD.md` §13.1 requires "capability status derived from one verified
release manifest." `ROADMAP.md` Phase 1 step 3 says "promote only `lua5.1-lnum32` from
the accepted evidence bundle" as though the mechanism exists.

A second edge matters more given the latest evidence came from a model. `PRD.md` §6.2
says `capabilities` reports "commands, schemas, diagnostic catalog, and features," and
the AI-agent workflow in §4.2 makes `capabilities --format json` step one, to discover
"dialects, commands, schemas, and limits." The live output has dialects and a diagnostic
catalog. There is no commands list and no schemas list. (Limits are fine — they ride in
every response envelope, just not here.) The primary machine consumer's documented entry
point does not answer the questions the documentation says it answers.

**Recommendation: wire the manifest to real gate results before promotion, not at
promotion. Add the commands and schemas lists.**

### 4. Publication is mechanically impossible today

`docs/RELEASING.md` is candid that crates.io order, binary channel, signing, checksums,
and rollback are undefined. Beyond that, the audit found concrete mechanical blockers:

- **No crate manifest has a `description` field.** `cargo publish` rejects on that
  alone. Same for `readme`, `keywords`, `categories`.
- No git tags exist. No release workflow. The only CI artifact is a run-scoped
  `candidate-evidence-bundle`, not a release.
- MSRV is explicitly unestablished (`README.md:109`); the toolchain is pinned at 1.97.1
  in both CI matrix legs, so there is no stable-versus-MSRV signal.
- No `cargo audit` or `cargo deny`, and `PRD.md` §13.2 requires an SBOM for 1.0 with
  nothing sequencing it.

None of this is hard. All of it will be discovered on release day if it is not named in
the plan now.

**Recommendation: name publication mechanics as an explicit Phase 1 item.**

### 5. `max_string_bytes` does not bind on the release target

`max_string_bytes` (16 MiB) is enforced only in `crates/luad-core/src/reader.rs:344`,
inside the Lua 5.4 string reader. Lua 5.1's `load_string_51`
(`crates/luad-dialect-lua51/src/chunk.rs:122-145`) reads the declared `size_t` and calls
`read_exact(size)` with no limit check. Same for 5.2, 5.3, and 5.5.

Practical impact is contained — `read_exact` cannot read past actual input, and the CLI
caps input at 64 MiB — so this is not a denial of service. But `PRD.md` §9.2 lists string
length as a required defense, the limit is exposed as user-tunable configuration that
silently does nothing on the profile about to be promoted, and the diagnostic catalog
advertises a string-limit diagnostic (`L54-STR-001`) that only one dialect can emit. A
researcher who tightens the limit to bound memory gets no protection and no warning.

This is exactly the class of defect the promotion checkpoints will not catch, because
they are all about analysis correctness.

Relatedly: `#![forbid(unsafe_code)]` is present on all five dialect crates but absent
from `luad-core`, `luad-analysis`, `luad-cli`, and `luad-oracle` — including the crate
that owns the untrusted-byte reader. There is no actual `unsafe` anywhere, so this is a
one-line change per crate (or a workspace `[lints]` table) that makes the README's
"memory-safe" claim structurally enforced rather than incidentally true.

---

## Sequencing changes

### The dependency chain is needlessly serial and its long pole is a human

`ROADMAP.md` runs callee fix → replay → customer transfer → promotion → deeper facts.
Strictly serial. But the outside-human trial requires recruiting a person and waiting on
their schedule, and it gates everything behind it.

Blockers 2 through 5 above — fuzz infrastructure, evidence-manifest wiring, publication
mechanics, the string-limit fix — are all independent of the customer trial.
`docs/DEVELOPMENT-WORKFLOW.md` §9 already permits parallelism for slices with disjoint
paths and independent acceptance commands; these qualify cleanly.

**Recommendation: run them concurrently with the transfer wait rather than after it.** As
written, the plan implicitly idles during its longest-latency step.

### The outside-human trial has an unacknowledged failure mode

Phase 1 checkpoint 2 requires a trial "on different-vendor firmware." But the only
qualified profile is `lua5.1-lnum32` with layout `endian=1, sizet=4`, tag 9. A different
vendor plausibly ships stock 5.1 without LNUM, or LuaJIT, or — very commonly in embedded
— big-endian MIPS, which is outside the pinned layout entirely. In those cases `luad`
correctly refuses, the trial tests nothing about the claimed surface, and the one outside
human is spent. Conversely, firmware that does match LNUM32 is most likely another
OpenWrt/TP-Link-family device, which weakens the vendor independence the checkpoint
wanted.

**Recommendation: split the checkpoint into the two goals it conflates.**

- **In-profile transfer.** Pre-screen the candidate firmware with `inspect` before the
  trial starts and confirm it resolves to `lua5.1-lnum32`. Only then hand it over.
- **Out-of-profile refusal.** Verify that a non-matching vendor blob produces a correct,
  actionable "unsupported profile" diagnostic and the right exit code rather than a
  plausible misparse. This is arguably the more valuable test, it is cheap, and it can be
  done today with synthesized fixtures — no human required.

Also align the language: `ROADMAP.md` checkpoint 2 says "uncoached investigation," while
`docs/RELEASING.md` precondition 9 additionally requires "a different model family." The
roadmap is the looser of the pair and the one people will read.

### Fact-family selection is in the wrong phase

`docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md` records that a full export over the 252-file
tree is approximately 776 MB, that instruction and xref records are about 76% of it, and
that "consumers commonly need only callee, origin, relation, and prototype facts." The
documented consumer materializes 776 MB to use roughly 186 MB of it. Fact-family
selection sits at Phase 2 item 3 — after promotion.

`export` currently exposes only `--max-facts-per-file`, and there is no `--select`
anywhere in the CLI, despite `PRD.md` §7.4 listing `--select` as a requirement for "every
potentially large command." Count-truncation is the wrong tool here: it drops the tail
rather than the unwanted kind, so an agent can lose callee facts because instruction
facts consumed the budget first. That is a silent-loss failure mode in the bounded-output
contract, not merely friction.

The counterargument in the documents is fair — the customer completed the workflow, so
this is friction, and friction "blocks only when it prevents completion." Accepted for
promotion.

**Recommendation: move it to first position in Phase 2, and either implement `--select`
or downgrade `PRD.md` §7.4 from a description to a stated gap.** Given the primary
consumer is a context-budgeted agent, this is the highest-leverage item in Phase 2 by a
wide margin.

### Phase 2 item 1 will break the schema just promoted on

`docs/examples/origins.json` shows `origin` as a single object keyed by `kind`. Phase 2
item 1 replaces the single `control-flow-conflict` marker with a set of evidence-linked
alternatives. Under `PRD.md` §7.3 that is a meaning change to an existing field, which
requires a new schema major — and it silently stops matching for consumers branching on
`kind == "control-flow-conflict"`, which is 2,940 values per firmware tree.

The sequence as written promotes a target, tells consumers the contract is real, then
immediately breaks it for the most common unresolved-value case.

**Recommendation: state one of these in the roadmap.** Either the LNUM32 promotion
freezes the schema major for the fact families it promotes and Phase 2 must be additive
within it, or the promotion is explicitly not a schema-stability signal. The documents
currently do neither; `docs/RELEASING.md` only says pre-1.0 breaks require a major bump
without saying how many to expect.

### PERF-008: do not block on it, but do not skip the tripwire

The documents are honest that no timing or peak-memory evidence exists, and the audit
confirms it is total — no criterion, no `benches/`, no `Instant` in non-test code. This
does **not** block promotion, because the release claim is correctness and no performance
claim is being made.

The second-order cost is unpriced, though. Without a peak-memory number, it is unknown
whether firmware-tree `export` is safe on a modest machine, and there is no regression
detector for an accidental quadratic as Phase 2 lands origin alternatives and
table-literal origins — both of which expand traversal on the hottest paths.

**Recommendation: one recorded run over the redistributable fixture corpus under
`/usr/bin/time -l`, committed as a baseline, before Phase 2 starts.** An afternoon, and a
tripwire rather than a benchmark suite. Resist building the harness `PERF-007` implies.

---

## Missing from the roadmap entirely

### There is no reference external layer, and the architecture is betting on one

The architectural boundary — deterministic facts inside, judgment outside — is stated in
`README.md`, `PRD.md` §2.3, `ARCHITECTURE.md`, and the roadmap's exclusions, and it is
the right call. But Phase 1's exit outcome asserts it as achieved: "a human or AI agent
can complete the reference firmware workflows with the supported CLI and a thin external
judgment layer."

Nothing in the repository or the roadmap builds, ships, or specifies that layer. "Thin"
is never defined. The only evidence is anecdotal customer trials that are not recorded
in-repo. The project has written an extraordinarily rigorous account of what `luad` will
not do, and the boundary is only defensible once someone has demonstrated the other side
works.

**Recommendation: ship a worked example.** A few hundred lines — take `export` JSONL,
apply a naive sink list, emit candidate findings with evidence links back to stable IDs.
Not a product, an example. It does four things at once: puts a number on "thin," makes
`PRD.md` §14.3's "reference agent completes the standard workflow with zero human-text
scraping" measurable instead of aspirational, exercises the machine interface for real
before schemas freeze, and makes the project legible to an outsider in five minutes.
`docs/examples/RECIPES.md` is adjacent but it is recipes, not a worked investigation.

### Customer evidence is not durable, and no regression corpus exists

`docs/DEVELOPMENT-WORKFLOW.md` §3 says the customer researcher records commands,
adapters, and wrong answers. `ROADMAP.md` says each record identifies candidate hashes,
user and firmware context, commands attempted, outcomes, and minimized regressions.
**There is no such record anywhere in the repository and no named location for one.** The
aggregate corpus numbers reached `docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md`, which is the
right instinct, but the trial record itself — the commands, the wrong answers, the
workarounds — lives in a chat log.

Relatedly, the workflow says a reproducible correctness defect "becomes a minimized
public regression," but `tests/fixtures/` contains `authority/`, `embedded/`,
`precompiled/` and topical `.lua` files with no regression corpus. Either no defect has
been minimized yet, or the practice is not wired. Worth determining which.

**Recommendation: define `docs/customer-trials/<date>-<target>.md` with a fixed skeleton
and make "the record is committed" part of the checkpoint.** This is the
highest-signal artifact the project produces and it is the one not being kept.

### Phase 3 is ordered by version number, not by customer

"Stock Lua layouts, Lua 5.2, 5.3, 5.4, 5.5, LuaJIT, and vendor mappings advance one exact
target at a time" is numeric order, and it is the wrong order for the stated customer.

**Lua 5.4.8 is buried and it is the cheapest second promotion.** `README.md` says 5.4.8
already has normalized typed agreement with the official listing and an independent
decoder, plus public disassembly, validation, lossless, and machine-contract evidence;
the audit confirms `luad-dialect-lua54` is the most developed dialect after 5.1. It is
the second-most-finished thing in the repository and it sits behind an unranked list. The
promotion machinery has run exactly once, on a target where the steward built both the
tool and the authority. Promoting 5.4.8 next proves the machinery repeats, which is the
actual risk, and it is the target most likely to attract non-firmware users.

**LuaJIT is the expensive strategic decision and it is deferred without an argument.**
`PRD.md` §16.2 question 1 asks whether the next dialect investment optimizes for a
stock-Lua correctness reference or prevalent reverse-engineering ecosystems. The roadmap
neither answers it nor schedules the answer. In embedded and firmware RE specifically,
LuaJIT is far more prevalent than 5.2/5.3/5.5 combined. It is also not "one more dialect"
— new chunk model, new opcode semantics, and no `luac -l -l` oracle in the same form —
so it could consume the entire post-1.0 roadmap on its own. Deciding late is the
expensive way to decide.

**Recommendation: name 5.4.8 as target #2, and give LuaJIT an explicit scoping decision
rather than a position in a version-sorted list.**

### Nothing in the plan makes the tool obtainable

The destination state is entirely about facts and evidence. There is no install story
anywhere — no `cargo install`, no Homebrew, no release binaries for end users (the CI
artifacts are qualification evidence, not distribution). `PRD.md` §14.4 lists adoption
signals but the roadmap allocates zero work toward adoption. For a tool whose thesis is
that external agents and researchers compose these facts, that is a real omission.

**Recommendation: add a small "make it obtainable" item immediately after promotion.**

### Minor

`scripts/check.sh:10-17` — the contributor check `README.md` points every contributor to
asserts the maintainer's Gemini wrapper model-configuration string and exits 1 on
mismatch. It happens to work for outsiders because `config` is a pure echo, so it is not
a functional blocker. But baking internal AI-orchestration configuration into the public
quality gate is odd for a repository soliciting contributions, and it will break
confusingly the day the provider changes. Move it to a steward-only script.

Roughly 6 of the 44 gate scripts run explicitly in CI (the rest execute indirectly via
`cargo test --workspace`), and CI covers two little-endian platforms with no Windows and
no `cargo audit`. Neither blocks this promotion — the layout claim is pinned to
`endian=1` — but the fixture-matrix requirement in
`docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md` mentions "each architecture family claimed by
CI," and it is worth stating that big-endian is out of scope rather than merely untested.

---

## Summary of recommended plan changes

**Add to Phase 1**, parallel with the customer-transfer wait rather than after it:

- analysis-layer fuzz coverage, a CI smoke stage, and one recorded campaign;
- wire `completed_gates` and the coverage manifest to real gate results, and add the
  commands and schemas lists to `capabilities`;
- publication mechanics: crate metadata, tagging, checksums, MSRV, rollback;
- the `max_string_bytes` fix and workspace-wide `forbid(unsafe_code)`.

**Change in Phase 1:**

- pre-register the expected post-fix callee number;
- split the outside-human trial into in-profile transfer and out-of-profile refusal, with
  `inspect` pre-screening;
- align the roadmap's trial language with `docs/RELEASING.md`'s different-model-family
  requirement.

**Reorder Phase 2:**

- fact-family selection moves to first;
- state the schema-freeze policy before promotion, since origin alternatives will break
  the contract just promoted on.

**Add before Phase 2 starts:**

- one committed performance and memory baseline as a tripwire;
- a reference external layer as a worked example;
- a committed customer-trial record format.

**Rank Phase 3:**

- name 5.4.8 as target #2 to prove the promotion machinery repeats;
- give LuaJIT an explicit scoping decision rather than a position in a version-sorted
  list.
