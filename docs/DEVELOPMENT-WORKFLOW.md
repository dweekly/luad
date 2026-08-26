# Customer-outcome development workflow

Status: authoritative development process.

This workflow turns customer research needs into trustworthy product increments without
making orchestration a product of its own. The normal unit of delivery is one coherent
researcher outcome, implemented and tested together in one pull request. Independent
model review and separated proof construction are reserved for risks that require them.

## 1. Planning artifacts

Development uses two forward-looking plans:

1. [`ROADMAP.md`](../ROADMAP.md) states product outcomes, dependencies, ordering, and
   release boundaries. It does not prescribe implementation details or model roles.
2. [`NEXT-SPRINT.md`](NEXT-SPRINT.md) states the one active delivery contract. It names
   the customer outcome, public boundary, non-goals, evidence, allowed paths, and stop
   condition.

There is one active sprint contract. Acceptance replaces it with the next contract;
completed work belongs in code, tests, release evidence, `CHANGELOG.md`, pull requests,
and commits.

A sprint covers one useful workflow or one exhaustive semantic family. All variants
governed by the same authority and algorithm belong in one table-driven batch. Fields,
opcodes, record variants, and diagnostics are not separate sprints merely because they
can be enumerated separately.

## 2. Delivery lanes

The steward selects the least expensive lane that can falsify the claim.

### Product lane

This is the default. It covers localized fixes, complete enumerable families, public
records, CLI composition improvements, and bounded analysis capabilities.

A product-lane batch uses:

- one customer outcome;
- one worktree, branch, and pull request;
- one implementation session that writes production code and ordinary tests together;
- steward-owned focused verification and algorithmic review;
- existing gates and CI wherever they express the claim;
- at most one bounded implementation correction;
- external model review only when a named risk trigger applies.

A small patch is simply a small product-lane batch. It does not acquire a separate
acceptance branch, oracle, gate, or release manifest.

### Qualification lane

This lane covers exact target promotion, release candidates, schema-major transitions,
hostile-input containment boundaries, compiler or fixture authority, and release
attestation. It may separate acceptance authorship from implementation and may require
an independent oracle, frozen acceptance commit, mutation probes, and durable evidence
bundle.

Qualification proves a release claim. It does not become the default shape for product
development.

## 3. Roles

### Steward/controller

The steward owns product scope, the sprint contract, worktree boundaries, final
algorithmic review, verification, integration, and promotion. The steward:

- selects a customer outcome rather than an internal implementation fragment;
- supplies the implementation agent with the exact relevant context;
- runs tests, gates, Git operations, and CI;
- directly repairs routine Rust, build, schema-generation, packaging, and CI defects;
- rejects test weakening, scope expansion, and unsupported claims;
- decides whether an independent review is worth its latency;
- accepts only a clean revision whose remote state and evidence are verified.

The steward does not treat a walkthrough, model verdict, test name, aggregate count, or
provider runtime as proof of completion.

### Implementation agent

Gemini 3.7 Flash High at the High model variant is the default delegated implementation
agent. It receives a bounded contract, relevant source and test paths, architectural
invariants, and the focused expected behavior. It writes production code and ordinary
tests in the same persistent worktree session.

The agent does not change the claim, fixture provenance, support tier, accepted release
evidence, or shared proof harness. Routine non-interactive turns are edit-only; the
steward performs verification and Git operations. One resumed correction may address a
specific reviewed defect. A broader second pass requires rescoping the sprint.

### Independent reviewer

Claude Opus provides a bounded, tool-free review only when at least one of these risks
is present:

- a new semantic algorithm crosses control-flow joins, loops, aliases, or captures;
- a public schema-major, compatibility, or target-support claim changes;
- the acceptance authority has more than one plausible interpretation;
- malformed input creates a material containment or resource-boundary risk;
- the steward remains uncertain about correctness after inspecting the implementation;
- release qualification requires model-family-independent criticism.

The reviewer receives a curated packet containing the claim, exact relevant diff,
authority, and executed evidence. It returns one structured verdict. One follow-up is
allowed only when new bounded evidence answers a specific ambiguity.

Routine compiler failures, formatting, generated files, packaging, CI configuration,
and straightforward table coverage do not trigger Opus review. Opus does not routinely
author a second test suite.

### Roadmap reviewer

Claude Fable reviews product direction only after a substantial roadmap batch or at a
release boundary. It does not participate in individual sprints.

### Customer researcher

The customer researcher receives a candidate binary, public documentation, and a real
investigation objective. It does not receive the implementation diff, internal gate
checklist, or expected feature ranking. It records commands, elapsed work, custom
adapters, incorrect or ambiguous answers, and questions the tool could not answer.

Customer evidence prioritizes the roadmap and validates composition. Private firmware
and investigation-specific security judgments remain outside the repository. A
reproducible correctness failure becomes a minimized public regression.

## 4. Sprint contract

`docs/NEXT-SPRINT.md` stays short enough to review as one decision. A product-lane
contract contains:

1. **Outcome** — the concrete researcher question or workflow enabled.
2. **Public claim** — observable behavior, including command or library boundary.
3. **Scope** — affected subsystem and allowed paths.
4. **Non-goals** — adjacent behavior that remains outside the batch.
5. **Evidence** — the focused regression, authority, and existing gate or command.
6. **Stop condition** — the exact state eligible for review and integration.

A qualification contract additionally names exact fixtures and hashes, independent
authority, mutation probes, compiler/profile/layout identity, canonical gate, artifact
handoff, and promotion boundary.

Implementation details appear only when they protect an architectural invariant.
Requiring typed operands or stable evidence is appropriate; prescribing a private Rust
helper name is not.

## 5. Evidence standard

Tests are proportional to the public claim.

Product-lane evidence:

- exercises the public boundary when the behavior is public;
- compares semantic content rather than only counts or field presence;
- includes the boundary or negative case capable of exposing the likely defect;
- reuses accepted fixtures, authorities, comparators, and gates;
- fails rather than skips when a required fixture or tool is absent;
- keeps machine output deterministic and validates its typed representation.

An exhaustive table is appropriate when the claim is an exhaustive family. It belongs
in one table-driven test matrix rather than a sequence of nearly identical sprints.

New proof infrastructure requires a written explanation of the defect that existing
tests and gates cannot detect. A new helper, oracle, gate, schema, or manifest is not
justified by the desire to make an already-expressible claim look more formal.

Qualification evidence may require:

- an independent specification-derived decoder or official tool;
- frozen public-boundary acceptance before implementation;
- mutations proving the comparator rejects omission, substitution, or corruption;
- pinned fixture, compiler, profile, platform, and revision identities;
- a clean-revision evidence bundle retained outside temporary storage;
- prerequisite closure without duplicating prerequisite semantic suites.

The steward checks for vacuous loops, shared production logic on both sides of a
comparison, mutations that never reach the comparator, and assertions that verify only
presence or counts.

## 6. Product-lane lifecycle

1. **Select one outcome.** Prefer a complete researcher workflow or enumerable family
   over a small internal rule.
2. **Write the contract.** Name the public claim, focused evidence, non-goals, and stop
   condition.
3. **Create one isolated worktree.** Record the base commit, branch, allowed paths, and
   provider identity.
4. **Implement once.** Give Gemini the contract and relevant code. Production code and
   ordinary tests are one assignment and one continuous session.
5. **Review and verify.** The steward inspects the algorithm and scope, runs the narrow
   regression, and directly fixes routine integration defects. One bounded agent
   correction is available for a substantive implementation error.
6. **Run existing proof.** Execute the relevant established gate when one exists. Run
   the aggregate suite once locally or in CI; do not repeatedly run both without a
   diagnosed need.
7. **Integrate.** Commit, push one pull request, obtain green CI, merge, push, and verify
   remote `main`.
8. **Advance.** Replace the active contract and update indexed documentation whose
   freshness trigger fired.

An external review occurs between steps 5 and 6 only when a risk trigger in section 3
applies. Its findings become one bounded correction list; review does not restart after
routine corrections.

## 7. Qualification lifecycle

Qualification adds only the separation required by the release claim:

1. Write the exact target and promotion contract.
2. Obtain one bounded independent review of the authority and acceptance outline.
3. Freeze the minimum public acceptance evidence needed to expose a false claim.
4. Implement against that evidence without weakening it.
5. Produce one clean candidate revision and run the canonical gate into a fresh
   artifact directory.
6. Run the aggregate repository check once.
7. Review black-box behavior, mutation rejection, prerequisite identity, skips,
   artifact completeness, and documentation truthfulness.
8. Push, merge, verify remote `main`, and retain accepted evidence in CI or release
   storage.

Release closure proves identity, completeness, and authorized promotion. It references
accepted prerequisites rather than reimplementing their comparators.

## 8. Customer cadence

Customer checkpoints occur after every two or three related product batches, at a
roadmap boundary, and before target promotion. They interrupt sequencing immediately
for a silent incorrect answer.

The steward classifies feedback as:

- reproducible correctness defect;
- machine-interface or composition friction;
- missing deterministic VM fact;
- investigation-specific judgment that belongs outside `luad`.

The next batch removes the highest-cost repeated workaround that belongs inside the
product boundary. A successful private-corpus run supplements but never substitutes
for redistributable evidence.

## 9. Worktrees and parallelism

Every delegated edit uses an isolated Git worktree. Product work uses one branch and
one pull request. Qualification may use an acceptance branch followed by an
implementation branch when independence is material.

Serial execution is the default. Parallel work is eligible when slices have:

- disjoint production and test paths;
- independent acceptance commands;
- one immutable base revision;
- separate worktrees, branches, pull requests, and artifact directories;
- a deterministic integration order.

Read-only roadmap work may proceed beside an isolated coding task. Agents do not
resolve concurrent edits to shared schemas, fixtures, plans, gates, or release
manifests.

## 10. Provider interfaces

Repository wrappers are the canonical provider interface. Provider flags change in the
wrapper and this document together.

### Antigravity

```console
scripts/agents/agy-gemini.sh config
scripts/agents/agy-gemini.sh access
scripts/agents/agy-gemini.sh implement PROMPT_FILE
scripts/agents/agy-gemini.sh resume CONVERSATION_ID CORRECTION_PROMPT_FILE
```

The wrapper selects `gemini-3.7-flash-high`, the High model variant, the current Git
worktree, sandboxing, edit-only execution, and structured output. `access` reports the
effective workspace and permissions without starting a model task. Broad home-directory
grants and `--dangerously-skip-permissions` are prohibited.

Use one conversation for the batch. Resume it only for the single bounded correction.
The steward inspects the worktree after an interruption because an in-flight edit may
already be durable.

### Claude

```console
scripts/agents/claude-opus.sh design-review PROMPT_FILE
scripts/agents/claude-opus.sh review-fresh PROMPT_FILE
scripts/agents/claude-opus.sh review-start PROMPT_FILE
scripts/agents/claude-opus.sh review-resume SESSION_ID FOLLOWUP_PROMPT_FILE
```

The wrapper uses the logged-in Claude subscription, removes Console credentials,
selects Opus with the 1M context window, disables tools and MCP, and emits a structured
verdict with timing and usage. A fresh one-shot review is the default. A persistent
session is used only for one evidence-bearing follow-up.

Provider preflight verifies the resolved model, CLI version, authentication source,
allocation status, exposed tools, workspace grant, and successful inference. An
environment or permission failure is repaired directly; it does not consume a second
semantic review.

## 11. Time, usage, and process budget

End-to-end elapsed time starts with the first planning, delegation, or edit action and
ends when accepted work is verified on remote `main`. Provider runtime is reported
separately and is never presented as total sprint time.

At sprint close, record:

- end-to-end wall time and number of correction rounds;
- steward, Gemini, Opus, and other-model invocation counts and wall time;
- input, output, thinking, and cache tokens where exposed;
- failed permission, authentication, timeout, and CI attempts;
- focused-test, gate, aggregate-check, and CI duration;
- production, test, qualification, documentation, and operations diff sizes;
- customer workflow outcome and any remaining workaround.

Each wrapper's compact structured result is copied into the sprint artifact directory
when it contains timing or token usage. Raw prompts, transcripts, private firmware, and
provider debug logs are not committed. The close report aggregates the compact records
so a temporary log cleanup cannot erase the measurements.

Unavailable measurements are labeled unavailable. Subscription-equivalent prices are
usage observations, not spending ceilings.

For an ordinary product batch:

- one implementation invocation, one optional correction, one pull request, and one
  aggregate CI run are the normal ceiling;
- external review is limited to one risk-triggered verdict and one evidence-bearing
  follow-up;
- orchestration and qualification work should consume no more than roughly 25% of
  active wall time before cold CI;
- a test-to-production diff above 2:1 triggers a duplication and fixture-size review,
  but never motivates padding production code or deleting valuable tests;
- crossing a ceiling pauses orchestration for steward rescoping or direct repair rather
  than granting more agents, context, or ceremony.

The primary productivity measures are researcher workflows completed per wall-clock
day, silent-answer defects, escaped regressions, and correction rounds. Lines per hour
is a diagnostic for process imbalance, not a target.

## 12. Preservation, documentation, and escalation

After acceptance, push and merge the reviewed work, push `main`, and run
`scripts/verify-main-pushed.sh`. Temporary work is not accepted evidence until its
required artifacts are retained by CI, a pull request, or release storage.

The root README indexes every maintained Markdown document with its purpose, freshness
date, and revalidation or deletion trigger. Plans and roadmaps remain forward-looking.
Requirements and reference documents describe present truth and future constraints.
History belongs in `CHANGELOG.md`, releases, pull requests, and commits. Code comments
describe current invariants rather than earlier implementations.

Escalation rules:

- A materially different public claim returns to sprint specification.
- A defective frozen qualification test changes only through explicit steward review.
- Two failures with the same root cause trigger direct process repair before another
  agent pass.
- A silent incorrect answer blocks promotion and receives a minimized regression.
- Useful out-of-scope work returns to the roadmap without expanding the active batch.
- No model verdict can promote, publish, or release a target.
- A sprint is accepted only after its authorized revision is merged, pushed, and
  verified remotely.
