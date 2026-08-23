# Evidence-gated development workflow

Status: authoritative development process. The transition in section 10 applies
until the current broad coding plan is closed.

This workflow separates product direction, acceptance design, implementation, and
release decisions. Its purpose is to make each claim small enough to verify and to
prevent a green test name or persuasive walkthrough from substituting for evidence.

## 1. Operating model

Development uses two forward-looking planning documents after the current transition:

1. `ROADMAP.md` describes important product capabilities, their order, dependencies,
   and broad exit outcomes. It does not prescribe production structs, filenames, or
   implementation techniques.
2. `docs/NEXT-SPRINT.md` describes exactly one active, bounded unit of work. It owns
   the public claim, non-goals, fixtures, authorities, acceptance tests, mutation
   probes, canonical gate, and checkpoint handoff.

There is never more than one active sprint document. After acceptance, durable history
lives in code, tests, gate artifacts, release evidence, and `CHANGELOG.md`; the sprint
document is replaced with the next forward-looking sprint rather than accumulated as
an obsolete plan.

The roadmap answers **what matters next**. The sprint answers **what exact claim is
eligible for acceptance now**. Neither document may claim that unverified work is
already supported.

## 2. Roles and separation of responsibility

### Product and acceptance steward

The steward:

- maintains the roadmap and active sprint contract;
- chooses the next smallest useful product claim;
- reviews and freezes acceptance tests before production implementation;
- controls changes to sprint scope, public fixtures, canonical gate specifications,
  and acceptance tests;
- independently executes public-boundary probes and the canonical gate;
- accepts or rejects the checkpoint based on evidence from one clean revision.

The steward does not accept a phase name, test name, commit message, aggregate test
count, or implementation-agent walkthrough as proof.

### Independent acceptance-test author

The test author works from the last accepted revision plus the sprint contract, before
seeing the implementation. Its job is to encode the promised public behavior and the
ways a superficially plausible implementation could be wrong.

The test author may change only the sprint-owned acceptance tests, independent oracle,
fixtures and provenance, gate specification, and sprint-specific gate wrapper. It
must not alter the shared proof harness or gate runner, and it must not implement
production behavior. It records the expected red result and demonstrates that each
mutation probe rejects the targeted defect.

Model diversity is preferred here because it reduces correlated interpretation errors.
The default test-author role uses Claude Code with the current `opus` alias at high
effort. The evidence handoff records the CLI version and resolved model identity; an
alias is not itself a reproducibility claim.

### Implementation agent

The implementation agent receives the frozen sprint contract and acceptance commit.
It may choose the production design within the stated architecture and non-goals. It
may add production code and ordinary unit tests, but it may not modify or bypass:

- the active sprint's public claim or non-goals;
- frozen acceptance tests or their independent oracle;
- fixture bytes, hashes, or provenance;
- the sprint-specific gate specification or wrapper, or the shared proof harness and
  gate runner;
- required compiler checks, clean-tree checks, negative controls, or expected tests.

If the contract is inconsistent or the acceptance test is defective, the agent stops
and submits a narrowly explained change request. It does not silently redefine the
claim. The default implementation role uses Antigravity with
`gemini-3.7-flash-high`, high effort, and an isolated worktree.

### Acceptance reviewer

The steward performs final acceptance in a fresh context. A separate review model may
be consulted, but it cannot promote the sprint. The reviewer starts with black-box CLI
behavior and only then inspects implementation details and test coverage.

## 3. Required sprint contract

`docs/NEXT-SPRINT.md` must be short enough to review as a single contract and contain:

1. **Claim** — one externally observable capability stated without implementation
   language.
2. **Researcher value** — the concrete human or agent workflow it enables.
3. **Starting evidence** — the accepted revision and relevant existing gates.
4. **Non-goals** — adjacent work that is explicitly ineligible for this sprint.
5. **Public examples** — exact commands, exit codes, stdout shape, and stderr behavior.
6. **Fixture matrix** — paths, hashes, provenance, layouts/profiles, and why each case
   exists.
7. **Independent authority** — official listing, separately transcribed decoder,
   specification-derived golden, or another source that does not share production
   logic.
8. **Acceptance assertions** — facts compared at the public boundary.
9. **Killer mutations** — one-field changes that must be detected and the expected
   rejection reason.
10. **Canonical gate** — one exact script, specification, and prerequisite closure.
11. **Handoff** — required clean commit, artifact directory, hashes, command logs,
    skips, environment identity, and known limitations.
12. **Stop condition** — no downstream roadmap work begins before acceptance.

Avoid implementation prescriptions unless they protect an architectural invariant.
For example, requiring typed encoded operands is appropriate; requiring a particular
Rust helper name usually is not.

## 4. Acceptance-test design

Acceptance tests are written and reviewed before production work begins.

They must:

- invoke the public CLI or deserialize the public schema whenever the claim is public;
- compare complete semantic content, not only record counts or field presence;
- recurse through all relevant prototypes and fixtures;
- use an authority independent of the production decoder;
- fail when a required field is removed or changed;
- prove that text and machine forms carry the same underlying facts where claimed;
- include malformed and boundary cases without permitting silent skips;
- pin fixture and tool identities required by the claim;
- produce a red result for the intended missing behavior before implementation.

A test is not a killer probe merely because its name says `killer`. It must apply the
mutation to otherwise-valid output or evidence and demonstrate that the comparator,
schema, or gate rejects it. Assertions about a hand-constructed unrelated object do
not qualify.

The steward reviews tests for vacuous loops, shared production code on both sides of a
comparison, assertions that check only existence or counts, and mutations that never
reach the comparator. Only then is the acceptance commit frozen.

## 5. Gate standard

A canonical sprint gate is manipulation-resistant rather than literally ungameable.
It must:

- name one unique gate ID and map to one script/specification pair;
- enumerate the exact acceptance tests and reject missing, ignored, filtered, or
  zero-test execution;
- declare the real prerequisite gates from the roadmap dependency graph;
- pin all public fixtures and required compiler/profile identities;
- execute positive comparisons and adversarial mutations;
- reject dirty, stale, cross-revision, tampered, or substituted results;
- emit a result package tied to one clean Git commit;
- keep compiler absence, fixture absence, and unsupported profiles as hard failures;
- make target profile/layout identity explicit in release evidence;
- avoid treating `scripts/check.sh` as semantic proof.

The implementation agent may report a narrow test result while iterating. It may use
the word `PASSED` for the canonical gate only when the actual gate script succeeds from
the clean candidate revision and the resulting artifacts are available for review.

## 6. Worktree and branch isolation

Use separate Git worktrees so agents do not edit the same files or inherit unrelated
dirty state:

```text
accepted revision
  -> sprint/<id>-acceptance   independent tests and gate, frozen first
       -> sprint/<id>-impl    production implementation based on acceptance commit
```

The steward creates and validates worktrees. Agents do not reuse a developer's dirty
working directory. Before an agent starts, record:

- base commit;
- worktree path and branch;
- allowed file set;
- forbidden file set;
- model and CLI version;
- sprint contract hash.

The acceptance author does not see an implementation diff. The implementation agent
does see the frozen tests. Final review uses a fresh session and the complete diff from
the accepted base.

## 7. CLI orchestration

The installed interfaces inspected on 2026-08-23 are:

- Claude Code `2.1.241`, available as `claude`;
- Antigravity CLI `1.1.19`, available as `agy`;
- Antigravity model ID `gemini-3.7-flash-high` for Gemini 3.7 Flash (High).

These versions are observations, not permanent requirements. Every sprint handoff
records the versions actually used.

### Claude acceptance author

Claude supports non-interactive print mode, `--model`, `--effort`, structured JSON or
streaming output, JSON-schema-constrained final output, tool allowlists, permission
modes, resumable sessions, and native `--worktree` creation. The steward normally
creates the worktree explicitly so both providers follow the same isolation model.

Representative invocation from the acceptance worktree:

```console
claude -p \
  --model opus \
  --effort high \
  --permission-mode acceptEdits \
  --allowedTools "Read,Glob,Grep,Edit,Write,Bash(cargo test *),Bash(git diff *),Bash(git status *)" \
  --output-format json \
  --no-session-persistence \
  "Author only the frozen acceptance tests and gate described in docs/NEXT-SPRINT.md. Do not implement production behavior."
```

Do not use `--dangerously-skip-permissions`. For a read-only critique, use plan mode
and a read-only tool allowlist. When structured handoff automation is enabled, pass a
reviewed JSON Schema through `--json-schema`.

### Antigravity implementation agent

Antigravity supports non-interactive print mode, exact model and effort selection,
`plan` and `accept-edits` execution modes, sandboxed terminal use, structured JSON or
streaming output, JSON-schema-constrained final output, timeouts, and resumable
conversations.

Representative invocation from the implementation worktree:

```console
agy -p \
  --model gemini-3.7-flash-high \
  --effort high \
  --mode accept-edits \
  --sandbox \
  --output-format json \
  --print-timeout 30m \
  "Implement only docs/NEXT-SPRINT.md against the frozen acceptance commit. Do not edit the sprint contract, acceptance tests, fixtures, sprint gate, or shared proof harness. Stop after the checkpoint handoff."
```

`agy` starts a local helper and writes logs beneath its Antigravity configuration
directory. In a managed outer sandbox it may require explicit permission for those
operations and its localhost listener. Never compensate by disabling repository or
agent safety controls globally.

For both tools, prompts should identify the exact sprint document, base and acceptance
commits, allowed paths, forbidden paths, required gate, and stop condition. Store the
prompt text or its SHA-256 with the handoff when reproducibility matters.

## 8. Sprint lifecycle

### Step 1: select

The steward chooses the smallest roadmap item that produces independently observable
researcher value. If it cannot be stated as one claim, split it.

### Step 2: specify

Write `docs/NEXT-SPRINT.md`. Resolve ambiguity before test or implementation work.

### Step 3: author acceptance

The independent test author creates public-boundary tests, fixtures, oracle code,
mutation probes, and the gate. The steward reviews their epistemic strength, runs the
expected red result, and freezes the acceptance commit.

### Step 4: implement

The implementation agent changes production code and ordinary unit tests only. It
runs narrow tests while iterating and stops at the sprint checkpoint.

### Step 5: produce candidate evidence

The steward reviews the diff for scope and frozen-file changes. After correcting any
approved issues, create one clean candidate commit and run the canonical gate into a
fresh artifact directory. Run `scripts/check.sh` separately.

### Step 6: accept or return

Acceptance requires all of:

- the black-box examples behave exactly as specified;
- the independent comparison and every killer mutation pass;
- the canonical clean-revision gate passes with no skips;
- aggregate repository checks pass;
- documentation and capabilities do not overclaim;
- the implementation diff contains no unauthorized acceptance-test weakening;
- the handoff artifact is complete and independently reproducible.

If rejected, return a bounded defect list against the same sprint. Do not expand the
sprint or review unrelated downstream work.

### Step 7: advance

After acceptance, update `ROADMAP.md`, replace `docs/NEXT-SPRINT.md` with the next
contract, and begin again from the newly accepted revision.

## 9. Handoff format

Each implementation handoff reports facts, not a completion essay:

```text
sprint ID and claim
base commit
acceptance-test commit
candidate implementation commit
clean: true|false
changed production paths
frozen paths unchanged: true|false
canonical gate command and exit code
gate artifact directory and manifest hash
tests passed/failed/ignored/missing
fixture/compiler/profile identities
scripts/check.sh result
known limitations within the sprint claim
```

The reviewer may reject a handoff without examining code when the candidate is dirty,
the frozen paths changed without approval, required evidence is absent, or the
canonical gate was not actually executed.

## 10. Transition from the current broad sprint

`docs/CODING-AGENT-PLAN.md` remains the sole active implementation plan while its
existing broad sprint is brought to an honest clean conclusion. The new roadmap/sprint
pair does not become active midstream.

For this one transition:

1. Preserve the current implementation work; do not discard useful prototypes.
2. Correct the outstanding public-boundary and proof defects against the existing
   plan without adding new scope.
3. Produce one clean candidate revision and run the actual canonical gates.
4. Independently review the evidence and either accept the current sprint or explicitly
   downgrade unfinished surfaces to roadmap work.
5. Once the repository is clean and its claims are honest, replace
   `docs/CODING-AGENT-PLAN.md` with a high-level `ROADMAP.md` and one
   `docs/NEXT-SPRINT.md`.
6. Update all documentation links so there is no competing active implementation plan.

During this transition, the current coding agent may finish the current sprint. Claude
and Antigravity assume their separated test-author and implementer roles beginning with
the first `NEXT-SPRINT` cycle.

## 11. Documentation lifecycle

The root README indexes every maintained Markdown document with its purpose, last-fresh
date, and revalidation or deletion trigger. Documentation work is incomplete until the
index and all inbound links agree with the file set.

Roadmaps and sprint plans describe only future claims, dependencies, tests, gates, and
stop conditions. Acceptance replaces the active sprint instead of marking its items
complete. Product history belongs in the changelog, release notes, pull requests, and
commits—not in the next plan.

Requirements, architecture, security, and interface documents describe present truth
and future constraints. Code comments follow the same present-state rule: they explain
what is invariant and why it matters without comparing the code with an earlier
implementation.

When a freshness trigger fires, the owning change updates or deletes the affected
document. Deletion also removes its index entry and repairs all references.

## 12. Escalation rules

- A defective acceptance test is fixed only through an explicit steward-approved test
  amendment, with the original red evidence retained.
- A sprint that requires a materially different public claim returns to specification;
  it is not patched through repeated implementation loops.
- Two repeated failures with the same root cause trigger a process review before
  another coding pass.
- Work that is useful but outside the claim returns to the roadmap and remains
  unpromoted.
- No agent may broaden authority from “finish the sprint” into releasing, publishing,
  pushing, deleting user work, or changing external systems.
