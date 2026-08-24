# Evidence-gated development workflow

Status: authoritative development process.

This workflow separates product direction, acceptance design, implementation, and
release decisions. Its purpose is to make each claim small enough to verify and to
prevent a green test name or persuasive walkthrough from substituting for evidence.

## 1. Operating model

Development uses two forward-looking planning documents:

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

A sprint normally owns one physical field, diagnostic family, output record, or other
single semantic distinction. If its claim needs multiple independent matrices,
diagnostic families, or public commands that could be accepted separately, split it
before acceptance work begins.

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

Acceptance authorship has two checkpoints. First, the author returns a read-only
acceptance outline naming the independent authority, minimum fixtures, positive
comparisons, killer mutations, expected red defect, and estimated test surface. The
steward approves or narrows that outline before edits are allowed. Second, the author
produces the first durable red test and diff before expanding the suite. An author that
cannot reach either checkpoint stops without changing the sprint claim.

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

The contract uses the minimum fixture and command set needed to distinguish the claim.
Exhaustive coverage is appropriate when the claim itself is an exhaustive table; it is
not a default requirement for a bounded correction.

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

### Proportional evidence levels

Select the least expensive level that can falsify the claim:

- **Bounded correction:** one public regression, one independently derived expected
  value or boundary pair, and two to four targeted killer mutations.
- **Semantic matrix:** exhaustive independently owned rows for a dialect field,
  opcode family, schema union, or similarly enumerable subsystem, plus mutations for
  omission, misclassification, and boundaries.
- **Target promotion:** full public-command closure, exact compiler/profile/layout
  identity, corpus and adversarial evidence, prerequisite manifests, and release
  artifacts.

Moving to a larger level requires a larger public claim, not merely a desire for more
tests. Acceptance helpers should remain narrower than the production subsystem they
judge. If the oracle becomes a second general implementation, reduce the sprint or
justify that duplication as target-promotion evidence.

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

Development artifacts may live in a fresh temporary directory. An accepted gate's
result, specification, hashes, and command log must be retained by a pull request, CI
artifact, or release-evidence bundle before the temporary directory is discarded.

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

Each role works on its own branch and reviewable pull request when a remote review
surface is available. The acceptance branch freezes before the implementation branch
is created. Shared planning documents, gate infrastructure, schemas, fixtures, and
release manifests have one steward owner; agents do not resolve concurrent edits to
those paths themselves.

### Parallel execution threshold

Serial execution is the default. Parallel work is eligible only when the steward can
write a dependency graph showing that the slices have disjoint production and
acceptance paths, independent gates, a common immutable base, and a deterministic
integration order. Each slice receives a separate worktree, branch, pull request,
allowed-path set, and artifact directory. One agent may not author acceptance for a
slice whose implementation it has seen.

Read-only roadmap refinement may proceed beside an isolated coding slice. Concurrent
code or test authorship waits until the controller can prove non-overlap; anticipated
speedup alone is not sufficient authority to parallelize.

## 7. CLI orchestration

The installed interfaces inspected on 2026-08-23 are:

- Claude Code `2.1.241`, available as `claude`;
- Antigravity CLI `1.1.19`, available as `agy`;
- Antigravity model ID `gemini-3.7-flash-high` for Gemini 3.7 Flash (High).

These versions are observations, not permanent requirements. Every sprint handoff
records the versions actually used.

### Provider preflight

Before delegating repository work, run a tool-disabled smoke request and confirm from
machine output:

- resolved canonical model, CLI version, and intended authentication source;
- successful inference with no permission or OAuth-lock errors;
- allocation or rate-limit status, overage status, and termination reason;
- the exact built-in and MCP tool set exposed to the session.

Then run a read-only repository probe with the intended mode and allowlist. Managed
sandboxes must explicitly permit the provider's configuration directory and local
helper when required. A request that never reaches inference is an environment failure,
not a model or budget failure.

For a Claude Pro or Max subscription, remove `ANTHROPIC_API_KEY`,
`ANTHROPIC_AUTH_TOKEN`, and other Console or gateway credentials from the invocation
environment. `claude auth status --json` must report `authMethod: claude.ai`. The init
event must report `apiKeySource: none`, and the rate-limit event must report
`isUsingOverage: false`. A reported `total_cost_usd` is an API-equivalent usage estimate
in this mode, not a workflow spending ceiling. Console PAYG is a separate, explicitly
selected mode.

### Claude acceptance author

Claude supports non-interactive print mode, `--model`, `--effort`, structured JSON or
streaming output, JSON-schema-constrained final output, tool allowlists, permission
modes, resumable sessions, and native `--worktree` creation. The steward normally
creates the worktree explicitly so both providers follow the same isolation model.

Use a staged invocation. The read-only outline stage is deliberately inexpensive and
has no edit or shell tools:

```console
env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN \
  claude -p \
  --safe-mode \
  --strict-mcp-config \
  --mcp-config '{"mcpServers":{}}' \
  --model opus \
  --effort high \
  --permission-mode plan \
  --tools "Read,Glob,Grep" \
  --output-format json \
  --json-schema ACCEPTANCE_OUTLINE_SCHEMA \
  --no-session-persistence \
  "Read the sprint and workflow. Return the minimum acceptance outline. Do not edit files or run commands."
```

After steward approval, start a separate authoring invocation with the approved outline
included in the prompt:

```console
env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN \
  claude -p \
  --safe-mode \
  --strict-mcp-config \
  --mcp-config '{"mcpServers":{}}' \
  --model opus \
  --effort high \
  --permission-mode dontAsk \
  --tools "Read,Glob,Grep,Edit,Write,Bash" \
  --allowedTools "Read,Glob,Grep,Edit,Write,Bash(cargo test -p luad-oracle --test SPRINT_TEST -- --nocapture)" \
  --output-format stream-json \
  "Implement only the approved acceptance outline. Produce the first durable red test before expanding the suite. Do not modify production code."
```

`--tools` controls which built-in tools exist. `--allowedTools` preapproves matching
uses; it is not an exclusive allowlist while the permission mode can still ask for
approval. `dontAsk` makes every unmatched request fail closed. Prefer a shell-free
authoring invocation with `Read,Glob,Grep,Edit,Write`; add `Bash` only after the exact
focused test command is known. Broad patterns such as `Bash(cargo test *)` are not an
acceptable substitute for an exact command.

The steward interrupts authoring if the outline invocation does not return a usable
structured result, or if the edit stage runs for 15 minutes without a durable red test
and reviewable diff. A compiler or gate already making observable progress may finish;
open-ended search does not extend the checkpoint. If the subscription allocation is
exhausted, retain durable files and resume after reset rather than switching to API
credits implicitly.

Turn ceilings belong on atomic read-only outline or review stages. Do not let a turn
ceiling interrupt a multi-file edit before its durable checkpoint. For a small
compiler-directed correction, prefer a fresh prompt containing the exact diagnostics
and allowed paths; resume a large session only when preserving its context is worth
reloading it.

`--safe-mode` disables project customizations while preserving Claude subscription
authentication. The strict empty MCP configuration and explicit tool list keep the
session scoped. Pass every required file and instruction explicitly. Verify the init
event reports `claude-opus-5`, no unintended MCP servers, and only the allowed built-in
tools; the `opus` alias alone is not evidence. Do not use
`--dangerously-skip-permissions`.

Independent review uses the same safe mode, strict empty MCP configuration, and
shell-free tools. An eight-turn ceiling is normally sufficient for one sprint contract,
its frozen acceptance module, and the candidate production paths. Increase the review
surface only when the claim requires it; a large duplicated oracle is a reason to
narrow acceptance, not automatically to allocate more reviewer context.

### Antigravity implementation agent

Antigravity supports non-interactive print mode, exact model and effort selection,
`plan` and `accept-edits` execution modes, sandboxed terminal use, structured JSON or
streaming output, JSON-schema-constrained final output, timeouts, and resumable
conversations.

Representative invocation from the implementation worktree:

```console
agy --print='Implement only docs/NEXT-SPRINT.md against the frozen acceptance commit. Do not edit the sprint contract, acceptance tests, fixtures, sprint gate, or shared proof harness. Run only the named focused acceptance test and stop at the candidate checkpoint.' \
  --model gemini-3.7-flash-high \
  --effort high \
  --mode accept-edits \
  --sandbox \
  --output-format json \
  --print-timeout 30m
```

`agy` treats `-p` and `--print` as value-taking options. Attach the prompt with
`-p='...'` or `--print='...'`; a bare `-p` consumes the next option as its prompt.

Before allowing edits, request a read-only implementation outline containing the
expected production paths, invariants, smallest proposed change, and focused test
commands. The steward rejects scope outside the sprint or frozen boundary. During the
edit stage, require a reviewable production diff before broad test execution. If
non-interactive mode cannot obtain its scoped permissions, use an interactive session
inside the already isolated worktree; do not widen filesystem access or redirect the
agent to a different checkout. Trust only the worktree. Deny attempts to inspect a
home directory or another checkout, restate the absolute worktree root, and approve
only the exact focused test command. The implementation agent never receives blanket
permission to run commands.

`agy` starts a local helper and writes logs beneath its Antigravity configuration
directory. In a managed outer sandbox it may require explicit permission for those
operations and its localhost listener. Never compensate by disabling repository or
agent safety controls globally.

For both tools, prompts should identify the exact sprint document, base and acceptance
commits, allowed paths, forbidden paths, required gate, and stop condition. Store the
prompt text or its SHA-256 with the handoff when reproducibility matters.

The implementation agent runs one focused sprint test while editing. It does not run
the canonical gate or aggregate repository check. This keeps implementation feedback
fast and leaves one authoritative clean-revision gate and aggregate run to the steward.

## 8. Sprint lifecycle

### Step 1: select

The steward chooses the smallest roadmap item that produces independently observable
researcher value. If it cannot be stated as one claim, split it.

### Step 2: specify

Write `docs/NEXT-SPRINT.md`. Resolve ambiguity before test or implementation work.

### Step 3: approve the acceptance outline

Run the read-only acceptance author. Confirm that its proposed evidence level,
fixtures, oracle, mutations, and expected red defect are the minimum needed for the
claim. Narrow the sprint or outline before authorizing edits.

### Step 4: author acceptance

The independent test author creates public-boundary tests, fixtures, oracle code,
mutation probes, and the gate. The first checkpoint is a durable red test and diff.
The steward reviews epistemic strength, runs the expected red result, and freezes the
acceptance commit.

### Step 5: implement

The implementation agent changes production code and ordinary unit tests only. It
runs narrow tests while iterating and stops at the sprint checkpoint.

### Step 6: produce candidate evidence

The steward reviews the diff for scope and frozen-file changes. After correcting any
approved issues, create one clean candidate commit and run the canonical gate into a
fresh artifact directory. Run `scripts/check.sh` separately.

### Step 7: accept or return

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

### Step 8: advance

After acceptance, update `ROADMAP.md`, replace `docs/NEXT-SPRINT.md` with the next
contract, and begin again from the newly accepted revision.

Record a short process retrospective at every accepted sprint: what created evidence,
what created delay, where an agent or permission boundary failed, and whether the
claim was correctly sized. Apply a workflow change only when the lesson generalizes
beyond that sprint. A formal workflow review is mandatory after every three accepted
sprints, or immediately after repeated failure, unexpected billing/authentication,
acceptance-test overgrowth, or a gate that permits a known defect. The maintained
workflow describes the resulting present process; retrospective history belongs in
the pull request, commit, or changelog.

The retrospective records time to outline, time to first durable red, acceptance test
and line count, implementation turns, permission denials, steward corrections,
canonical-gate duration, aggregate-check duration, resolved model identity, allocation
status, and API-equivalent usage when the provider reports it. These measurements are
diagnostic signals rather than dollar ceilings for subscription-authenticated runs.

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

## 10. Active planning state

`ROADMAP.md` is the only product-direction plan and `docs/NEXT-SPRINT.md` is the only
implementation sprint. A roadmap item does not authorize implementation until the
steward gives it a bounded sprint contract.

If the active sprint is accepted, blocked, or respecified, replace its contents with
the next forward-looking contract and update the README documentation index in the
same change. If no reviewed sprint contract exists, implementation work stops while
read-only research and acceptance design may continue.

Claude and Antigravity use the separated acceptance-author and implementation-agent
roles defined above. The steward records the exact tool versions, model identities,
worktrees, and commits for every cycle.

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
