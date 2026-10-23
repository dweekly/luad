# `luad` roadmap

Status: plan of record for community usefulness and the firmware consumer.

Fresh as of: 2026-10-22.

## Destination and product boundary

Make unfamiliar PUC Lua bytecode useful to people and tools: identify its declared
format, inspect exact constants and closure bindings, follow supported call and value
relationships, compare artifacts, and reproduce each answer from the original bytes.
The first audience is firmware researchers and Lua tool authors; VM learners and
maintainers comparing builds provide a second check that the product is not specific
to one investigation. Scripts and agents are interfaces to these users, not independent
proof of community demand.

Earn a distinct place through reliable interpretation, byte provenance, explicit
uncertainty, bounded operation, and a usable machine contract. Measure the useful
combination against existing tools rather than claiming that Rust, disassembly,
constant pools, CFGs, or embedded-layout handling are unique. Reuse compatible tools
and contribute fixes and fixtures upstream when that solves the user's problem.

Keep extraction, decompilation, source reconstruction, target execution, authentication
policy, taint classification, exploitability, and persistent research state outside the
core. A caller-oriented view can belong in `luad` even when it reorganizes existing
facts. Its contract must preserve assumptions, identity, context, and incomplete
coverage; determinism alone does not establish semantic correctness.
LuaJIT and Luau are separate bytecode systems outside the product.

[docs/NEXT-SPRINT.md](docs/NEXT-SPRINT.md) authorizes the single implementation batch.
This roadmap does not authorize production edits. Remove accepted obligations from
this file; retain history and accepted measurements in commits, issues, release
evidence, and [CHANGELOG.md](CHANGELOG.md).

## How to choose the next batch

Rank candidates in this order:

- Eliminate a reproducible false answer or an unbounded path on an exposed surface.
- Unblock a named user question or remove a repeated, error-prone integration step.
- Improve useful coverage on the actual files and relationships needed by that task.
- Reduce measured latency, output, or installation friction on that workflow.
- Expand targets or integrations only when the preceding options cannot answer the need.

For each candidate record the user, question, current workaround, evidence and its
confidence, expected benefit, dependencies, implementation cost, and correctness risk.
Use counts when reproducible, with their population, tool revision, input identity,
consumer revision, and field definition. A correctness counterexample needs no adoption
count. A raw unknown-reason histogram is not a measure of questions blocked, and more
resolved values are not an improvement if uncertainty has been discarded.

Re-rank after every two or three related product batches and after an outside trial.
A new silent incorrect answer interrupts feature work. Each implementation contract
must map acceptance assertions to exact executable commands before code changes;
existing tests or gates are reused unless they cannot falsify the new interaction.

## Delivery order

The two ownership tracks below meet at a shared public workflow. Fixes in the private
consumer do not require expanding the core, and a waiting private measurement does not
block a public correctness fix. Coordinate shared interface changes across the tracks
so consumer and core results retain matching schema and interpretation identities.

These are milestones, not single implementation assignments. Contract and accept one
coherent outcome at a time; split public corpus/reference-consumer work, caller
inspection, and packaged trial preparation into bounded batches as their dependencies
become reviewable.

| Order | Outcome | Owner | Dependency and exit condition |
|---|---|---|---|
| B | A reliable firmware measurement loop | Firmware consumer, with public reproductions in `luad` | No before/after product ranking until coverage and consumer semantics are checked. |
| C | Useful public investigation and caller-inspection workflows | `luad`, plus a small reference consumer | Depends on B for firmware benefit claims; exact answers must be obtainable without a custom decoder. |
| D | Independent evidence of value against alternatives | Maintainer and outside users | Trial an installable C candidate before interface freeze; correct the blocking findings. |
| E | A clearly scoped experimental announcement | Maintainer | B-D close for the advertised workflows; install, evidence, limits, and fresh-download checks pass. |
| F | A narrow stable contract and exact target qualification | `luad` | Adopt the 1.0 program only after utility is established; promote no target by implication. |

### B. Make the firmware consumer a reliable product signal

The private consumer owns this work in its own repository. Keep private binaries,
security findings, model/version coordinates, and raw investigation output there.
Upstream only minimized, redistributable VM or interface reproductions.

**Qualify the consumer's interpretation.** Preserve unknowns at expression, recursion,
field-path, and output limits. Reject unknown schema variants instead of treating them
as empty. Require file and export completion, explicit skipped/failed/truncated counts,
and artifact-plus-interpretation identities. A truncated stream must not yield a clean
empty result. Consume the core's link records rather than maintaining a competing
instruction-based export resolver where the supported convention applies.

Keep lexical containment separate from call reachability. A never-invoked nested
closure must not make its parent's endpoint reach a sink; an explicitly invoked twin
must provide the necessary edge. Qualify callback registration and dispatch-table
recovery with decoy tables, aliases, overwrites, branches, and unknown cases. Separate
possible call-graph paths from feasible execution and from authentication judgments.
Retain per-caller origin evidence so unrelated callers cannot taint a specific path by
union. Treat security labels as investigation-specific hypotheses requiring validation.

**Close source coverage outside the core.** Inventory bytecode, source, unsupported,
and failed inputs separately, including which missing files supply needed callers or
callees. Evaluate an existing Lua parser or a pinned compatible offline compiler for
source files. A compiler bridge must be isolated and bounded, must not execute the
source or chunk, and must preserve source-to-generated-artifact identity, syntax and
numeric-mode assumptions, and mappings usable by the consumer. Generated bytecode is a
new artifact, not the vendor's original bytes. If compatibility cannot be demonstrated,
retain a separately labeled source path and explicit unresolved coverage.

**Resolve byte order from artifacts.** Inspect actual headers and representative body
fields from each required platform. Record an inventory by encoded profile, widths,
and byte order; do not infer chunk layout from the CPU. Propose big-endian parsing only
if a needed encoded layout is genuinely refused and public compiler authority plus a
redistributable positive fixture can define it. A refusal control alone cannot qualify
reading that layout.

**Re-measure with a fixed denominator.** Pin the input inventory/hashes, core build,
consumer revision/configuration, and scope. Compare the released baseline with the
candidate at `(artifact, prototype, pc, argument)`, alongside task-level caller and
endpoint results. Account separately for lost information, corrected stale answers,
newly known answers, source coverage, and consumer fixes. Recheck the suspected 2000
saturation in raw records and aggregation separately; localize it before assigning a
core fix. Do not run the private pipeline's findings through the core's `diff` command
as a substitute for a typed origin comparator.

**Exit:** the consumer detects deliberate false reachability, cutoff loss, missing
records, and stale or mismatched inputs; records complete coverage and scoped before/
after results; and identifies the highest-cost remaining question with public reproducers
for any core defects. Consumer counts alone never qualify a target or a security finding.
Unresolved source or dynamic paths may remain explicitly outside coverage; a complete
accounting must not be described as complete whole-firmware analysis.

### C. Deliver complete public workflows and convenient factual views

Provide three executable workflows from a packaged candidate and public inputs:

- **Inspect and investigate:** inventory a mixed tree, identify declared layouts, find a
  literal/global, inspect its uses and closure bindings, and recover the supporting byte
  locations. Account for source, malformed, unsupported, and truncated inputs.
- **Inspect callers:** select an exact artifact and prototype in an explicit corpus,
  enumerate the supported incoming relations, and inspect each caller's argument
  origins. Show duplicate/failed resolutions and corpus coverage beside the answer.
- **Compare and hand off:** identify exact content changes between two related builds,
  inspect changed constants or prototypes, and pass an exactly compatible artifact to
  a tested external tool. Separate structural/content changes from behavioral claims.

Use a small redistributable application/module subset and applicable official Lua
cases compiled with pinned stock 5.1 and OpenWrt LNUM32 authorities. Include stripped/
debug pairs, closures, module initialization, field repacking, open arguments, loops,
and the actual loop-convergence regression shape. Pin argument-level expressions and
conservative unknowns as well as structure. Reuse the existing origin and link gates;
a realistic fixture is valuable only if an assertion can detect its relevant defect.
Retain source licenses, compiler/patch identities, commands, hashes, and controls.

**Make caller inspection a convenient operation with an explicitly experimental
evidence boundary.** Choose the CLI spelling and typed response in its
contract, reuse existing relation/link/origin analysis, and begin with bounded one-hop
per-caller records. Do not require users to join a full instruction export for this
question. Preserve bytecode-local parameter origins. An empty enumerated caller list
means no observed caller in that corpus, not unreachable code or a complete negative.
Unenumerated callers remain unknown; they cannot be listed or counted by assumption.
Multi-hop substitution and flattening into a union require separate evidence of need.

Ship one small reference consumer demonstrating schema checks, identity-scoped joins,
completion checks, unknown propagation, and caller context. Share its factual adapter
across the workflows; keep firmware dispatch, sink, and authentication policy outside it.
Test duplicate local IDs across artifacts, unusual paths/string bytes, omitted records,
and unknown variants. Persistence and a general-purpose SDK are not prerequisites.

Measure time to first answer, end-to-end time, peak memory, output bytes, and glue code
on public workloads and a privately scoped firmware replay. Prefer existing family
selection, targeted queries, and reuse of computed analysis. Set quantitative budgets
from these baselines before claiming performance or implementing a new optimization.
No persistent index, schema redesign, or uniform limit increase without a demonstrated
bottleneck and a falsifiable improvement target.

**Exit:** each workflow has reproducible commands, exact expected answers and failure
cases, applicable profile/tool versions, bounded output, and byte evidence. A user
needs no custom bytecode decoder. The README leads directly to these outcomes and
states current capability limits; existing discoverability features are tested rather
than rebuilt merely because a reader overlooked them.

### D. Establish independent usefulness

Recruit at least two people outside the development loop: a firmware researcher and a
Lua tool author or maintainer with a different task. Give each a packaged candidate,
public inputs appropriate to their task, and the public documentation. Define the
question and success assertions before the trial; preserve uncoached first-use results.
Internal agents can prepare fixtures but cannot substitute for these participants.

Run the same relevant tasks with exact versions of official `luac`, unluac/unluac-rs,
and a current applicable Rizin build. Separate source inspection, project claims, and
executed results, including released versus development versions. Compare correct
answers, refusal/unknown behavior, glue code, installation effort, time, and evidence
traceability. Do not score a decompiler on a task it does not promise or require an
alternative to fail for `luad` to succeed. Update the dated prior-art survey from results.

**Exit:** outside users complete the public tasks, blocking errors and misconceptions
are corrected, and at least one task demonstrates a concrete reason to choose or embed
`luad`. If there is no useful advantage, narrow the product to an adapter, reusable
library, or shared evidence contribution instead of expanding feature breadth. Preserve
sanitized trial and comparison records in durable release/PR evidence.

### E. Announce a useful experimental release

Announce after A-D establish the advertised workflows, without waiting for every 1.0
qualification obligation. Publish the task-specific value, exact experimental profiles,
known limitations, and working examples; do not advertise a vulnerability scanner,
behavioral-equivalence checker, or universal Lua backend.

Require the exact packaged revision to pass the relevant named gates, aggregate CI on
Linux x86-64 and macOS ARM64, existing hostile-input smoke checks, and workflow transfer
from fresh downloads. Retain matching archives, checksums, source SBOM, build identity,
and required attestations using existing machinery. Do not rebuild accepted bytes or
move a released tag. A known false answer in an advertised workflow blocks announcement
until fixed, explicitly refused, or removed from that advertised workflow.

Clearing a private firmware image or resolving every unknown is not an announcement
condition. Require reliable consumer accounting for any claimed firmware benefit;
keep incomplete private coverage visible while shipping independently demonstrated
public workflows.

Use the project issues/discussions for reports; do not create a new feedback platform.
Publish useful fixtures and format notes alongside the release and invite upstream
reuse. Seek outside participants before announcement so trial findings can shape it.

**Exit:** a new user can install, answer the documented questions, understand omissions,
and continue in an existing tool. Capability status remains experimental until its
separate promotion gate passes. Record subsequent independent use and repeat tasks;
star counts, model reviews, and a successful self-run are not adoption evidence.

### F. Stabilize what users actually depend on

Adopt [docs/ROADMAP-1.0.md](docs/ROADMAP-1.0.md) when outside use justifies a compatibility
promise. Freeze the smallest command/fact subset that serves those workflows, including
identity, limits, completion, errors, and schema evolution. Give experimental derived
facts an explicit boundary so a stable export envelope does not promote them implicitly.

### Version 1 support boundary

Preserve the [frozen version-1 boundary](docs/RELEASING.md#frozen-version-1-boundary):

| Qualification order | Compiler/profile | Exact serialized layout |
|---|---|---|
| First | OpenWrt-derived Lua 5.1.5, `lua5.1-lnum32` | `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4` |
| Second | Stock PUC Lua 5.1.5, `lua5.1` | `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0` |

No adjacent layout, dialect, or analysis inherits support. Changing that future release
boundary requires its own explicit planning decision and corresponding requirements/
release-policy changes.

## Conditional work after the first useful workflows

Select from this list by verified task benefit, cost, and risk, not issue age or raw
frequency. None is an automatic prerequisite for announcement or a 1.0 promise.

- **Mutable-capture origins:** evaluate only after a qualified consumer identifies
  affected questions. Bound a cell by its close and distinguish register reuse; require
  a complete effect model or a known-safe instruction allowlist, refuse unknown writes,
  and charge replay to a shared per-prototype budget. Cover open-result calls, numeric
  and generic loops, closure-mediated writes, and unresolved members. Preserve
  `mutable-capture` when the set cannot be established completely. Use
  [#97](https://github.com/dweekly/luad/issues/97) as a source of adversarial cases, not a
  permanent reason to staff or decline the work.
- **Table/escape precision:** improve only for measured questions, using known-safe
  readers and explicit escapes. A later callee or alias write cannot preserve stale
  contents merely to improve a resolution count.
- **Additional profiles:** prioritize actual refused artifacts with public authority.
  Encoded big-endian Lua 5.1, vendor opcode maps, EdgeTX, and newer stock releases compete
  on that basis. Do not add a second module convention for an unverified matching gap.
  Revisit the future release boundary if justified demand changes its ordering.
- **Multi-hop caller inspection:** require per-call-site context, bounded recursion,
  open/missing arguments, callbacks, aliases, and unknown caller coverage. Keep a
  union of possible inputs separate from any claimed feasible execution path.
- **Integrations and distribution:** choose a Rizin/decompiler adapter, in-process API,
  Windows package, package-manager channel, or WASM only when a named outside user has
  an otherwise blocked workflow. Reuse ecosystem formats and compare implementation
  cost with contributing the missing capability upstream.

Do not reopen loop widening by replacing its absorbing conflict marker with a growing
set. Any new mechanism must first establish a bounded lattice/fixpoint and preserve
unaffected call origins. Do not add decompilation, source parsing, automatic opcode-map
inference, policy classifications, or persistent sessions as incidental extensions.
