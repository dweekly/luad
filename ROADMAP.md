# `luad` product roadmap

Status: authoritative product direction.

Fresh as of: 2026-09-06.

Product requirements live in [PRD.md](PRD.md). Exact implementation and acceptance
commands belong in [the active sprint](docs/NEXT-SPRINT.md). This roadmap orders
future obligations; it does not promote a target or authorize product implementation.

## Destination

`luad` 1.0 will be a dependable companion for investigating Lua inside extracted
firmware. A researcher will identify an explicitly qualified bytecode profile, retrieve
useful facts with byte-level evidence, account for unreadable or unsupported files,
and continue in a preferred decompiler or reverse-engineering platform without writing
a parser.

The release will serve one complete firmware workflow before adding target breadth:

1. inventory a mixed extracted tree by content, including compiled chunks named `.lua`
   or `.luac`, source files, malformed chunks, and unsupported layouts;
2. find a literal or global lookup and inspect the relevant instructions, prototypes,
   constants, and closure bindings;
3. export only the needed fact families while preserving artifact and interpretation
   identity, offsets, explicit limits, and a terminal outcome for every input; and
4. reproduce a finding from the original bytes and hand a compatible chunk to an
   external tool for source reconstruction or a broader investigation.

The differentiator will be this useful combination of exact firmware profiles,
reproducible evidence, bounded behavior, and a documented machine interface. Release
acceptance will not depend on being the first or only tool with a capability. An
upstream project fixing a defect will strengthen the workflow rather than invalidate
our reason to ship.

### Version 1 support boundary

Version 1.0 will promote exactly two independently qualified targets, as defined by the
canonical [release boundary](docs/RELEASING.md#frozen-version-1-boundary):

1. OpenWrt-derived Lua 5.1.5 profile `lua5.1-lnum32` with
   `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4`;
2. stock PUC Lua 5.1.5 profile `lua5.1` with
   `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0`.

Passing LNUM32 will not imply stock Lua 5.1 support. Each profile, numeric
representation, word size, and byte order remains a separate claim. EdgeTX Lua 5.3
32-bit, stock Lua 5.4.9, Lua 5.2, stock 5.3, 5.5, and other layouts or vendor profiles
will remain experimental or unsupported until their own post-1.0 contracts pass.

The package boundary will remain Linux x86-64 and macOS arm64, distributed through
verified GitHub release archives. Additional package platforms will require build and
smoke evidence without broadening the bytecode support claim.

## Product boundaries

`luad` will own hostile-input parsing, explicit profile selection, validated layouts,
lossless byte provenance, physical instruction roles, typed operands, constants,
closure bindings, structural validation, and deterministic text/JSON/JSONL export.

Verification will mean consistency with the selected format and the named checks.
It will not establish safe execution, the producer's intent, or a unique origin from
ambiguous bytes. A diagnostic will name the observed failure and exact location;
attributing it to a contradicted header field will require evidence of that
contradiction. Unknown causes will remain unknown. Merely changing a header byte does
not prove a contradiction if the affected representation is unused in that chunk.

Firmware extraction, decompilation, source reconstruction, security policy,
attacker-control or exploitability judgments, target execution, persistent research
state, and autonomous investigation will remain outside the core. LuaJIT and Luau are separate bytecode systems outside the product.

Existing CFG, xref, query, diff, explanation, symbolic-callee, origin, call-relation,
and prototype-content-identity surfaces will remain experimental unless a dedicated
contract qualifies an exact subset. Version 1 will not require new dataflow analysis,
a GUI, a plugin platform, or a custom query language expansion. Examples using
experimental facts will say so; the required stable workflow will not depend on them.

### Compose with the ecosystem

Publish task-specific pointers and tested handoffs, with exact tool versions and
profile limitations where relevant:

| Researcher task | Recommended starting point to document |
|---|---|
| Extract firmware containers and retain extraction metadata | [Unblob](https://github.com/onekey-sec/unblob) or [Binwalk](https://github.com/ReFirmLabs/binwalk) |
| Recover readable Lua source | [unluac](https://sourceforge.net/projects/unluac/) or [unluac-rs](https://github.com/x3zvawq/unluac-rs), after checking the exact input profile |
| Work with explicit opcode/type maps | The [unluac fork's mapping conventions](https://github.com/Jeong-Min-Cho/unluac), without guessing a map |
| Conduct an interactive reverse-engineering session | [Rizin](https://github.com/rizinorg/rizin) |
| Investigate LuaJIT bytecode | [LuaJIT Decompiler v2](https://github.com/marsinator358/luajit-decompiler-v2) |
| Work with Luau | [Luau's own tooling](https://github.com/luau-lang/luau) |

Keep comparisons dated, reproducible, and specific to the measured task. Revalidate
recommendations when writing a walkthrough. Share minimized public reproducers and
useful fixtures upstream; do not make upstream acceptance a release dependency.

## Release train

```text
layout truth and bounded refusal on every exposed parser
  -> compact evidence and one public firmware workflow
  -> outside-user trial and correction of workflow friction
  -> minimal stable interface and hostile-input tripwires
  -> exact qualification: LNUM32, then stock Lua 5.1.5
  -> fresh-session transfer and one frozen 1.0
```

An installable candidate may support a user trial without promoting a target. Freeze
the stable interface and boundedness tripwires before target promotion. A subsequent
change that invalidates a promoted claim will require requalification; no target may
inherit stale evidence.

Reference accepted prerequisite gates by identity. A downstream gate will add a suite
only when it owns a new interaction that those prerequisites cannot falsify. A compiler
listing can establish the facts it exposes; malformed-input behavior, byte provenance,
analysis semantics, and machine contracts need their own applicable evidence.

## Release execution sequence

Deliver the stages below in dependency order, one sprint contract and one pull request
at a time, following [the contract lifecycle](docs/DEVELOPMENT-WORKFLOW.md#12-preservation-documentation-and-escalation).
A target-qualification contract must merge as a separate planning change before
implementation. Other stages place their contract in the first commit of their own
pull request. Restore the neutral checkpoint in the final commit. Remove a stage when
its evidence is accepted; remove publication only after fresh downloads verify.

1. **Layout declarations:** make the Lua 5.2, 5.3, and 5.5 readers honor or explicitly
   refuse every declared width on all public surfaces. Probe maintained fixtures
   through the CLI, retaining valid originals and unsupported-width controls. Refusal
   is sufficient for layouts outside the release boundary; no EdgeTX implementation
   is implied.
2. **Consistency and rendering:** preserve the deepest failure offset, check serialized
   test values and numeric modes at their declared widths, and report only demonstrable
   header/body contradictions. Render supported 4-byte floats at their declared
   precision while preserving raw bits. Define corruption controls before changing
   diagnostics; do not infer a root cause from a downstream parse error alone.
3. **Compact target evidence:** close fixture-provenance gaps, adapt existing compiler
   comparisons for the two release profiles, select an implementation-independent
   second decoder for facts it can expose, and generate the smallest public corpus
   covering the release claim. Include applicable official tests, firmware-shaped
   microcases, stripped/debug pairs, and minimized defects. Seed maintained fuzz
   targets; no required tool or fixture may skip.
4. **Public firmware workflow:** deliver the three executable walkthroughs in
   Milestone 2 below, a concise README entry path, and one safe external consumer.
   Address missing core facts or composition defects in bounded contracts; do not
   expand experimental analysis to make the demonstration work.
5. **Outside trial:** give an outside firmware researcher an installable candidate,
   public inputs, and the public guide before freezing the interface. Record results
   and correct blocking friction within the product boundary. Internal trials may
   prepare this stage but cannot substitute for it.
6. **Machine-contract qualification:** qualify the minimal stable commands and selected
   fact families against live schemas, including executable examples, identity,
   diagnostics, exit behavior, limit reporting, and capabilities driven by evidence.
   Freeze the 1.x compatibility policy only after trial findings are resolved.
7. **Hostile-input qualification:** audit allocation and traversal limits, establish
   runtime and peak-memory tripwires, retain a time-bounded fuzz campaign and minimized
   regressions, and publish the compact hostile-input corpus with provenance.
8. **LNUM32 qualification:** merge the exact contract, then produce a new candidate
   identity with the authenticated OpenWrt authority, prerequisite references,
   out-of-profile refusal proof, and internal uncoached investigation. Complete the
   required open-window corpus replay without turning derived coverage into a stable
   analysis promise.
9. **Stock Lua 5.1.5 qualification:** merge its independent contract, then qualify the
   exact stock layout, physical roles, constants, offsets, malformed-input behavior,
   and symmetric stock/LNUM rejection.
10. **Candidate transfer and freeze:** rerun the public walkthroughs from packaged
    artifacts in a fresh session, finish the security checklist and production
    publication mode, freeze version/compatibility notes, and close required evidence
    over the release revision. Reuse packaging, SBOM, and bundle mechanisms.
11. **Publication:** tag and publish the accepted candidate, download every public
    artifact into a fresh environment, and verify checksums, identity, and smoke
    behavior. A failed publication leaves promotion and rollback rules intact.

### Milestone 1 — layout truth

Outcome: no exposed parser silently substitutes its preferred layout for a declared
one. Every accepted interpretation reports the layout actually used.

Evidence must exercise each serialized width and applicable byte-order/numeric flag
through the public CLI. Unsupported declarations must fail by field name and offset;
supported declarations must govern body reads, reported facts, and scalar rendering.
Known inconsistent bodies must fail with location and context. Positive originals and
corruption controls must exercise the same comparators. Preserve exact encoded facts
separately from interpreted values.

Stop before feature work while a known silent layout substitution or false valid
verdict remains. Do not expand support merely to satisfy a width probe.

### Milestone 2 — one useful firmware workflow

Outcome: an analyst can answer a concrete question using public inputs, without
writing an instruction decoder or reconstructing file identity from stream order.

Provide three executable walkthroughs with input provenance, download/build commands,
expected results, bounded output, failure behavior, and exact tool/profile versions:

- **Inventory:** a mixed extracted tree with bytecode named both `.lua` and `.luac`,
  source, malformed input, and an unsupported profile. Account for every input and
  distinguish export completion, validation verdict, and truncation.
- **Investigate:** find a literal or global lookup, inspect the relevant physical
  instructions and closure bindings, and retain evidence locating each fact in the
  original artifact. No security conclusion or runtime callee identity is implied.
- **Hand off:** pass a compatible chunk to a documented external decompiler and
  cross-check a disputed raw detail using published `luad` output. An incompatible
  profile must receive an honest limitation and next step, not a claimed integration.

Make the README lead with purpose, installation, one short example with useful output,
exact support, limitations, and task-specific tool pointers. Move maintainer release
mechanics behind links. Reconcile stale target and MSRV claims, archive indexing,
release channel/owner requirements, and workflow-role documentation with their owning
contracts without adding release infrastructure. Provide exact-version format notes tied to official/vendor
sources. Keep research-history and internal proof machinery out of the first-use path.

Provide a small external SQLite or equivalent consumer using parameterized writes,
artifact-plus-interpretation-scoped keys, and explicit file/stream completion checks.
Test duplicate prototype IDs across files, unusual paths/string bytes, failed inputs,
and truncated streams. Persistence stays outside the core. Existing prototype-content
comparison may have a clearly experimental recipe; equal content is not a claim of
behavioral equivalence.

Stop when the workflow and its failure cases reproduce from published examples. Do
not add a general importer framework, extraction engine, or analysis platform.

### Milestone 3 — trial and minimal stable machine contract

Outcome: a researcher can use the interface without coaching, and a small external
consumer can depend on the qualified surface throughout 1.x.

Before freeze, an outside firmware researcher must try the candidate on authorized,
public, in-profile inputs pre-screened only for profile applicability. Record commands,
time to first useful answer, custom glue, missed files, misunderstandings, unresolved
questions, and incorrect answers. Set the concrete task and success assertions before
the trial; do not coach to a passing result. Correct blocking defects and repeat the
invalidated portion. One trial demonstrates transfer, not broad adoption.

Freeze `inspect`, `disasm`, `validate`, `export`, `capabilities`, `diagnostics`, and
`schema`, and enumerate the stable export fact families explicitly. Stabilizing the
export envelope must not accidentally stabilize every experimental record it carries.
Required behavior includes selective bounded export, per-file outcomes, input and
interpretation identity, diagnostics, stdout/stderr separation, exit codes, deterministic
ordering, live schemas, and machine-visible limits. Qualify every shared fact across
text/JSON/JSONL and run documented consumers against actual output.

Capabilities must distinguish implementation presence, experimental evidence, and exact
promoted targets, with LuaJIT and Luau out of scope. Define additive fields, open and
closed vocabularies, schema-major changes, CLI compatibility, and content-ID schemes.
Partial-facts recovery remains deferred; failed inputs must still produce their
identification and diagnostic outcome without invented recovered semantics.

Stop before interface freeze until the outside trial and its blocking corrections
close. Waiting for a participant does not authorize unrelated product work.

### Milestone 4 — proportional public evidence and hostile-input bounds

Outcome: each release claim is falsifiable against a compact, reproducible corpus, and
arbitrary input remains within declared allocation, traversal, recursion, diagnostic,
and output limits on every exposed path.

Pin the producing authorities for stock Lua 5.1.5 and OpenWrt LNUM32, including source,
patches, configuration, build recipes, and fixture hashes. Reuse applicable
[official Lua tests](https://www.lua.org/tests/) and existing gates; add independent
comparisons only for facts their authorities actually expose. Prove each comparator
rejects meaningful corruption. A shared implementation lineage is not by itself an
independent semantic authority.

Publish valid and hostile fixtures with provenance in the repository or release.
Include compiler-generated firmware shapes, closure companions, malformed widths and
counts, truncations, and minimized fuzz findings. Correct provenance for every fixture
referenced by a retained gate; narrowing the release cannot excuse missing evidence.
A separate corpus repository, all-version dataset, general mutator, layout re-emitter,
and Prometheus preset matrix will not be prerequisites.

Seed every maintained fuzz target. Retain bounded CI smoke and a representative
extended campaign over the exact candidate, with configuration, corpus identity,
duration, and results. Set falsifiable runtime and peak-memory tripwires for small
input, a large instruction vector, deep prototypes, long strings, and a representative
mixed firmware batch. Turn crashes, excessive allocation, timeouts, and inconsistent
verdicts into minimized redistributable regressions.

Stop qualification for a known panic, unbounded allocation/traversal, unexplained
timeout, or P0 correctness/security defect. Share useful reproducers upstream without
requiring a new dataset service or upstream acceptance to release.

### Milestone 5 — exact targets in firmware order

Outcome: promote only the two exact profiles after machine and boundedness contracts
freeze, with no support inherited from neighboring layouts.

**LNUM32:** issue a new candidate identity rather than reuse RC1. Authenticate the Lua
5.1.5 archive, OpenWrt revision, ordered patches, build recipe, platform binaries,
fixtures, and exact profile/layout. Reference accepted public-read, validator,
diagnostic, machine-contract, retrieval, scalar-rendering, export-bound, and hostile
prerequisites rather than duplicating them. Prove unaffected callee registers survive
open argument/result windows and complete the preregistered firmware replay. Retain
an internal uncoached investigation and an actionable out-of-profile refusal.
Experimental derived facts cannot expand the stable target claim.

**Stock Lua 5.1.5:** pin its official authority and the exact little-endian, 64-bit
`size_t`, non-integral-double layout. Qualify profile selection and symmetric rejection
against LNUM, closure descriptors, `SETLIST C == 0` data words, stripped/debug
prototypes, constants, offsets, jump targets, and bounded malformed-input handling.
Other stock layouts remain experimental.

Each promotion gate must emit its own manifest only after clean prerequisites,
platform attestations, mutation controls, and the aggregate check close over the
candidate revision with zero required skips. Stop at the exact two-target set.

### Milestone 6 — transfer and one frozen 1.0

Outcome: a fresh user can install the package, complete the documented workflow,
reproduce supporting bytes, understand unknowns, and continue in another tool.

Verify the walkthroughs and external consumer from packaged artifacts in a fresh
session. Retain the outside trial and candidate transfer records without private
firmware, sensitive findings, or investigation-specific judgments. If interface
changes invalidate a trial, repeat the affected workflow before release.

Freeze one clean revision, support matrix, schema set, and evidence index. Run required
promotion gates, the aggregate check, and candidate fuzz evidence with exact authorities
and no required skips. Build both archives using the existing packaging/SBOM machinery;
finish only the missing production publication mode. Align capabilities, documentation,
security policy, release notes, checksums, and artifacts, then publish and verify fresh
downloads. Use the release procedure's rollback path after partial publication.

Stop for failed transfer, inconsistent evidence identity, or unresolved release defects.
Do not claim broad adoption from one trial, affiliation with Lua.org or PUC-Rio, or
safe execution from structural checks.

## Version 1 acceptance

Release only when all of the following hold for the exact candidate:

1. Every exposed parser honors or refuses declared layouts; known contradictory
   fixtures fail, and diagnostics separate observed facts from uncertain causes.
2. The two release targets pass their named evidence gates with pinned authorities,
   independent comparisons where applicable, corruption controls, and no required skips.
3. Stable commands and fact families agree across formats, preserve interpretation and
   byte provenance, and remain deterministic within the advertised host contract.
4. A mixed firmware batch accounts for every input, selected fact families avoid an
   unnecessary full export, and incomplete output cannot appear complete to the consumer.
5. Resource tripwires, seeded fuzzing, the candidate campaign, and public regressions
   establish the named hostile-input bounds.
6. An outside researcher has completed the concrete public workflow before interface
   freeze, blocking friction is resolved, and fresh packaged-candidate transfer passes.
7. The support matrix, schemas, evidence, SBOM, checksums, and downloadable artifacts
   identify the same revision, exact targets, and limitations.

## Post-version-1 research

### Additional targets and profile facilities

Choose one target by demonstrated researcher need and public compiler authority.
EdgeTX Lua 5.3.6 32-bit is a strong next candidate, not a mandatory next release. Pin
`edgetx-luac`, define `lua5.3-edgetx32` precisely, distinguish radio-compatible bodies
from host long-string width inconsistencies using reproducible evidence, and prove
symmetric rejection against stock 5.3. Record any SD-card source license per case.

Stock PUC Lua 5.4.9 may follow a demonstrated workflow need. Pin its exact layout and
compiler, and reuse 5.4.8 evidence only where a reviewed delta preserves the relevant
facts. Neither target is a 1.0 dependency.

A provenance-bound TP-Link opcode-map profile may outrank another stock version when
router researchers repeatedly need it and a public GPL source drop supplies authority.
Reuse compatible `.op N name` and `.type N kind` conventions. Automatic map recovery,
declarative parser plugins, and origin-ecosystem inference require separate decisions;
no default may guess a layout or map.

Other candidates include OpenTX/older EdgeTX Lua 5.2, NodeMCU integral/byte-swapped
layouts and LFS containers, Playdate, other stock releases, and additional layouts.
Consult the [prior-art survey](docs/PRIOR-ART-AND-CORPORA.md), verify its dated claims,
and require an exact authority and customer outcome before scheduling one.

### Corpus and ecosystem contributions

Expand corpora when a new claim needs coverage. NodeMCU `luac.cross`, a general layout
re-emitter, a composable chunk mutator, Prometheus stress inputs, and an all-version
stock corpus need their own bounded justification. Preserve source licensing and
provenance; do not vendor proprietary or malware-derived samples by implication.
A separate corpus repository or citable dataset may follow actual reuse.

Consider Kaitai/ImHex contributions, a Rizin adapter, or WASM only with a concrete
consumer. Reuse existing formats and contribute shared fixes rather than building a
parallel platform. A public rewriting command requires a separate product decision.

### Bounded value and call facts

Before expanding analysis, measure useful resolution on representative public chunks
under conservative rules. Define joins, loops, aliases, capture mutation, path-specific
alternatives, and cutoff semantics before a stable schema. Promote a narrow existing
fact family only when a user workflow needs it and independent evidence qualifies it.
Whole-program inference, source recovery, execution, and security policy remain outside
version 1; partial-facts recovery and comparison promotion need separate contracts.

### Outside validation

Continue outside trials across firmware families, and request Lua community review of
terminology, profile claims, build instructions, and surprising output. Record adoption
separately from transfer success. Use repeated workarounds and mistaken interpretations
to prioritize the next bounded change; do not expand the release merely to accumulate
features or badges.

## Sequencing rules

- Silent incorrect answers interrupt planned feature work.
- Only an active sprint contract authorizes implementation; a planning checkpoint does not.
- Private corpora may find defects and measure usefulness but cannot define or promote
  a format without public authority and redistributable evidence.
- Stable contracts and boundedness tripwires precede target promotion; invalidated
  evidence must be rerun against the changed candidate.
- Outside feedback precedes interface freeze. Self-run evaluation cannot replace the
  outside participant or establish independent adoption.
- Release work must reference accepted prerequisites instead of rebuilding proof or
  packaging infrastructure without a specific unmet requirement.
- Upstream improvement is a success. No gate may require other tools to remain deficient.
- Stop at the useful two-profile workflow. Additional dialects, analysis, datasets, and
  integrations require a separate customer-backed decision.
