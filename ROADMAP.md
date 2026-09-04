# `luad` product roadmap

Status: authoritative product direction.

Fresh as of: 2026-09-03.

Product requirements live in [PRD.md](PRD.md). Exact implementation and acceptance
details live only in [the active sprint](docs/NEXT-SPRINT.md). This roadmap orders
future obligations; it does not promote a target, authorize product work, or replace an
executable gate.

## Destination

`luad` 1.0 will be the Lua bytecode verifier and fact source: the tool that tells the
truth about a chunk's layout and internal consistency across every Lua release and
vendor layout, proves each claim against the producing compiler's own listing with
negative controls, exports those facts under a stable machine contract, and publishes
the corpora that let anyone test the claim. It turns untrusted compiled chunks into
exact, auditable facts for humans, scripts, and AI agents without executing the input,
and equivalent inputs and options produce byte-for-byte deterministic output on every
advertised host.

Parsing, disassembly, and decompilation are commodities in this ecosystem. Three things
are not, and everything below is ordered by how directly it serves them:

1. **honest refusal**: a chunk whose body contradicts its header is never reported
   valid, and every refusal names the field, the declared value, and the offset;
2. **an authority discipline**: every public claim is proven against the producing
   compiler's listing plus an independent decoder, with a negative control; and
3. **public corpora**: the stock regression corpus, the vendor-layout matrix, and the
   hostile-chunk corpus are published so the claim is testable by anyone.

The public product should feel consistent with Lua itself: narrow claims, exact version
names, portable behavior, plain documentation, liberal licensing, and releases that are
easy to download and verify. The proof machinery can remain detailed internally; a user
should need only the support matrix, command reference, limitations, checksums, and one
evidence link. The [prior-art and corpus survey](docs/PRIOR-ART-AND-CORPORA.md) is the
public acceptance picture: its tool-comparison matrix must show `luad` as the only row
that reads every column correctly and names the inconsistency in the one that lies.

### Version 1 support boundary

Version 1.0 will promote only the independently qualified targets in the canonical
[release boundary](docs/RELEASING.md#frozen-version-1-boundary):

1. OpenWrt-derived Lua 5.1.5 profile `lua5.1-lnum32` with
   `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4`;
2. EdgeTX Lua 5.3.6 profile `lua5.3-edgetx32` with 4-byte `int`, a 4-byte `size_t`
   header slot, 4-byte instructions, 4-byte `lua_Integer`, 4-byte `lua_Number`, and
   `LUAC_NUM` serialized as a single-precision float, as produced by the EdgeTX
   `edgetx-luac` host compiler at a pinned revision;
3. stock PUC Lua 5.4.9 profile `lua5.4`, format 0, with 4-byte instructions, 8-byte
   `lua_Integer`, 8-byte `lua_Number`, and the pinned official compiler's standard
   little-endian representation; and
4. stock PUC Lua 5.1.5 profile `lua5.1` with
   `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0`.

[Lua 5.4.9](https://www.lua.org/versions.html) replaces 5.4.8 as the forward-looking
1.0 target because it is the final Lua 5.4 bug-fix release. Accepted 5.4.8 evidence may
be a prerequisite where the exact 5.4.9 qualification contract proves the relevant
format and opcode facts unchanged, but it cannot by itself promote 5.4.9.

Each profile and layout is a separate claim. Passing LNUM32 never implies stock Lua 5.1
support, passing EdgeTX never implies stock Lua 5.3 support, and passing one stock
layout never implies a different numeric representation, word size, or byte order.
Lua 5.2, stock 5.3, 5.5, other stock layouts, and other vendor profiles remain
experimental or unsupported until their own post-1.0 contracts pass. LuaJIT and Luau
are out of scope.

The 1.0 distribution boundary is Linux x86-64 and macOS arm64. Additional package
targets require their own build and smoke evidence but do not broaden the bytecode
support matrix.

## Product boundaries

`luad` owns:

- hostile-input parsing, layout detection, validation, and lossless byte provenance;
- header-versus-body consistency: every declared width honoured on every surface or
  refused by name, never assumed;
- version-specific instruction decoding, physical roles, operands, constants, effects,
  targets, source locations, and closure bindings;
- deterministic text plus versioned JSON and JSONL contracts;
- structural navigation through prototypes, cross-references, control flow, queries,
  exports, and exact comparisons; and
- explicit evidence for every public support claim, including the public corpora that
  evidence is drawn from.

`luad` will not own decompilation, guessed source reconstruction, security policy,
attacker-control or exploitability judgments, target execution, persistent research
state, or autonomous investigation. Those consumers compose over the factual CLI.
Decompilers, devirtualizers, and reverse-engineering platforms are consumers of
`luad`'s facts, not competitors, and `luad` does not compete with them on breadth of
dialect parsing. LuaJIT and Luau are separate bytecode systems outside the product.

## Engineering mountains

The roadmap does not assign equal weight to unequal work.

| Mountain | Size | Release position | Core difficulty |
|---|---:|---|---|
| Layout truth and honest refusal | Large | First, before any feature work | Every declared width honoured end to end or refused by name in every dialect; consistency diagnostics; offset-anchored failures; declared-precision rendering |
| Authority discipline and public corpora | Large | Version 1 | The producing compiler's listing as the oracle for stock and vendor profiles; independent second decoders; a generated, provenance-tracked stock corpus; negative controls everywhere |
| Exact target fidelity, vendor first | Large | Version 1, after the contract freezes | Serialized layouts, opcode semantics, and malformed-input behavior across four claimed targets, two of them vendor profiles |
| Stable machine contract, minimal core | Medium | Version 1, before any target is promoted | Typed facts, schemas, diagnostics, exit codes, and platform-independent scalar rendering for the smallest surface the niche needs |
| Hostile-input robustness | Medium | Version 1, trimmed | Resource limits, fuzz targets with seeds, minimized regressions, and the public hostile-chunk corpus |
| Distribution and release mechanics | Small | Already built | No further investment before 1.0; publish with what exists |
| Structural navigation and comparison | Medium–large | Experimental in 1.0 | CFGs, xrefs, query, and diff stay available and labeled experimental until a post-1.0 contract promotes them |
| Bounded value and call analysis | Extra large | After version 1 | Reaching definitions, joins, loops, aliasing, captures, cutoffs, and evidence-preserving uncertainty |

## Release train

The dependency order is:

```text
layout truth: honour every declared width end to end or refuse by name
  -> authority generalization and the generated public stock corpus
  -> minimal stable machine contract
  -> hostile-input evidence and the public hostile-chunk corpus
  -> exact targets in niche order: LNUM32, EdgeTX 5.3-32, stock 5.4.9, stock 5.1.5
  -> transfer and one frozen 1.0
```

A target manifest binds to the exact tool revision that produced it, so the public
contract and the boundedness tripwires freeze before any target is promoted against
them. A later change to the stable contract requalifies every promoted target rather
than inheriting its evidence.

Accepted prerequisite gates are referenced by identity. A downstream milestone does
not duplicate their semantic suites unless it owns a new interaction capable of
falsifying the release claim.

## Release execution sequence

The milestones below are delivered as the stages in this list, in this order. Each
stage is one sprint contract in `docs/NEXT-SPRINT.md` and one pull request, following
the contract lifecycle in
[the development workflow](docs/DEVELOPMENT-WORKFLOW.md#12-preservation-documentation-and-escalation):
the stage's first commit replaces the checkpoint with its contract, and its last commit
restores the checkpoint. A target-qualification stage (the four targets of Milestone 5)
instead merges its contract as a separate planning change before any implementation,
because its acceptance commands must be fixed before code. A stage is deleted from this
list when its evidence is accepted: for most stages that is the merge of its pull
request, and for the final publication stage it is the fresh-environment verification
of the published artifacts. The list holds only unmet obligations.

1. Milestone 1a: declared header widths in Lua 5.2, 5.3, and 5.5. For every width byte
   the dialect serializes, the reader either decodes at the declared width on every
   public surface (`Layout` reports it, constants and test values use it) or refuses
   the header with a diagnostic naming the field and declared width at that byte's
   offset with a non-zero `validate` exit, as the Lua 5.4 reader already does for
   `lua_Number`. `Layout` never differs from the declared header. Allowed paths: the
   three dialects' `header.rs`, their `chunk.rs` only where a declared width is
   decoded, the diagnostic catalog, and one new oracle test. Evidence: a width-probe
   test that rewrites each width byte of every maintained 5.2, 5.3, and 5.5 fixture
   through the public CLI and asserts honour-or-refuse, with the unmodified fixture and
   the 5.4 refusal as controls. Honouring a 4-byte 5.3 body end to end is the EdgeTX
   stage's work; refusing it by name is sufficient here.
2. Milestone 1b: header-versus-body consistency diagnostics (a long-string length
   width that contradicts the declared `size_t`, `LUAC_NUM` and `LUAC_INT` checked at
   the declared width, integral flags that contradict constant tags), and every
   layout-mismatch body failure anchored at the observed offset naming the
   contradicted header field.
3. Milestone 1c: 4-byte floats rendered at 4-byte precision on every human and machine
   surface, and retirement of diagnostics that blame a symptom when the cause is a
   declared width.
4. Documentation truth pass: retire the remaining stale present-tense claims (Lua 5.4.8
   evidence described as the 1.0 target, the duplicate MSRV statements in the
   changelog, the archived candidate guide indexed as maintained, the PRD's open
   platform question), name the 1.0 distribution channel, owner, and MSRV in the PRD,
   and align `docs/DEVELOPMENT-WORKFLOW.md` with the review and model roles actually in
   use.
5. Milestone 2a: the differential oracle takes the authority compiler's listing per
   profile (pinned official compilers, the OpenWrt LNUM32 build, `edgetx-luac`, NodeMCU
   `luac.cross`), and unluac and unluac-rs enter the harness as independent second
   decoders consumed as external programs.
6. Milestone 2b: the generated stock regression corpus from the per-release official
   test suites, pinned by published SHA-256 and compiled by the matching pinned
   compiler, with the manifest, the generator script, the family/version/preset layout
   with a metadata sidecar, the per-construct micro-corpus, and the existing oracle
   gates passing over it; the five shared toy programs cease to be the sole evidence.
7. Milestone 2c: the internal layout re-emission generator and the NodeMCU authority,
   used to put the 32-bit and integral Lua 5.1 fixtures under recorded provenance, to
   produce cross-layout negative controls, and to seed the analysis fuzz targets.
8. Milestone 3a: `capabilities --format json --evidence` distinguishes implementation
    presence, experimental evidence, and exact promoted targets, fed by recorded gate
    results, and lists LuaJIT and Luau as out of scope.
9. Milestone 3b: the machine-contract qualification gate for the stable core
    (`inspect`, `disasm`, `validate`, `export`, `capabilities`, `diagnostics`,
    `schema`) becomes a required routine CI job, every JSON/JSONL example in the
    documentation executes against the live schemas in a test, the remaining commands
    carry an experimental label on every surface, and the partial-facts truncation
    marker ships as an experimental flag.
10. Milestone 3c: the 1.x compatibility policy in the machine-interface reference and
    the release-notes compatibility statement template in the release procedure.
11. Milestone 4a: runtime and peak-memory tripwires for the five named workloads, each a
    falsifiable assertion with its threshold defined once and documented.
12. Milestone 4b: a seed corpus for every maintained fuzz target, drawn from the
    generated corpus, and one representative time-bounded fuzz campaign with a retained
    artifact and the published configuration, corpus identity, and result format for
    the evidence bundle.
13. Milestone 4c: the chunk mutator with a ground-truth manifest per variant, and
    Prometheus-generated control-flow-flattened inputs at each preset strength as
    analysis stress cases.
14. Milestone 4d: the public hostile-chunk corpus in its own repository with a
    provenance manifest per chunk, seeded from fuzz findings, width probes, and mutator
    output, and the upstream offer to the corpus that OSS-Fuzz's Lua project clones.
15. Milestone 5, LNUM32: contract (new candidate identity, authenticated authority and
    patch series, prerequisite gates by identity), then implementation with the candidate
    manifest retained in a GitHub release, the out-of-profile refusal proof, the
    investigation-record template, and the internal uncoached investigation.
16. Milestone 5, EdgeTX: contract (pinned EdgeTX revision and `edgetx-luac` build recipe,
    the `lua5.3-edgetx32` profile and layout, the consistency-diagnostic rule for
    host-built long strings, GPLv2 sdcard inputs recorded per case), then the
    implementation that turns the survey matrix row green with `luad` the only tool that
    also names the inconsistency, and symmetric rejection against stock 5.3.
17. Milestone 5, Lua 5.4.9: contract (pinned archive and compilers, the 5.4.8-to-5.4.9
    delta review), then the 5.4.9 release gate over the generated corpus and its
    candidate dispatch.
18. Milestone 5, stock Lua 5.1.5: contract, then the stock release gate and its
    candidate dispatch.
19. Milestone 6a: README reduction, one firmware-researcher guide, one machine-consumer
    example that cross-checks published facts against unluac-rs or rizin, exact-version
    format notes, and the fresh-session transfer record.
20. Milestone 6b: a production publication mode for the release workflow (today only
    the rehearsal path exists), then the freeze change (version, release notes,
    compatibility statement, completed security checklist, tripwire record, extended
    campaign rerun).
21. Milestone 6c: with the frozen candidate on remote `main`, tag `v1.0.0`, publish,
    download every public artifact into a fresh environment, and repeat checksum and
    smoke verification. This stage is deleted only after that verification succeeds.

### Milestone 1 — layout truth

Outcome: no chunk whose body contradicts its header is ever reported valid, on any
dialect, and every refusal tells the reader which field lied.

Required work:

- honour every header width byte in Lua 5.1 through 5.5 end to end (parse, reported
  layout, constants, scalar rendering) or refuse it with a diagnostic naming the field
  and the declared width, to the standard the Lua 5.4 header reader already meets;
- report the declared layout, never a stock layout substituted for it;
- add header-versus-body consistency diagnostics: a long-string length field whose
  width contradicts the declared `size_t`, a `LUAC_NUM` or `LUAC_INT` test value
  checked at the declared width, and integral flags that contradict constant tags;
- anchor a body failure caused by a layout mismatch at the offset where the
  contradiction was observed and name the contradicted header field, instead of
  reporting the first downstream symptom at offset 0;
- render a 4-byte float at 4-byte precision on every human and machine surface, never
  widened to double first; and
- retire every diagnostic whose text blames a symptom when the cause is a declared
  width.

Evidence boundary: a width-probe gate takes every maintained fixture in every dialect,
sets each header width byte to every other value, and asserts that the result is
either decoded at the declared width or refused by name, never reported valid with a
stock width; unmodified fixtures remain valid as the negative control. The EdgeTX
chunks are the second control at this milestone: each one is refused with a diagnostic
naming the declared width, never accepted at the header and failed in the body. Reading
them correctly is the EdgeTX profile's acceptance criterion in the exact-target
milestone, not this milestone's.

Stop condition: `validate` cannot return a valid verdict for a lying header in any
dialect. Feature work does not resume until this holds.

### Milestone 2 — authority and corpus

Outcome: every public claim is proven against the compiler that produced the chunk,
and the evidence is drawn from a corpus anyone can regenerate.

Required work:

- generalize the differential oracle from the official `luac -l -l` listing to the
  authority compiler's listing, recorded per profile: the pinned official compiler for
  stock profiles, the OpenWrt LNUM32 build, `edgetx-luac`, and NodeMCU `luac.cross`;
- admit unluac and unluac-rs as independent second decoders in the differential
  harness, consumed as external oracles and never as code;
- generate the stock regression corpus from the per-release official Lua test suites,
  pinned by their published SHA-256 and compiled by the matching pinned compiler, with
  provenance recorded per `CONTRIBUTING.md`, and add permissively licensed real-world
  sources (Kong, Penlight, luvit, the Neovim runtime) for breadth;
- lay out fixtures as family, version, and preset directories with a metadata sidecar,
  and add a per-construct micro-corpus (`adjust01..`, `booleanassign01..`, and so on)
  as the skeleton for control-flow and dominator goldens;
- build an internal layout re-emission generator that re-dumps one chunk under another
  layout tuple, and use it with NodeMCU `luac.cross` to put the 32-bit and integral
  Lua 5.1 fixtures under recorded provenance and to produce cross-layout negative
  controls; a public `luad rewrite` command is a post-1.0 decision;
- seed the analysis fuzz targets from the generated corpus; and
- retire the five shared toy programs as the sole evidence for any dialect.

Evidence boundary: the corpus manifest, the generator script, and every existing oracle
gate pass over the generated corpus; each authority is pinned by archive URL, SHA-256,
build recipe, and platform.

Stop condition: no fixture without recorded provenance remains referenced by a gate.

### Milestone 3 — minimal stable machine contract

Outcome: a shell script, Lua developer, or AI agent can consume one small, documented
interface throughout the 1.x line.

Required work:

- freeze the stable core at `inspect`, `disasm`, `validate`, and `export`, plus
  `capabilities`, `diagnostics`, and `schema`; keep CFG, xrefs, query, diff, explain,
  callees, origins, and relations available and labeled experimental;
- stabilize command discovery, schemas, envelopes, interpretation identity,
  diagnostics, exit codes, stdout/stderr separation, pagination, and resource-limit
  reporting for the stable core;
- retain recursive batch export with per-input outcomes and explicit fact-family
  selection;
- add an experimental partial-facts mode that emits every fact up to a failure with an
  explicit truncation marker, so a firmware triage never receives nothing;
- make every JSON/JSONL example executable against the same schemas as live output;
- define the 1.x compatibility policy for closed variants, open vocabularies, additive
  fields, schema-major changes, target identities, and prototype-content schemes; and
- ensure `luad capabilities --format json --evidence` distinguishes implementation
  presence, experimental evidence, and exact promoted targets, and lists LuaJIT and
  Luau as out of scope rather than planned.

Evidence boundary: one machine-contract qualification gate exercises every stable
command and format at the public CLI, validates live output against schemas, compares
shared facts across text/JSON/JSONL consumers, and includes corruption controls.

Stop condition: after this milestone, an incompatible change to the stable core
requires an explicit schema-major or CLI-major qualification contract; experimental
surfaces may still change with a changelog entry.

### Milestone 4 — hostile-input evidence and the public hostile-chunk corpus

Outcome: every target candidate crosses the same boundedness and fuzzing tripwires,
and the malformed chunks that prove it are published for everyone.

Required work:

- audit every parser allocation and recursive or traversal boundary against declared
  resource limits;
- exercise detection, every parser in the support matrix, post-parse analysis, and
  text/JSON rendering through maintained fuzz targets, each with a seed corpus;
- turn every crash, timeout, excessive allocation, or inconsistent verdict into a
  minimized redistributable regression;
- build a chunk mutator that writes a ground-truth manifest beside each variant
  (constant reordering, dead slots, stripped or restored debug info, permuted opcode
  tables via a map, swapped constant tags, re-emission under another layout), so
  expected facts are known by construction;
- generate labeled control-flow-flattened inputs with Prometheus over this
  repository's own sources, at each preset strength, as analysis stress cases;
- publish the hostile-chunk corpus in its own public repository, one provenance
  manifest per chunk, seeded from fuzz findings, width probes, and mutator output, and
  offer it upstream to the corpus that OSS-Fuzz's Lua project clones;
- record runtime and peak-memory tripwires for small input, a large instruction vector,
  deep prototypes, long strings, and the firmware-scale mixed workflow; and
- retain bounded fuzz smoke in routine CI and run one representative time-bounded
  campaign on the 1.0 candidate.

Deferred from the 1.0 path: runner isolation for public-fork pull requests waits for
the first external pull request; the standalone security-review packet folds into the
release procedure's checklist.

Evidence boundary: CI proves that every maintained target executes under the common
smoke envelope, each tripwire has a falsifiable assertion, and the published corpus
reproduces every retained regression.

Stop condition: any known panic, unbounded allocation or traversal defect, unexplained
timeout, or P0 correctness or security defect blocks qualification.

### Milestone 5 — exact targets in niche order

Outcome: the promotion machinery proves two vendor profiles and two stock targets, in
the order that serves the unfilled niche first.

**LNUM32.** As previously specified: issue a new candidate identity for the current
revision rather than reusing the superseded `lua51-lnum32-0.1.0-rc1`; authenticate the
Lua 5.1.5 source, OpenWrt revision and ordered patch series, build recipe, platform
compiler binaries, fixtures, profile, and exact layout; reference the accepted
public-read, validator, diagnostic, machine-contract, retrieval, scalar-rendering,
export-bound, and hostile-input prerequisites; prove that open argument/result windows
cannot erase a callee already established in an unaffected register; run one internal
uncoached investigation; prove that an out-of-profile sample fails with an actionable
diagnostic; minimize every reproducible
finding before promotion.

**EdgeTX Lua 5.3 32-bit.** Pin the EdgeTX revision and the `edgetx-luac` build recipe as
the authority; qualify the `lua5.3-edgetx32` profile with this repository's MIT sources
and EdgeTX SD-card scripts (GPLv2, recorded per case) as inputs, stripped and
debug-bearing; define the profile's treatment of a host-built chunk whose long-string
lengths contradict the header slot (a named consistency diagnostic, never a parse);
require the survey matrix row to be green with `luad` the only tool that also names the
inconsistency; prove symmetric rejection between `lua5.3-edgetx32` and stock 5.3. This
stage converts the layout-truth milestone's named refusal of the 4-byte Lua 5.3 layout
into a correct read under the explicit profile.

**Stock PUC Lua 5.4.9.** Pin the final archive, official compiler binaries, reference
manual, source tables, fixtures, and exact standard layout; review the 5.4.8-to-5.4.9
delta and accept prior evidence only for facts the delta proof preserves; qualify
parsing, byte accounting, physical instruction roles, typed operands, constants,
prototype and upvalue identity, targets, source lines, validation, deterministic scalar
rendering, text/JSON/JSONL agreement, and malformed-input behavior over the generated
corpus; require the official listing plus an independent decoder and corruption
controls.

**Stock PUC Lua 5.1.5.** Pin the official authority and the exact little-endian 64-bit
`size_t`, non-integral-double layout; prove profile selection and symmetric
stock-versus-LNUM rejection; qualify closure descriptors, `SETLIST C == 0` data words,
stripped and debug prototypes, constants, offsets, jump targets, and bounded
malformed-input handling; keep big-endian and other Lua 5.1 layouts experimental.

Evidence boundary: each target's promotion gate emits its own manifest only after all
clean prerequisite results, platform attestations, mutation probes, and the aggregate
check close over one revision with zero required skips.

Stop condition: promote exactly the four named profiles and layouts. Capability and
documentation records name each exact layout and never collapse into a broad
`Lua 5.x supported` claim.

### Milestone 6 — transfer and one frozen 1.0

Outcome: the release can be understood and used without access to the implementation
history, and one revision, one support matrix, and one set of artifacts can be
independently verified after publication.

Required work:

- reduce the README entry path to purpose, exact support table, installation, three
  first commands, limitations, and links;
- provide one firmware-researcher guide and one machine-consumer example; the worked
  consumer cross-checks `luad`'s facts against unluac-rs or rizin using only published
  output, without embedding sink, taint, or exploitability policy;
- publish exact-version format notes with links to the relevant official Lua and
  vendor sources;
- commit customer-trial records using a stable template while excluding private
  firmware and investigation-specific security judgments;
- freeze a clean candidate, run each promotion gate with its exact authority and no
  required skips, run the aggregate check and the extended fuzz campaign once, build
  both platform archives with the existing packaging and SBOM machinery, assemble the
  evidence index, confirm that capabilities, README, security policy, release notes,
  schemas, and artifacts identify the same targets and revision, tag `v1.0.0`, publish,
  and verify fresh downloads.

No new release infrastructure is built before 1.0 beyond the production publication
mode that the rehearsal path lacks; the archive, SBOM, bundle, and rehearsal that exist
are sufficient.

Evidence boundary: a fresh human or agent installs the packaged candidate and completes
inspection, disassembly, validation, and export using only published help and
documentation; the published artifacts verify against the retained evidence.

Stop condition: documentation never calls an experimental dialect supported, never
implies affiliation with Lua.org or PUC-Rio, and never makes a security conclusion from
static facts. A failed or partial publication does not change capability status; use
the documented rollback procedure, correct the bounded defect, issue a new candidate,
and rerun only the invalidated evidence.

## Version 1 acceptance

Version 1 is eligible only when all of these statements are true for the exact promoted
targets:

1. No maintained fixture, generated corpus chunk, or width-probe variant is reported
   valid when its header and body disagree, on any dialect, and every refusal names the
   contradicted field.
2. Every maintained release fixture crosses the public CLI and agrees with the pinned
   authority compiler's listing plus an implementation-independent decoder.
3. Mutation probes prove that gates reject wrong opcodes, operands, constants, roles,
   targets, metadata, schema fields, and evidence substitutions.
4. Text, JSON, JSONL, and export consumers agree on shared facts and remain
   deterministic across advertised hosts, including floating-point rendering at the
   declared width.
5. Resource limits, malformed-input tests, the extended fuzz campaign, and clean builds
   support the safety claim, and the hostile-chunk corpus is public.
6. The capability manifest, release evidence, documentation, SBOM, checksums, and
   downloadable artifacts identify the same targets, revision, and limitations.
7. A fresh human or agent can install the tool and complete the documented inspection,
   disassembly, validation, and export workflows using only public help and examples.

## Post-version-1 research

### Additional targets

Promote one exact target at a time in customer-value order. Lua 5.2, stock 5.3, 5.5,
and additional stock layouts may reuse the stock-Lua qualification contract. A vendor
profile is a candidate only when a public first-party compiler or a vendor GPL source
drop can serve as its authority. The current candidates, in customer-value order, with
their authorities recorded in
[docs/PRIOR-ART-AND-CORPORA.md](docs/PRIOR-ART-AND-CORPORA.md):

- OpenTX and EdgeTX 2.10 Lua 5.2 (`size_t` 4, `lua_Number` 8) from the firmware source.
- NodeMCU Lua 5.1 integral and byte-swapped layouts (`luac.cross`), and NodeMCU LFS
  images as a multi-prototype container.
- Playdate Lua 5.4 32-bit with appended opcodes (`pdc`).
- TP-Link AX1800 Lua 5.1 with a reordered opcode table (vendor GPL drop).

### Profile facilities

- Opcode-table maps and constant-type-tag maps are explicit, provenance-bound profiles,
  file-compatible with the `.op N name` and `.type N kind` formats that unluac users
  already have for shipped games and routers.
- Deriving an opcode map from a canary chunk compiled by the target VM is a separate
  tool, never a default.
- Declarative dialect descriptors, so a new vendor layout is data rather than a fork of
  the parser.
- A layout-tuple fact that names the likely origin ecosystem of a chunk without
  asserting it as a dialect selection.
- A public `luad rewrite` command that re-emits a chunk under another layout tuple,
  promoted from the Milestone 2 internal generator.

### Corpus and authority sources

- Fixtures compiled from GPL sources record that license per case, following the
  `tests/fixtures/embedded/MANIFEST.json` convention; share-alike, proprietary, and
  malware-derived samples never enter the tree.
- The stock regression corpus and the hostile-chunk corpus receive a citable dataset
  record once a release depends on them.

### Ecosystem contributions

- A WASM build of `luad` for a browser drop-target and for embedding in other tools.
- A `luac.ksy` for the Kaitai Struct format gallery, a Lua 5.5 ImHex pattern, and an
  exporter that feeds `luad`'s structural model to rizin, all derived from this
  repository's model rather than imported.

### Bounded value and call facts

Before expanding value analysis, run a design spike over representative public chunks
and measure the proportion of call sites resolved under deliberately conservative
rules. A proposal must define join, loop, alias, capture-mutation, and cutoff semantics
before committing to a stable schema. Path-specific facts must not be replaced by a
union over unrelated paths or callers. The first admissible increments are
intraprocedural and evidence-linked. SSA, whole-program interprocedural dataflow,
high-level expressions, and security classification remain outside version 1.

### Outside validation

The first 1.1 obligations are the two checkpoints that need a participant outside the
project:

- an outside-human in-profile trial: pre-screen an authorized public firmware sample only
  far enough to establish that it resolves to the exact LNUM32 profile, then hand an
  outside human the released binary and public quick start without coaching, and record
  commands, elapsed work, incorrect or ambiguous answers, and remaining workarounds; and
- Lua community review of terminology, target claims, build instructions, and
  surprising output, with each correction landing as its own bounded change.

Version 1.0 rests on the internal uncoached investigation, the out-of-profile refusal
proof, and the fresh-session transfer record. Those are usability evidence from inside
the project; independent adoption evidence arrives with these checkpoints, and no 1.0
document may describe the release as externally validated before they close.

### Other deferred surfaces

Promotion of CFG, xrefs, query, diff, explain, callees, origins, and relations to the
stable contract; a stable partial-facts mode; decompiler output, source reconstruction,
an assembler, execution, tracing, persistent research state, GUI/TUI work, hosted
services, and policy-bearing security analysis all require separate post-1.0 product
decisions.

## Sequencing rules

- Silent incorrect answers interrupt planned feature work. A lying header reported
  valid is a silent incorrect answer.
- A vendor profile enters only with a public authority compiler or GPL source drop.
- No target is promoted before the stable contract and the boundedness tripwires freeze;
  changing either afterwards requalifies every promoted target.
- Release infrastructure is complete for 1.0 except the production publication mode;
  it absorbs no other work before the release.
- Schema promotion precedes compatibility promises. Experimental fields and commands
  remain labeled as such.
- Private or downloaded corpora may find defects and measure usefulness but never
  replace redistributable fixtures and independent authorities.
- A release checkpoint measures an external user outcome, but self-run evaluation is
  usability evidence rather than independent adoption evidence.
- Waiting for an outside participant does not authorize unrelated product work. A
  disjoint documentation, packaging, or evidence-retention batch may proceed only under
  its own sprint contract.
- One gate per release claim is preferred over a public thicket of badges. Internal
  prerequisite gates remain discoverable through the evidence manifest.

## Preserved planning provenance

The archived [2026-08-25 roadmap and release-readiness
review](docs/reviews/2026-08-25-roadmap-review.md) records the exploration that exposed
the open-window replay, fuzzing, manifest, publication, string-limit, performance,
customer-transfer, external-layer, documentation, and distribution gaps. The
[prior-art and corpus survey](docs/PRIOR-ART-AND-CORPORA.md) records the ecosystem
evidence behind the current ordering. Both remain point-in-time inputs rather than
current status; this roadmap preserves their concerns as forward obligations.
