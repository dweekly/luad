# Changelog

All notable changes are documented here. `luad` is a 0.x experimental tool: no dialect
is promoted to a supported tier and no interface carries a compatibility promise yet.

## Unreleased

- Add an unmodified LuCI 22.03 `util.lua` beside the 23.05 subset, and tests making the
  release comparison executable. The prototypes without a content-digest match are
  pinned and checked against the textual source diff in debug and stripped builds, a
  one-token edit control is included, and luad's validated layout must predict exactly
  when the official Lua 5.1.5 lister accepts an artifact (stock versus LNUM32).

- Add `callers` to the export reference consumer: one-hop callers of a prototype answered
  offline from a verified bundle's records, with the same exactly-once call-site classes
  as `luad callers`. It joins only on full record context plus the call id. Capped,
  incomplete-family, out-of-inventory and non-5.1 targets refuse. Tests require
  agreement with `luad callers` on the fixture corpora and the vendored LuCI subset.

- Add a pinned, unmodified LuCI subset (openwrt/luci `openwrt-23.05` at 3d39e8c,
  Apache-2.0) with tests that compile it with official Lua 5.1.5 and check every listed
  same-artifact caller against its source line: the call instruction must sit on a line
  that calls the target by its declared name. Pins a few caller answers with their
  argument evidence and the strict link index's current admission boundary.

- Add experimental `luad callers`: the observed one-hop callers of one Lua 5.1 prototype
  across an explicit corpus. It combines accepted same-artifact call relations,
  convention-gated cross-chunk links and verbatim argument origins, with no new
  resolution rule. Every other call site is counted in exactly one class (conflicting,
  degraded, attributed elsewhere, unmapped label, unattributed), so the counts per file
  sum to its call sites. Limit or index uncertainty is marked `degraded`, so it cannot
  pass for a clean negative. Partial coverage exits 1 and limits exit 5. New
  `callers` schema; no existing schema changes.

- Stop the Lua 5.2/5.3 validators from checking `SETUPVAL` operand B as a source register
  (#108). B is an upvalue index and keeps its upvalue bound; A remains register-checked.
  Official compiler output whose upvalue index exceeds the writing function's stack no
  longer reports false `L52-REG-002`/`L53-REG-002` errors.

- Refuse unavailable structured disassembly, effects and explanation on Lua 5.2/5.3/5.5 instead of a
  generic projection with zero opcode fields and omitted children. Preserve unverified
  human text listings and their existing all-version scalar-rendering proof. Default/instruction
  export now emits framed per-file failures instead of panicking on those nested inputs.
  Explicit fact selections use an exact profile allowlist and fail before publishing
  partial facts; raw structural inspection/export remains available across all five
  currently read PUC versions. Unknown profiles acquire no availability by default.
  Existing Lua 5.1/5.4 public disassembly and implicit Lua 5.4 export stay available.
  Required official-compiler debug/stripped controls cover selectors, formats, caps,
  mixed/strict completion, raw child facts and reference-consumer failure accounting.
  Retain existing bounded parse diagnostics and limit exit status on refused files;
  explanation selector dispatch cannot bypass profile refusal or report empty success.
  No new decoder, schema version, archive identity or support tier is introduced.

- Add a bounded export reference consumer with executable/input/schema/stream identities,
  offline schema and completion verification, exact record context, explicit mixed-file
  coverage and truncation, and corruption controls. This experimental example does not
  add a decoder, qualify analysis semantics or promote any target. Public replay also
  reproduced default/instruction export crashes on nested Lua 5.2/5.3/5.5 inputs; the
  reader refuses those attempts and the docs name the structural-selection workaround.
  Replace unsafe SQL
  interpolation guidance with verified, identity-scoped joins and bound parameters.

- Encode nonfinite machine floats as canonical `nan`, `inf`, `-inf` strings, retaining
  finite JSON numbers, raw source bits and Rust f64 field types. The current schema
  number/string union replaces schema-invalid null values; envelope/JSONL versions
  stay unchanged in the experimental interface. Decoded NaNs carry a class, while
  payload/sign remain in raw evidence. Exact JSON float parsing fixes a reproduced
  one-bit finite round-trip loss. Required source-generated controls cover all five
  PUC dialects, four/eight-byte source floats, tagged model owners and malformed tokens.
- Reject nonmatching Lua 5.3-5.5 LUAC_NUM header sentinels exactly, including NaNs that
  an epsilon comparison accepted. Official loader/listing controls reject the same
  header mutations; valid header twins pass. No crafted bytecode is executed and no
  target/support tier is promoted.

- Include emitted `parameter_field` records in the typed export schema. Actual default,
  selected-origin, mixed-failure and capped CLI streams exercise all sixteen record
  variants; corrupted tags, field access/parameter types and missing context are rejected.
  Record payloads and schema versions are unchanged. Individual record validation does
  not establish stream completion or correct cross-record identity joins.

- Discard stale Lua 5.1 call-frame facts across callee, argument-origin and capture
  analysis. All CALL result families invalidate the temporary tail before preserving
  explicit results; the combined generic iterator also invalidates its conditional
  control update. Reachable tailcalls cannot preserve overlapping captured cells.
  Reconstructed tables obey the same boundary in definition scans and retained aliases.
  Ordinary live locals, fresh definitions and exact require results remain useful;
  companion/unreachable words do not manufacture capture writes. A clobbered symbolic
  caller no longer supplies a cross-chunk target. Raw/encoded IR facts, machine shapes
  and capability tiers are unchanged. Required official-compiler controls exercise
  the family without executing crafted bytecode.

- Make explicit `luci-module-setglobal` links conditional on an admitted straight-line
  root initialization. Final root stores replace stale closure candidates; nested
  function bodies cannot invent exports. Unproved declarations, root calls/table
  mutation, missing/corrupt providers and exhausted admission preserve uncertainty.
  Total retained definitions are capped in canonical artifact order; an incomplete
  index no longer turns a singleton into a unique target. Public required-compiler
  controls cover overwrites, aliases, clobbers, child bodies, input permutations,
  cutoffs and selected JSONL composition. Crafted module-call stack reads and escaped
  selector aliases preserve uncertainty; initialized post-call values remain useful.
  Proof-chain and index-label copying have explicit limits. Linking rejects bytecode
  stdin and documents the immutable-corpus precondition of its two-pass interface.
  This narrows experimental linking and promotes no supported target or runtime
  reachability claim.

- Fix false `diff` equality for same-count constant replacements, exact float/string
  representations, capture descriptors, varargs, child changes, header/layout fields,
  trailing bytes and same-length debug changes. Comparison is positional decoded
  content, not behavioral equivalence. `--semantic` conservatively retains physical
  bits and shows decoded fields/roles without copying constant payloads per use;
  `--ignore debug` excludes all compared debug names/lines/scopes and rejects typos.
  JSONL now retains chunk-wide differences in the root `diff_prototype` record.
  Required official Lua 5.1.5 public source-pair tests exercise all formats and modes.

- `gate-argument-origins-lua51` now pins argument-level origin verdicts on the committed
  OpenWrt-derived 32-bit LNUM authority chunk, not only its profile. Structural counts cannot
  catch a precision regression -- the 0.3.0 origins regression left instruction, prototype and
  call-site counts identical while changing answers -- and no non-stock layout had a pinned
  verdict. One of the two pinned verdicts resolves a preserved float literal, which depends on
  decoding numbers under `num=8,integral_flag=4`, so it fails if the layout handling moves and
  not only if the dataflow does. The pinned set is exact, so a new call site cannot stand in
  for a regressed one, and the chunk is a `required_fixtures` entry of the gate.

- `luad origins` now reports each prototype's parameter field accesses: every constant-key
  table access whose base resolves to one of its own parameters, with the parameter index, the
  key path from the parameter outward, whether it reads or writes, and instruction and
  constant evidence. This answers which keys a `function handler(params)` reads out of
  `params`, which previously required reading a flat constant dump and inferring the contract
  from adjacency -- proximity rather than evidence. The base is resolved by the dataflow, not
  by register number, so a reassigned parameter register reports nothing and a key read off
  any other base is excluded. `SELF` counts as a read. A `SETTABLE` key is read by operand
  position, since both its key and its value can be constants and taking the first constant
  anywhere in the instruction names the assigned value as the key. The `origins` schema gains
  `parameter_fields` on each prototype, and both streaming paths carry the facts as
  `parameter_field` records: `origins --format jsonl` and `export`, whose `origin` family
  covers them, so a prototype with a contract and no calls is not an empty record set.

- Stop reporting Lua 5.1 table-literal fields that a callee may have overwritten. The
  reconstruction already detected that a table had been passed to a callee or stored to a
  global or upvalue, but recorded it as `incomplete: true` while still emitting the fields
  read before that point. `incomplete` means a field could not be reconstructed, so
  `{"dir": "/etc"}, incomplete` read as "`dir` is `/etc`, other fields may be missing" when
  `dir` was exactly the value in doubt. Only fields written after the last escape are now
  reported, and the escape itself marks the contents `incomplete` whether or not a field was
  dropped, because the holder may have added a key this prototype never writes. A table with
  nothing left to report carries no contents. A call that cannot reach the table still changes nothing. This
  is a defect present in 0.3.1, verified against that tag, and independent of the other
  changes here; the previously pinned behaviour is corrected rather than preserved. A consumer
  holding results from 0.3.1 can find exactly which records this moved without re-deriving
  anything: `export --format jsonl` is deterministic, so build at `8f0890c` (the commit before
  this change) and at `main`, export the same inputs with both, and diff the `record_type`
  `origin` lines; each differing record names its `call_id`. The intervening commits add only
  new `parameter_field` records and a new `arguments` array on an `open` argument window, so an
  `origin`-only diff over that range isolates this correction. Diff against `main` rather than
  `0b6e8c1`: this change shipped with a defect of its own at that commit, corrected in
  `27e5e4b`.

- Reconstruct a Lua 5.1 table access whose key is a register, where the key register holds
  only literals. `GETTABLE`/`SELF` reported `dynamic-key` whenever the key was not the
  instruction's own constant operand, without consulting the key register at all, so
  `local k = "dir"; sink(params[k])` collapsed the whole argument. One literal key now names
  one field; a key chosen by a branch names one field per key. A key that is not determinable
  -- a call result, a loop variable -- still reports `dynamic-key`, because a field cannot be
  named without naming its key. A reconstructed key carries no constant id.

- Report the determinable prefix of an open argument window in Lua 5.1 origin analysis.
  `CALL`/`TAILCALL` with a top-dependent argument count emitted only `open-argument-window`
  and discarded every argument, including the ones at fixed registers below the tail:
  `sink("rm -rf " .. params.dir, "flag", helper())` reported nothing at all, losing the one
  argument a reader of a shell-shaped call came for. The window stays open and still reports
  its reason; it now also carries the prefix, dense from index zero with registers contiguous
  from the callee, covering every determinable position rather than only the resolved ones so
  no position is reassigned. The prefix is bounded by the open-result marker and is empty
  without it, because counting registers to the frame size instead would report arguments the
  call does not have. The `origins` and `export` schemas gain the field.

- Resolve the `a or b` and `a and b` idioms over locals in Lua 5.1 origin analysis. `TESTSET`
  had no transfer function, so its write fell through to the unmodeled-write default and the
  tested branch was reported as `unknown:overwritten`. It is now modeled per edge: the assigned
  value reaches the successor that performs the write, the destination's prior contents reach
  the one that skips it, which is a distinction the control-flow graph already carried as
  `conditional-skip`. On `tests/fixtures/origins_testset.lua`, `local chosen = primary or
  secondary` moves from `alternatives(parameter[1] | unknown:overwritten)` to
  `alternatives(parameter[0] | parameter[1])`, and a chained `a or b or c`, where one hole
  swallowed two parameters, moves from `alternatives(parameter[2] | unknown:overwritten)` to
  all three. Folding both outcomes into one state instead would be unsound in the other
  direction, putting the retained value on the edge that assigns; `gate-argument-origins-lua51`
  pins that it does not.
- `docs/MACHINE-INTERFACE.md` now states what `overwritten` means: a register write the
  analysis does not model, which is why it also covers a register written more than once. It
  was previously readable as a claim that a bounded reaching set had been found and discarded.

- `luad --help` and the unrecognized-subcommand error now name the command that answers each
  reader's question, and state plainly that there is no decompiler, pointing at `luad inspect`
  plus unluac for readable source and at `docs/examples/RECIPES.md` for worked chains. The
  subcommand list named mechanisms only, so a reader who guessed `luad decompile` got a verb
  list that could not distinguish an absent capability from a misspelling. The map prints to
  stderr; machine stdout is unchanged.

- Keep the resolved side of a partly unresolved control-flow join in Lua 5.1 origin
  analysis. A join whose reaching definitions include an `Unknown` collapsed to
  `control-flow-conflict`, discarding the definition that did resolve and flattening the
  unresolved one's own reason; it now emits the `alternatives` set with that definition as
  an option carrying its reason. On `tests/fixtures/origins.lua` the root-kind histogram
  moves `unknown` 8 to 7 and `alternatives` 3 to 4, with no origin losing an expression.
  `has_unknown` is public so the previous conservative reading stays derivable from a set.
- Fix stale table contents surviving a write through an alias, in origin analysis. The alias
  check compared the whole slot expression against the whole mutated register, so a table
  nested inside a larger expression was missed, and so was a write through a register
  holding a set of reaching definitions. Both sides are now enumerated: the check recurses
  into subexpressions and matches each table option of the mutated register. The second half
  is a defect present in 0.3.1 and independent of the join-site change, reachable whenever
  two differently shaped bounded sets range over the same table; the join-site change widened
  how easily it is reached. Invalidation stays targeted rather than blanket, so a table that
  is not an alias of the mutated register keeps its expression.
- `control-flow-conflict` is now reserved for a loop-carried value widened at
  `MAX_BLOCK_REVISITS`, where the set of reaching definitions is not finite. It still
  absorbs a join, which termination depends on: widening to a bounded set there was tried
  and reinstated the unbounded lattice growth that 0.3.1 fixed.

## 0.3.1 — 2026-09-18

- Fix Lua 5.1 origin analysis exhausting its transfer-step budget on functions that
  contain loops. Loop-carried slots whose value kept growing on every pass now widen to
  `control-flow-conflict` after a bounded number of block revisits, so every call outside
  the loop keeps its exact origin instead of the whole prototype reporting
  `analysis-limit` (144 to 17 `analysis-limit` results across a 260-file firmware corpus).
- Add the project logo and CI, Codecov, release, and dual-license badges to the README.
  Publish measured Linux line coverage from the workspace suite and instrumented CLI
  subprocesses through a separate coverage workflow.

## 0.3.0 — 2026-09-18

- Emit closed `prototype` expressions with child prototype paths and physical PC
  evidence for proven `CLOSURE` call-argument definitions in Lua 5.1 origin analysis
  (R-1c).
- Reconstruct constant-key table-literal origin expressions (`TableLiteral`) with
  deterministically sorted fields, write evidence, and visible partial cutoffs
  (`incomplete: true`) for request-shaped objects in Lua 5.1 origin analysis (R-1a).
- Emit closed `alternatives` expressions containing deduplicated, deterministically
  sorted candidate origins with reaching evidence when bounded definitions reach a
  control-flow join in Lua 5.1 origin analysis (R-1b).
- Add corpus-wide `query --input-list <file|-> --where <expression>` supporting streaming
  JSONL batch queries across file lists or stdin with per-input identity, stream framing,
  failure/skip retention, limit truncation, and strict-mode exit semantics (R-4).
- Fix query expression tokenizer hang on invalid expressions containing single '=' or '!'
  characters.
- Add export fact-family discovery and canonical registry (`ExportFactFamily`,
  `EXPORT_FACT_FAMILIES`) exposing `export: ExportCapability` in `CapabilityManifest` and
  `luad capabilities`, documenting valid families in `export --help`, and reporting sorted
  valid families on unknown `--facts` arguments (R-5).
- Add convention-gated cross-chunk linking (`--link-convention luci-module-setglobal`)
  enabling corpus-wide module indexing and inter-artifact call-site resolution in batch
  export, emitting auditable `cross_chunk_link` facts with explicit statuses (`resolved`,
  `absent`, `duplicate`, `dynamic`, `unsupported`, `limit_exceeded`), order-invariant
  indexing, fail-closed corpus and fact limits, and `link.schema.json` (R-2).

## 0.2.0 — 2026-09-17

Experimental correctness and firmware-workflow release. No dialect is promoted to
supported, and machine interfaces retain their 0.x compatibility status.

- Validate declared layouts and numeric canaries for Lua 5.2, 5.3, and 5.5; decode
  implemented widths and refuse unsupported declarations with anchored diagnostics.
- Expand version-specific operand checks and refuse derived analysis for Lua 5.2,
  5.3, and 5.5 while keeping structural inspection and validation available.
- Preserve parse-failure provenance through CLI and batch export, distinguish
  unsupported formats from malformed inputs, and handle broken pipes quietly.
- Bound input reads, string declarations, traversal, diagnostics, and subprocess
  monitoring; cover hostile-input cases and budget breaches with regression tests.
- Add a public firmware-shaped walkthrough with mixed-input inventory, constants,
  global queries, raw disassembly, and explicit profile boundaries.
- Publish Linux x86-64 and macOS ARM64 archives with checksums, a deterministic
  CycloneDX source SBOM, and GitHub build-provenance attestations. Publication uses
  accepted CI artifacts and verifies fresh downloads.

- Keep stdin workers under the subprocess tripwire deadline, including descendants
  that hold only stdin open. Cleanup joins only finished workers after its grace period.
- Remove the simulated unluac oracle and pinned decompiler requirement from the
  firmware walkthrough. Required tests verify luad facts and refusal behavior;
  third-party decompilation is an optional, separately validated experiment.
- Correct the walkthrough's input glob, expected manifest exit status, and completeness
  guidance; verify every manifest exit status against the CLI.

## 0.1.0 — 2026-09-16

First public release. `luad` reads compiled Lua bytecode and reports the exact format a
chunk was built for, its instructions, constants, and closure bindings, with byte-level
provenance for every fact. It is useful today on Lua 5.1 and 5.4 chunks, including the
non-standard layouts found in extracted router firmware, and it is published as
experimental rather than held back until a 1.0 evidence program completes.

**What works.** `inspect`, `disasm`, `validate`, `explain`, `export`, and `diagnostics`
across Lua 5.1 through 5.5, with published schemas. Output formats vary by command:
`inspect`, `disasm`, and `explain` emit text, JSON, and JSONL; `validate` and
`diagnostics` emit text and JSON; `export` is a streaming batch interface and emits
JSONL only. The README has the full matrix. Profile
detection distinguishes OpenWrt-style LNUM32 builds from stock layouts. Analysis
commands (`cfg`, `callees`, `callgraph`, `origins`, `xrefs`, `query`, `diff`) are
present and explicitly experimental. The workspace forbids `unsafe` code.

**Known defects.** Lua 5.2 and 5.3 do not fully honor or refuse declared header widths
by name, which can produce a confident wrong answer rather than an error; treat their
output as a hint. EdgeTX chunks fail inside the body with a diagnostic anchored at
offset 0. See the README for the current limitations table.

**Scope.** LuaJIT and Luau are separate bytecode systems and are out of scope. The
capability manifest lists the five stock Lua dialects and nothing else; no dialect
occupies the `planned` tier.

**No support claims.** The supported dialect set is empty. "Valid" means consistent with
the selected format and the named checks, not safe to execute or of known origin.

### Release planning

- Focused the 1.0 roadmap on a complete extracted-firmware workflow and two exact
  profiles: OpenWrt LNUM32 and stock Lua 5.1.5. Deferred EdgeTX, stock 5.4.9, broad
  corpus generators, and partial-facts recovery; moved executable walkthroughs and an
  outside researcher trial before interface freeze. Aligned the PRD and release policy,
  bounded diagnostic claims to observable evidence, and replaced exclusivity goals
  with task-specific tool handoffs and upstream cooperation.

- Refocused the roadmap on the verifier-and-fact-source niche: layout truth (every
  declared header width honoured or refused by name) is Milestone 1 and precedes all
  feature work; the differential oracle generalizes to the producing compiler's listing
  with unluac and unluac-rs as independent second decoders; the stock regression corpus
  is generated from the per-release official test suites; the 1.0 boundary gains EdgeTX
  Lua 5.3 32-bit as a fourth target; the 1.0 stable contract shrinks to `inspect`,
  `disasm`, `validate`, `export`, `capabilities`, `diagnostics`, and `schema`; the
  hostile-chunk corpus becomes a public artifact; LuaJIT and Luau move from planned to
  out of scope; no further release infrastructure is built before 1.0. The PRD's
  prior-art table now describes rizin, unluac, unluac-rs, luac-parser-rs, and
  LuaDecompiler as measured. The release execution sequence now opens with the Lua 5.2,
  5.3, and 5.5 header-width slice of Milestone 1; the sprint checkpoint stays neutral
  until that stage's pull request places the contract, per the contract lifecycle.

### Testing

- Added `test_target_boundary_agreement`, which holds the version-1 target boundary
  together across the release procedure, roadmap, and product requirements. The frozen
  boundary table is the authority; the test fails when another document names a
  different profile set or count, or schedules an out-of-scope dialect as future work.
  Verified by mutation: dropping a profile from the requirements and changing the
  stated count each fail the test.

### Documentation

- Added a tool-comparison matrix to `docs/PRIOR-ART-AND-CORPORA.md`: official `luac`,
  luadec, rizin, ChunkSpy, luac-parser, unluac, unluac-rs, and `luad` on the same
  EdgeTX chunks and on a width-probed stock chunk, with a README summary section and a
  roadmap line for hosting a public hostile-chunk corpus.
- Added `docs/PRIOR-ART-AND-CORPORA.md`, a survey of external tools, datasets, and
  bytecode-emitting ecosystems against the product scope, with candidate fixture sources
  and their license constraints. Its EdgeTX spike shows that a 32-bit Lua 5.3 chunk with
  a 4-byte `lua_Number` is accepted at the header and then fails inside the body with an
  offset-0 diagnostic. `ROADMAP.md` gains vendor-profile candidates with named
  authorities, corpus and authority sources, profile facilities, and ecosystem
  contributions under post-version-1 research.

### Repository setup

- Added `docs/BRINGUP.md` and `scripts/bringup.sh` as the single setup path for a
  developer machine, a self-hosted Actions runner, and a release builder. The script
  reports every required tool with its expected and found version and exits non-zero on
  any mismatch, and installs the missing ones idempotently without root. `scripts/pins.env`
  now owns the tool versions that no manifest already pins, and a pin-agreement test holds
  it, the CI workflow, the compiler-search constant, and the bring-up document together.
  The CI `Test` jobs run the same reporter so it cannot drift from CI. The official Lua
  compilers now install into `$HOME/.cache/luad/lua-tools/bin` and are searched there
  first, because macOS clears `/tmp` on reboot; `/tmp/lua-tools/bin` remains a fallback.
  Integration tests resolve the public `luad` binary through one helper that honors
  `CARGO_TARGET_DIR` instead of assuming `target/debug`.

### Release planning

- Recorded the release execution sequence in the roadmap: the remaining milestones as
  ordered, pull-request-sized stages that are deleted as they merge. Moved the
  outside-human in-profile trial and Lua community review from the 1.0 gates to the
  first post-1.0 obligations; 1.0 transfer evidence is the internal uncoached
  investigation, the out-of-profile refusal proof, and a fresh-session install record,
  and release documentation calls that usability evidence rather than independent
  adoption evidence.
- Aligned the contract lifecycle with that sequence: a qualification stage still merges
  its contract in a dedicated planning change first, while every other stage carries its
  contract in the first commit of its own pull request and restores the checkpoint in
  its last.
- Froze the future version-1 release boundary around three exact target layouts, two
  package platforms, the existing machine-contract majors and exit codes, repository
  ownership, and durable GitHub Release evidence retention. This planning decision does
  not promote a target; existing derived-analysis surfaces remain experimental unless a
  later public-contract qualification explicitly includes them.

### Release packaging

- Routed routine Linux x86-64 and macOS arm64 CI plus the publication rehearsal through
  explicit repo-scoped self-hosted runner labels, with runtime OS and architecture
  checks and the existing exact Rust host-triple checks. The 13-job release evidence
  contract and public support status are unchanged.
- Added a manually dispatched, non-production GitHub Release rehearsal that consumes
  one accepted `main` release bundle without rebuilding it, publishes the exact five
  files as an unsigned non-latest prerelease, verifies fresh asset and source-archive
  downloads, retains the result beyond Actions expiry, and proves corrupted-draft
  cleanup plus valid-release withdrawal with an offline stateful fake-GitHub regression.
  Hosted follow-up hardened cleanup for drafts without Git refs and pinned the normalized
  tagged-release roots emitted by GitHub CLI for both source archive formats.
- Added a bounded non-promoting release-bundle assembler and verifier. It composes the
  accepted Linux and macOS archives, canonical CycloneDX SBOM, and same-revision hosted
  result references into the conventional five-file release set, with a canonical
  four-entry `SHA256SUMS` and an evidence index that retains archive ledgers and install
  smokes while requiring an empty promoted-target set. Hosted CI assembles twice,
  byte-compares every file, verifies composition, and rejects corruption; its seven-day
  upload is not publication or durable authority.
- Added required hosted release-archive evidence for `linux-x86_64` and
  `macos-aarch64`: two independent Rust 1.97.1 build jobs per platform must produce
  byte-identical archives, ledgers, checksums, and installation transcripts before a
  verified two-platform checksum bundle is retained for seven days as diagnostic
  transport. The workflow includes archive-byte and checksum corruption controls and
  does not publish or promote an artifact.
- Added a clean-revision, same-host packaging dry run for the exact `linux-x86_64` and
  `macos-aarch64` release names. It produces a deterministic ustar/gzip archive, exact
  member ledger, `SHA256SUMS`, embedded version/source/platform identity, and installation
  transcript; independently verifies canonical bytes and source inputs; rejects archive,
  checksum, membership, path, mode, or identity corruption; and smokes the extracted
  binary without promoting a Lua target.
- Shipped the Apache License 2.0 text required by the existing `MIT OR Apache-2.0`
  workspace declaration and corrected the canonical repository URL to `dweekly/luad`.
- Added role-specific descriptions, repository, homepage, root README, license, and
  explicit `publish = false` metadata to every workspace package. Removed the contributor
  toolchain value from `rust-version` package metadata because no independent MSRV has
  been established, while retaining the toolchain pin itself.
- Documented and tested a locked local install from a checked-out `luad-cli` source path.
  Crates.io and `cargo install luad` are explicitly not 1.0 distribution channels.
- Established Rust 1.85 as the stable workspace MSRV with locked Linux and macOS build
  and source-install CI, while retaining Rust 1.97.1 for contributors and release
  builders and the separately pinned nightly for fuzzing.
- Added a required locked dependency audit for both release targets and dev dependencies,
  using a pinned `cargo-deny` action, an explicit SPDX allowlist, current RustSec
  advisories, no advisory ignores or license exceptions, and fail-closed yanked and
  unmaintained-direct-dependency policy.
- Added a clean-revision release SBOM command and required hosted check using the pinned
  official cargo-cyclonedx 0.5.9 asset. It writes one deterministic, path-independent
  CycloneDX 1.5 source dependency inventory, binds it to the source revision and lockfile
  digest, independently verifies the locked normal/build graph, and rejects component,
  edge, identity, checksum, scope, timestamp, serial, or host-path corruption without
  claiming platform-specific binary composition.

### Deterministic scalar rendering

- Added one core rendering authority covering canonical 64-bit integers, byte-exact
  escaping with a 64-input-byte preview bound, round-tripping finite floats, signed
  zero, infinities, and payload-independent NaN spelling. Typed resolved-constant
  previews, human disassembly, and the `origins` listing all consume the same policy
  while raw scalar bytes remain available in machine facts.
- Applied the authority on every dialect rather than only the exact Lua 5.1.5 and
  Lua 5.4.8 targets. Rendering takes only the preserved value, so a constant now reads
  the same whichever dialect produced it; previously an identical byte string printed
  in full on Lua 5.2, 5.3, and 5.5 but bounded on the exact targets, and an identical
  NaN printed as `NaN` on the former and `nan` on the latter.
- Made a bounded string preview state its full input length, as
  `"<64 bytes>..." (N bytes)`, so an elision is never confused with a constant whose
  own last three bytes are `...`.
- Extended `disasm --raw` to print untruncated string constants in the text listing.
  Text output was otherwise lossy above the preview bound with no non-JSON recourse.
- Replaced the `origins` text renderer's private literal formatter, which printed
  floats as `float(<raw_hex>)` and strings unbounded, with the shared authority.
  Both declared Lua 5.1 number widths decode: a four-byte binary32 is widened
  exactly as the parser widens it, so it renders as the same value.

### Safety enforcement

- Established a workspace-owned `unsafe_code = "forbid"` lint inherited by `luad-core`,
  every dialect (`lua51`, `lua52`, `lua53`, `lua54`, `lua55`), `luad-analysis`, `luad-cli`,
  `luad-oracle`, and the fuzz workspace without local opt-outs, verified by an executable
  negative control.

### Hostile-input robustness and fuzzing

- Added `fuzz_lua51_analysis` and `fuzz_lua54_analysis` fuzz targets that exercise recursive
  typed disassembly, validation, prototype lifting, CFG construction, whole-chunk xrefs,
  and JSON serialization on successfully decoded strict chunks.
- Seeded all eight fuzz targets (`fuzz_detect`, five stock parser targets, and two analysis
  targets) with maintained exact-dialect compiled fixtures.
- Added a canonical contributor and CI smoke runner script (`scripts/fuzz_smoke.sh`) owning
  the ordered 8-target suite, positive run budgets, per-target outer timeouts, corpus identity
  reporting, and compact JSON evidence emission.
- Added a Linux CI fuzz-smoke job running the canonical smoke suite under a pinned nightly
  toolchain and locked `cargo-fuzz` release with evidence artifact uploading.
- Pinned the resource-detection envelope the campaign relies on (`address` sanitizer, a
  512 MB RSS limit, and a 128 MB allocation limit) in the runner and recorded it in the
  emitted evidence, so unbounded-allocation detection no longer depends on an implicit
  libFuzzer default. A contract test asserts the CI workflow pins agree with the runner
  constants and that CI does not restate the runner's flags.
- Bounded debug-table upvalue-name preallocation in the Lua 5.2, 5.3, and 5.5 parsers;
  hostile declared counts now reach ordinary bounded rejection instead of requesting the
  declared allocation.
- Bounded register-effect arithmetic in the Lua 5.1 and Lua 5.4 semantic lifters. A chunk
  encoding a maximal register operand made derived effect ranges such as `R(A)..R(A+3)`
  overflow their `u8` index and panic; those derivations now saturate, so lifting a
  hostile chunk yields bounded effect facts beside the preserved raw operands instead of
  aborting. The chunk remains invalid and validation still reports it.

### Binary parsing

- Lua 5.1 chunks whose header declares an integral `lua_Number` (integral flag 1) now
  decode every LUA_TNUMBER constant as a two's-complement integer of the declared 4- or
  8-byte width. Every consumer of the typed constant, including `disasm` text and JSON
  and `origins`, reports the integer; the same bytes under integral flag 0 remain
  IEEE-754 floats, and the LNUM32 profile's tag-9 integers are unaffected.
- Enforced `ResourceLimits::max_string_bytes` across Lua 5.1, 5.2, 5.3, 5.4, and 5.5
  chunk loaders before string payloads are read or retained, with stable diagnostics
  `L51-STR-001`, `L52-STR-001`, `L53-STR-001`, and `L55-STR-002`.

### Analysis

- Lua 5.1 symbolic callee analysis now preserves a proved callee below an open vararg or
  result write range while retaining explicit open argument-origin windows.

### Development process

- Replaced the broad release outline with one dependency-ordered path to 1.0 covering
  exact target scope, stable machine contracts, hostile-input evidence, LNUM32 and stock
  Lua qualification, packaging, customer transfer, publication, and rollback. Aligned
  the PRD, release policy, security status, candidate guide, README status, and complete
  documentation index without promoting any current capability.
- Replaced per-increment model committees with customer-outcome product batches: one
  implementation session writes production code and ordinary tests, the steward owns
  algorithmic review and integration, Opus review is risk-triggered, and separated
  acceptance remains specific to qualification claims.
- Audited the workflow experiment from commit `3e958f1` at 2026-08-23 16:24 PDT through
  `22a632d` at 2026-08-25 18:45 PDT. Across 50 hours 21 minutes of elapsed time, or 31
  hours 32 minutes when the two overnight inactive gaps are removed, it produced 7,788
  net lines of customer-facing Rust after excluding standalone and inline tests,
  documentation, qualification code, scripts, and CI. That is 155 net product lines
  per elapsed hour or 247 per active-window hour. The final day produced 6,554 net
  product lines in 12 hours 22 minutes, while its 1 hour 39 minute candidate-
  qualification tail produced no customer-facing product code.
- The same experiment produced 31,164 net test lines, 1,729 net oracle/qualification
  lines, 1,444 net operations lines, and 1,060 net documentation lines across 35
  pull-request-marked mainline changes. Persisted action logs record 56 Antigravity
  wrapper invocations totaling 1 hour 57 minutes and 53 Claude wrapper invocations
  totaling 3 hours 35 minutes. Provider runtime is now reported separately from total
  wall time, and lines per hour remain a diagnostic rather than a target. Complete
  full-experiment token totals were not durably retained and are recorded as
  unavailable rather than inferred from partial results.

- Implemented the complete, table-driven, fail-closed structured retrieval vocabulary
  across typed constants, callee resolutions, call relations, call argument origins,
  interpretation profiles, and prototype content identities with exact typed matching,
  signed zero distinction (+0.0 vs -0.0), and context-bound cursor pagination that
  rejects unsigned offsets.
- Lua 5.1 xref indexing now derives `Binds` links directly from physical companion
  descriptor instructions at each `CLOSURE` site, ensuring site-accurate forward and
  inverse binding evidence, including descriptor-to-parent reads, without collapsing
  across repeated instantiations of the same child prototype.
- Removed the nonfunctional `compile` CLI command, capability surface, and documentation
  references.
- Lua 5.1 callees now retain typed constant-key `GETTABLE` and `SELF` lookup labels
  across bounded aliases, equal control-flow joins, and safe closure captures without
  claiming receiver identity or emitting an exact call edge. Typed key identity,
  deterministic evidence, explicit `lookup-label-only` call relations, public text and
  machine output, schemas, and NaN-loop convergence are covered by one authority-bound
  acceptance gate.
- Lua 5.1 now classifies closure bindings and `SETLIST C == 0` payload words through
  one physical-role pass. Non-executable companions retain raw words, owner links, and
  physical PCs while remaining absent from effects, calls, and CFG execution.
- Lua 5.1 validation now rejects truncated SETLIST payloads and control transfers into
  closure-binding or SETLIST companion words.
- Callee and argument-origin analysis now share a bounded whole-tree capture-mutation
  summary that detects sibling and transitive writes to the same captured cell.
- Recursive Lua 5.1 export now emits `luad-prototype-v2` content identities that commit
  physical companion roles; the v1 encoder remains available as a compatibility API.
- Added versioned `luad-prototype-v1` subtree-content identities to Lua 5.1 recursive
  export, with a normative binary encoding, debug/path invariance, ordered child
  commitment, exact constant bytes, public schema/capability discovery, and a dedicated
  mutation-sensitive gate.

- Qualified every maintained public read surface against the reproducible OpenWrt
  Lua 5.1.5 LNUM32 compiler and made the compiler comparison mandatory.
- Release evidence now rejects noncanonical Lua 5.1 profile/layout pairs and
  prerequisites bound to a different concrete profile.
- Gate prerequisites resolve and authenticate their own compiler authority instead of
  inheriting a target-specific compiler selected for the enclosing gate.
- Closed Lua 5.1 validator and diagnostic authority with a manifest-pinned,
  redistributable firmware-shaped stress fixture and a canonical prerequisite gate.
- Added canonical gates for RK-B, nested RK ownership, SELF, numeric-for,
  generic-for, and closure-capture register-span evidence.

### Disassembly

- Lua 5.1 `CLOSURE` operands, JSON comments, text suffixes, and prototype xrefs
  now use the same owner-relative child prototype identity at every nesting depth.

### Validation

- Lua 5.1 `TFORLOOP` now validates its count-dependent iterator/result register window
  without misclassifying scalar field `C` as a direct register.
- Lua 5.1 `SELF` now validates its implicit second destination register against the
  owning prototype's stack bound with exact public instruction provenance.
- Lua 5.1 `FORPREP` and `FORLOOP` now validate their fixed four-register windows
  against the owning prototype's stack bound and report exact instruction provenance.
- Lua 5.1 `MOVE` and `GETUPVAL` closure-binding descriptors now validate capture
  sources against the executing parent's register and upvalue bounds, with public
  owner, descriptor, companion, typed-source, and physical-offset evidence.
- Lua 5.1 nested-prototype RK validation now has public owner-isolation evidence for
  register and constant forms of both conditional operands, including stable child
  identities, physical offsets, and unresolved out-of-range machine facts.
- Lua 5.1 conditional RK field `B` now selects register or constant validation by bit 8
  across its exact ten-opcode VM-derived set, with public register, constant, and
  non-RK scalar boundary evidence.
- Lua 5.1 conditional RK field `C` now selects register or constant validation by bit 8
  across its exact VM-derived opcode set, with root-prototype bounds and resolved public
  constant facts.
- Lua 5.1 validation and public disassembly now use an exhaustive VM-derived authority
  for fixed direct-register field `C`; `CONCAT.C` observes exact stack bounds, while
  booleans, counts, size hints, unused fields, and conditional RK operands remain
  distinct.
- Lua 5.1 validation and public disassembly now use an exhaustive VM-derived authority
  for fixed direct-register field `B`, exclude scalar/count/unused and closure-binding
  fields, and avoid misclassifying bit 8 of a direct register as an RK constant.
- Lua 5.1 disassembly and validation now use the executed VM role of field `A` across
  all 38 stock opcodes, including register-bearing `CLOSE`, non-register `JMP` and
  comparison flags, and ignored closure-binding descriptor fields.
- Lua 5.1 validation now applies upvalue, child-prototype, and comparison-boolean
  domains to their encoded fields without treating those values as registers.
- Lua 5.1 validation returns deterministic, de-duplicated diagnostics when the same
  decoded chunk is validated more than once.

### Machine interface

- Recursive `export` now accepts a fail-closed `--facts` list for the nine existing
  counted fact families. Explicit selections are recorded in stream metadata, compose
  with per-file fact bounds and terminal counts, and avoid constructing unrelated
  independent analyses; omitted selection preserves the existing all-family stream.
- Batch export now distinguishes succeeded, skipped, and failed inputs, qualifies every
  non-success with its path, closes terminal counts, and returns default success when a
  mixed firmware tree yields at least one complete result; `--strict` retains all-or-none
  process status.
- Unknown input signatures now use the cataloged `PARSE-UNKNOWN-001` diagnostic instead
  of sharing the malformed-bytecode code.
- Added `callgraph` text/JSON/JSONL output, recursive `call_relation` export facts, and
  `calls` xrefs with one exact or explicitly unresolved caller-to-prototype result per
  Lua 5.1 call.
- Literal-global relations preserve the closure value present at each store instruction,
  reject multiple or non-closure stores, and retain auditable evidence across direct,
  aliased, CFG-agreed, and safely captured closure values.
- Added `origins` text/JSON/JSONL output and recursive `origin` export facts with one
  bounded expression per fixed Lua 5.1 call argument, explicit open windows, eager
  alias-safe operands, owner-qualified parameters, conservative captures, and typed
  analysis cutoffs.
- Origin expressions preserve constant-only and parameter-dependent `CONCAT`, all Lua
  5.1 unary and binary operations including unclassified `MOD`, table-construction
  inputs, fixed call results, CFG conflicts, unreachable calls, and mutation boundaries.
- Added `callees` text/JSON/JSONL output and recursive `callee` export facts with one
  tagged resolution per Lua 5.1 call, symbolic label/prototype evidence, and typed
  unresolved reasons.
- Added CFG-safe register propagation for literal globals, constant table paths,
  exact literal `require` labels, aliases, direct closures, and conservative multi-hop
  upvalue captures.
- JSONL facts now carry required per-record input and interpretation context, including
  honest partial context on parse and read failures; streaming schemas use major 2.
- Capability output now exposes the diagnostic-catalog command, schema, and formats.
- Lua 5.1 `CLOSURE` query summaries and semantic IR explanations now report the
  owner-relative child prototype path instead of formatting the local `Bx` index as a
  root prototype.
- Added `diagnostics [CODE] --format text|json` command and `schema diagnostics`
  publishing the frozen 108-code canonical diagnostic catalog with static lookup.
- Added `export --max-facts-per-file` with deterministic per-input fact truncation,
  unsuppressed control and diagnostic records, and explicit emitted/available counts.

### Documentation

- Added a tool-free, self-contained Opus design-review lane for bounded architecture
  critiques without repository traversal.
- Routine Antigravity implementation turns are now structurally edit-only, with
  focused and aggregate verification owned by the steward and interactive command
  approval reserved for explicit compiler-led exceptions.
- Antigravity invocations now explicitly grant the current Git worktree through the
  canonical wrapper, retain sandboxing, expose those workspace controls to drift
  checks, and provide a named effective-access audit command.
- Added an evidence-gated development workflow that separates the product roadmap,
  one active sprint, independent acceptance-test authorship, implementation, and
  clean-revision acceptance.
- Refined agent orchestration with provider preflight, staged acceptance outlines,
  proportional evidence levels, subscription-aware usage checkpoints, and
  steward-owned final verification.
- Added patch, semantic, and qualification delivery lanes so localized corrections use
  one implementation turn, one branch, bounded tests, and one CI aggregate run.
- Pinned Antigravity to the `gemini-3.7-flash-high` High reasoning model variant, without
  the unsupported separate `--effort` argument, and added a configuration drift check.
- Added persistent Opus and Gemini session wrappers with structured timing/token
  telemetry, shell-free acceptance authorship, and scoped interactive fallback when
  Antigravity print mode cannot acquire repository permissions.
- Added named interactive Antigravity wrapper stages for scoped permission fallback.
- Added repository-owned provider wrappers, curated context packets, ranged reads,
  semantic edit checkpoints, post-interrupt diff inspection, aggregate per-model
  sprint accounting, and mandatory remote preservation.
- Established a canonical documentation index with freshness triggers and consolidated
  the dated TP-Link/OpenWrt reports into present-facing embedded-firmware requirements.
- Reclassified all implemented dialects as experimental pending executable proof gates.
- Added contributor, architecture, coding-agent, machine-interface, security, and release guidance.
- Consolidated contributor guidance around one product roadmap and one active,
  evidence-gated sprint.
- Captured TP-Link Lua 5.1 field evidence and corresponding embedded-layout, profile, closure-binding, resolved-constant, and diagnostic proof gates.

### Parsing compatibility

- Lua 5.1 string lengths now honor 4-byte or 8-byte `size_t` as declared by the chunk header; commit `54e4b8d` was reported to parse and validate all 252 files in the TP-Link corpus.
- Lua 5.1 LNUM integer tag 9 is decoded through profile-aware code and covered by the
  public profile gate; exact target release evidence remains unpromoted.

### Build and CI

- Official Lua compiler installation uses the dependency-minimal `generic` make target,
  accepts a configurable destination directory, and keeps contributor checks directly
  executable in CI.
