# Changelog

All notable changes will be documented here. The project has not yet made a production release.

## Unreleased

### Documentation

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
