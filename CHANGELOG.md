# Changelog

All notable changes will be documented here. The project has not yet made a production release.

## Unreleased

### Disassembly

- Lua 5.1 `CLOSURE` operands, JSON comments, text suffixes, and prototype xrefs
  now use the same owner-relative child prototype identity at every nesting depth.

### Validation

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

- Added `export --max-facts-per-file` with deterministic per-input fact truncation,
  unsuppressed control and diagnostic records, and explicit emitted/available counts.

### Documentation

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
