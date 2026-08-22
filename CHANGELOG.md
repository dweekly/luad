# Changelog

All notable changes will be documented here. The project has not yet made a production release.

## Unreleased

### Documentation

- Reclassified all implemented dialects as experimental pending executable proof gates.
- Added contributor, architecture, coding-agent, machine-interface, security, roadmap, and release guidance.
- Documented the 2026-08-22 correctness review and remediation stop line.
- Added the TP-Link Lua 5.1 field report and corresponding embedded-layout, profile, closure-binding, resolved-constant, and diagnostic proof gates.
- Deferred composable research-workflow features until the factual analysis layer is trustworthy.

### Parsing compatibility

- Lua 5.1 string lengths now honor 4-byte or 8-byte `size_t` as declared by the chunk header; commit `54e4b8d` was reported to parse and validate all 252 files in the TP-Link corpus.
- Lua 5.1 LNUM integer tag 9 is decoded, pending separation into an explicit evidence-backed vendor profile.

### Known correctness issues

- Lua 5.4 `iABC` operand bit positions are decoded incorrectly.
- Lua 5.4/5.5 signed `sB` and `sC` operand interpretation is incomplete.
- Five Lua 5.4 immediate-comparison opcodes have incorrect modes.
- Immediate dominators are computed incorrectly.
- Lua 5.4 validation can return valid-for-analysis despite out-of-range registers.
- The differential oracle does not yet compare opcode operands or constant values and lacks negative controls.
- Required compiler absence can currently appear as a successful skipped test.
- Capability evidence is hand-authored and overstates verified support.
- Lua 5.1 still needs a generalized, header-derived layout model and passing layout/profile gates before embedded-layout support can be promoted; the `size_t` fix alone is not a full layout proof.
- Lua 5.1 `CLOSURE` binding descriptors are currently treated as executable `MOVE`/`GETUPVAL` instructions, producing false effects.
- Lua 5.1 LNUM tag 9 needs an explicit vendor profile rather than silent acceptance as stock Lua.
- Top-level parser errors can replace the actual failure offset with offset 0.
- Disassembly does not consistently resolve constant-bearing operands inline, making machine and human cross-referencing unnecessarily expensive.

See [docs/REVIEW-2026-08-22.md](docs/REVIEW-2026-08-22.md), [docs/FIELD-REPORT-TP-LINK-LUA51.md](docs/FIELD-REPORT-TP-LINK-LUA51.md), and [ROADMAP.md](ROADMAP.md).
