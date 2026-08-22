# Changelog

All notable changes will be documented here. The project has not yet made a production release.

## Unreleased

### Documentation

- Reclassified all implemented dialects as experimental pending executable proof gates.
- Added contributor, architecture, coding-agent, machine-interface, security, roadmap, and release guidance.
- Documented the 2026-08-22 correctness review and remediation stop line.
- Deferred composable research-workflow features until the factual analysis layer is trustworthy.

### Known correctness issues

- Lua 5.4 `iABC` operand bit positions are decoded incorrectly.
- Lua 5.4/5.5 signed `sB` and `sC` operand interpretation is incomplete.
- Five Lua 5.4 immediate-comparison opcodes have incorrect modes.
- Immediate dominators are computed incorrectly.
- Lua 5.4 validation can return valid-for-analysis despite out-of-range registers.
- The differential oracle does not yet compare opcode operands or constant values and lacks negative controls.
- Required compiler absence can currently appear as a successful skipped test.
- Capability evidence is hand-authored and overstates verified support.

See [docs/REVIEW-2026-08-22.md](docs/REVIEW-2026-08-22.md) and [ROADMAP.md](ROADMAP.md).
