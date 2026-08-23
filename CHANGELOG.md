# Changelog

All notable changes will be documented here. The project has not yet made a production release.

## Unreleased

### Documentation

- Added an evidence-gated development workflow that separates the product roadmap,
  one active sprint, independent acceptance-test authorship, implementation, and
  clean-revision acceptance.
- Established a canonical documentation index with freshness triggers and consolidated
  the dated TP-Link/OpenWrt reports into present-facing embedded-firmware requirements.
- Reclassified all implemented dialects as experimental pending executable proof gates.
- Added contributor, architecture, coding-agent, machine-interface, security, and release guidance.
- Consolidated contributor guidance around one forward-looking, evidence-gated execution plan.
- Captured TP-Link Lua 5.1 field evidence and corresponding embedded-layout, profile, closure-binding, resolved-constant, and diagnostic proof gates.
- Kept researcher state and inference outside `luad`; deterministic batch export is the next composability primitive.

### Parsing compatibility

- Lua 5.1 string lengths now honor 4-byte or 8-byte `size_t` as declared by the chunk header; commit `54e4b8d` was reported to parse and validate all 252 files in the TP-Link corpus.
- Lua 5.1 LNUM integer tag 9 is decoded through profile-aware code, pending the L1 public profile gate and target-specific release evidence.

### Open release work

- Make the exact LNUM32 profile reachable and truthfully identified through every public command.
- Make query, xref, and cursor errors fail closed.
- Eliminate validator false positives on valid compiler output.
- Prove typed Lua 5.1 disassembly, constants, and closure bindings through live CLI output.
- Add versioned machine envelopes, response-level schemas, and deterministic batch export.

See [the coding-agent execution plan](docs/CODING-AGENT-PLAN.md) and the
[embedded-firmware requirements](docs/EMBEDDED-FIRMWARE-REQUIREMENTS.md).
