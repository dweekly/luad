# Changelog

All notable changes will be documented here. The project has not yet made a production release.

## Unreleased

### Documentation

- Reclassified all implemented dialects as experimental pending executable proof gates.
- Added contributor, architecture, coding-agent, machine-interface, security, roadmap, and release guidance.
- Consolidated contributor guidance around one forward-looking, evidence-gated execution plan.
- Added the TP-Link Lua 5.1 field report and corresponding embedded-layout, profile, closure-binding, resolved-constant, and diagnostic proof gates.
- Deferred composable research-workflow features until the factual analysis layer is trustworthy.

### Parsing compatibility

- Lua 5.1 string lengths now honor 4-byte or 8-byte `size_t` as declared by the chunk header; commit `54e4b8d` was reported to parse and validate all 252 files in the TP-Link corpus.
- Lua 5.1 LNUM integer tag 9 is decoded through profile-aware code, pending the F1 public profile gate and release evidence.

### Open release work

- Prove Lua 5.4.8 typed public disassembly and normalized text output against the accepted raw-fact oracle and independent decoder.
- Review CFG/precondition and lossless-model claims at their public boundaries.
- Prove explicit Lua 5.1 stock layouts and LNUM profile selection with public diagnostics and provenance.
- Expose Lua 5.1 closure descriptors as capture bindings rather than executable effects.
- Resolve constant-bearing Lua 5.1 and Lua 5.4 operands consistently across text and machine output.
- Derive capability and README status only from verified release evidence.

See [the coding-agent execution plan](docs/CODING-AGENT-PLAN.md), [the TP-Link Lua 5.1 field requirements](docs/FIELD-REPORT-TP-LINK-LUA51.md), and [the roadmap](ROADMAP.md).
