# Active sprint: exact LNUM32 surface qualification

Lane: qualification. Target: prove one exact embedded Lua target without changing its
experimental capability tier.

## Claim and researcher value

For the OpenWrt-derived Lua 5.1.5 LNUM32 target with layout
`int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4`, every maintained public read
surface will select and report the same interpretation, and release evidence assembly
will reject prerequisites from any other profile or layout.

This sprint closes the public interpretation boundary needed by firmware researchers.
It deliberately leaves support-tier promotion for the following sprint, where the tier
can be derived from a verified exact-target evidence bundle.

## Acceptance matrix

One public authority matrix covers the debug and stripped fixtures through:

- detected and explicit `inspect`;
- JSON and text `disasm` with three-way agreement against the independent decoder and
  the pinned OpenWrt-derived compiler listing;
- `validate` with zero diagnostics on valid fixtures;
- `query` with an owner-qualified result and an actually applied predicate operand;
- recursive JSONL `export`, including mixed stock/LNUM inputs with per-file profile
  selection and no interpretation bleed;
- symmetric explicit-profile substitution failures for LNUM-as-stock and stock-as-LNUM.

The compiler comparison is mandatory. The gate runner supplies the authenticated
compiler path to the test process after checking the platform-specific compiler hash.
Absence of the compiler, an unlisted platform, an incorrect binary, or an unapplied
comparison fails the gate; no environment-conditional success path is permitted.

Release-manifest assembly and verification bind Lua 5.1 prerequisites to exact target
identity. A prerequisite that declares a different concrete profile or layout cannot
satisfy an LNUM32 release. Profile-neutral gates remain eligible only when explicitly
listed by the exact-target release gate. Prefix matching is not evidence of target
compatibility.

The Lua 5.1 opcode/validator authority documents and tests that `OP_TEST` and closure
binding descriptors do not validate their encoded `A` field as an executed register
operand.

## Required gate changes

- `gate-authority-lua51-openwrt-lnum32` pins `Lua 5.1.5 (double int32)` and the exact
  compiler SHA-256 for every maintained CI platform.
- The authority gate names every test in the acceptance matrix and carries the frozen
  fixture hashes already authenticated by `AUTHORITY.json`.
- Release-manifest negative controls substitute a stock Lua 5.1 profile/layout and an
  unrelated Lua 5.1-prefixed profile; both must be rejected.
- Existing proof-harness, machine-contract, profile, public-disassembly, CLI-selection,
  diagnostics, validator, and prototype-identity gates remain prerequisites rather than
  being reimplemented here.

## Allowed production paths

- `crates/luad-oracle/src/gate_runner.rs`
- Lua 5.1 opcode or validator authority documentation only where needed for the
  executed-role exception
- the minimum gate-runner environment plumbing needed to expose the verified compiler
  path to the named test process

Tests, gate specs, gate scripts, schemas, and `CHANGELOG.md` may change as required by
the matrix. Parser, disassembler, query, export, and capability production semantics are
out of scope unless a red public-boundary test demonstrates a target-specific defect.

## Non-goals

This sprint does not add a supported target record, load a release evidence bundle,
change the capabilities schema, promote base `lua5.1`, add symbolic callee or origin
analysis, ingest a private firmware corpus, or treat a public corpus as an oracle.

## Verification and stop condition

Acceptance requires:

1. focused red tests for exact profile/layout substitution and mandatory compiler use;
2. the complete authority surface matrix passing with zero skipped or conditional tests;
3. the named prerequisite gates and aggregate repository checks passing;
4. green pull-request CI on every maintained platform;
5. a clean merged revision with local `main` equal to `origin/main`.

The next sprint may promote only `lua5.1-lnum32`, and only from evidence produced by
this qualified revision.
