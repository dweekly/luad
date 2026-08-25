# `luad` product roadmap

Status: authoritative product direction. Exact implementation and acceptance details
belong only in [the active sprint](docs/NEXT-SPRINT.md).

## Destination state

`luad` will be a deterministic, stateless fact tool that lets a human researcher or
external agent move from a firmware tree to reproducible answers about bytecode
identity, constants, symbolic call selection, captures, value origins, control flow, and
change across firmware versions. Every answer will carry the artifact interpretation
and instruction evidence needed to audit it. Machine consumers will join and query
those facts without decoding Lua instructions or retaining hidden stream state.

Security classification, attacker control, exploitability, inferred intent, research
memory, and autonomous planning remain outside the executable. Deterministic VM facts
belong in `luad`; investigation-dependent judgments belong in the caller.

The first release target is the OpenWrt-derived Lua 5.1.5 LNUM32 profile with
little-endian, 32-bit serialized string lengths. Every support claim remains scoped to
an exact release, profile, layout, public surface, and evidence manifest.

## Delivery sequence

### 1. Freeze retrieval and machine contracts

Queries will cover callee paths and lookup labels, unresolved reasons, origin shapes,
call relations, interpretation identity, and prototype content identity. Every
predicate applies its complete operand or fails. Capture xrefs will remain tied to the
physical closure site when one child prototype is instantiated more than once with
different binders. Tested recipes will cover corpus constant search, capture traversal,
call-site enumeration, argument-origin triage, caller navigation, and cross-version
comparison. A dedicated constant-search verb is eligible only if it materially improves
the tested export/query recipe without creating parallel semantics.

Machine compatibility rules will define whether extensible analysis vocabularies are
open within a schema major, and command documentation will state verdict-to-exit-code
behavior in one table. The nonfunctional `compile` placeholder will leave the public
surface unless its complete trusted-compiler contract is independently implemented.

Exit outcome: a human or AI consumer can retrieve every release-critical fact without
reimplementing bytecode decoding or relying on undocumented enum and process behavior.

### 2. Qualify the stable LNUM32 release

The release candidate will freeze the schema major, publish exact target artifacts,
derive the `lua5.1-lnum32` support tier from the verified release evidence bundle, and
keep the base `lua5.1` dialect experimental. It will undergo an uncoached investigation
against a different firmware version or objective and a separate outside-human trial on
different vendor firmware. Reproducible correctness defects become minimized public
regressions. Release binaries and a short public-firmware quickstart will cover macOS
arm64 and Linux x86_64.

Exit outcome: a human or AI agent can complete the reference firmware workflows with
the supported CLI and a thin external judgment layer.

### 3. Qualify additional targets independently

Stock Lua layouts, Lua 5.2, 5.3, 5.4, 5.5, LuaJIT, and vendor mappings advance one exact
target at a time. Vendor qualification may consume a provenance-bound mapping recovered
by an external interpreter-analysis tool. Firmware rehosting and dynamic gadget testing
remain external.

## Dependency order

```text
retrieval and machine-contract freeze
  -> stable LNUM32 release evidence
  -> independently qualified additional targets
```

## Customer checkpoints

- Before schema freeze: review callees, origins, call relations, capture xrefs, and
  queries as one public area, then exercise every retrieval recipe against
  representative firmware.
- Before release: investigate a different firmware version or objective without
  implementation guidance and obtain one outside-human trial on different vendor
  firmware.

Silent incorrect answers interrupt the sequence. Friction routes to the nearest factual
matrix. A private or externally downloaded corpus supplements but never replaces
redistributable evidence.

## Persistent exclusions

`luad` will not own decompilation, sink classification, attacker control, sanitization,
authentication, exploitability, whole-system reachability, persistent research state,
autonomous planning, firmware unpacking, target execution, or dynamic gadget testing.
