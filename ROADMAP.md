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

### 1. Correct, validate, and promote the stable LNUM32 release

Qualification proceeds through three independently reviewable checkpoints:

1. Preserve a statically proved callee across open Lua 5.1 argument windows, rebuild
   the exact candidate with the existing callee and candidate gates, and replay the
   firmware workflow that exposed the gap.
2. Exercise the rebuilt candidate binaries in an uncoached investigation against a
   different firmware version or objective and in a separate outside-human trial on
   different-vendor firmware. Both trials must complete the agreed public workflows
   without a reproducible correctness defect in the claimed surface. Such defects
   become minimized public regressions before qualification continues; usability
   findings are classified separately and block only when they prevent completion.
3. Promote only `lua5.1-lnum32` from the accepted evidence bundle and customer records,
   publish the verified artifacts, and keep the base `lua5.1` dialect experimental.

Exit outcome: a human or AI agent can complete the reference firmware workflows with
the supported CLI and a thin external judgment layer.

### 2. Deepen deterministic firmware analysis

Customer-guided product batches improve the highest-cost remaining factual joins:

1. Preserve bounded, evidence-linked origin alternatives at control-flow joins instead
   of collapsing every multi-definition value to one conflict marker.
2. Represent bounded constant-key table construction as a value origin so repacked
   request data remains traceable across a call boundary.
3. Apply structured queries to explicit file lists and let batch export select fact
   families while preserving per-file outcomes and interpretation identity; publish
   schema-driven recipes for joining callees, origins, relations, and prototypes.
4. Consider cross-chunk label definitions only through an explicit named convention
   whose evidence remains distinct from general Lua semantics.

Interprocedural caller unions remain an external composition until a bounded design can
prevent a union over unrelated callers from appearing to be a path-specific fact.

Exit outcome: the thin external security layer applies policy to compact, auditable
facts without reimplementing Lua register analysis.

### 3. Qualify additional targets independently

Stock Lua layouts, Lua 5.2, 5.3, 5.4, 5.5, LuaJIT, and vendor mappings advance one exact
target at a time. Vendor qualification may consume a provenance-bound mapping recovered
by an external interpreter-analysis tool. Firmware rehosting and dynamic gadget testing
remain external.

## Dependency order

```text
accepted LNUM32 release candidate
  -> open-window callee correction and customer replay
  -> independent customer transfer
  -> target-specific promotion
  -> deeper deterministic firmware facts
  -> independently qualified additional targets
```

## Customer checkpoints

- Before promotion: investigate a different firmware version or objective without
  implementation guidance and obtain one outside-human trial on different-vendor
  firmware. Each record identifies the exact candidate hashes, independent user and
  firmware context, commands attempted, outcomes, and minimized public regressions;
  private firmware bytes remain outside the repository.
- After every two or three related deterministic-fact batches: replay the affected
  firmware workflow and measure remaining manual disassembly, unknown reasons, output
  volume, and consumer-side analysis code.

Silent incorrect answers interrupt the sequence. Friction routes to the nearest factual
matrix. A private or externally downloaded corpus supplements but never replaces
redistributable evidence.

## Persistent exclusions

`luad` will not own decompilation, sink classification, attacker control, sanitization,
authentication, exploitability, whole-system reachability, persistent research state,
autonomous planning, firmware unpacking, target execution, or dynamic gadget testing.
