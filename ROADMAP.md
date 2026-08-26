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

### 1. Validate and promote the stable LNUM32 release

Qualification proceeds through two independently reviewable checkpoints:

1. Exercise the exact candidate binaries in an uncoached investigation against a
   different firmware version or objective and in a separate outside-human trial on
   different-vendor firmware. Both trials must complete the agreed public workflows
   without a reproducible correctness defect in the claimed surface. Such defects
   become minimized public regressions before qualification continues; usability
   findings are classified separately and block only when they prevent completion.
2. Promote only `lua5.1-lnum32` from the accepted evidence bundle and customer records,
   publish the verified artifacts, and keep the base `lua5.1` dialect experimental.

Exit outcome: a human or AI agent can complete the reference firmware workflows with
the supported CLI and a thin external judgment layer.

### 2. Qualify additional targets independently

Stock Lua layouts, Lua 5.2, 5.3, 5.4, 5.5, LuaJIT, and vendor mappings advance one exact
target at a time. Vendor qualification may consume a provenance-bound mapping recovered
by an external interpreter-analysis tool. Firmware rehosting and dynamic gadget testing
remain external.

## Dependency order

```text
accepted LNUM32 release candidate
  -> independent customer transfer
  -> target-specific promotion
  -> independently qualified additional targets
```

## Customer checkpoints

- Before promotion: investigate a different firmware version or objective without
  implementation guidance and obtain one outside-human trial on different-vendor
  firmware. Each record identifies the exact candidate hashes, independent user and
  firmware context, commands attempted, outcomes, and minimized public regressions;
  private firmware bytes remain outside the repository.

Silent incorrect answers interrupt the sequence. Friction routes to the nearest factual
matrix. A private or externally downloaded corpus supplements but never replaces
redistributable evidence.

## Persistent exclusions

`luad` will not own decompilation, sink classification, attacker control, sanitization,
authentication, exploitability, whole-system reachability, persistent research state,
autonomous planning, firmware unpacking, target execution, or dynamic gadget testing.
