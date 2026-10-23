# Pinned public LuCI corpus with source-checked caller answers

Fresh as of: 2026-10-23. Lane: bounded public-workflow evidence (roadmap C); no analysis
rule changes and no target promotion.

## Outcome and decision

`luad callers` is validated so far on synthetic fixtures and on LuaSocket/Penlight,
which are not written in the LuCI module style. Roadmap C asks for a small licensed,
pinned public application/module subset with meaningful expected answers. LuCI is the
public code the firmware use case is about. A local experiment on all 55
`module("luci…")` files of openwrt/luci `openwrt-23.05` at
`3d39e8c38cfa276d5cdfad7105dbf47933eaed4f` found every one of 292 same-file callers on a
debug source line that literally calls the target by its declared name. It also found
that the strict link index admits only 14 of the 55 modules. This batch makes that
evidence executable in the repository.

Vendor a bounded, unmodified subset with its Apache-2.0 license and a notice recording
the origin, commit, paths and hashes. Compile it at test time with the required official
Lua 5.1.5 compiler, never executing it. Check caller answers against source text, an
oracle independent of luad's analyses, and pin a few meaningful answers. Pin the strict
index's admission result as the current boundary, so a later change to admission is a
visible, reviewed change.

## Scope

- **Corpus:** `tests/corpus/luci-23.05/`: unmodified sources under their upstream paths,
  `LICENSE` (upstream Apache-2.0 text), and `NOTICE.md` with the provenance and the
  per-file SHA-256. About 80 KB:
  - libraries: `luci.util`, `luci.sys`, `luci.cbi.datatypes`, `luci.model.uci`,
    `luci.http`, `luci.dispatcher`;
  - controllers: `mini.system`, `mini.index`, `mini.network`, `lxc`, `ahcp`, `openvpn`,
    `nft-qos`.
- **Tests:** one ordinary oracle test file. **Docs:** a RECIPES walkthrough, the README
  index, CHANGELOG.
- **Out of scope:** production code, link conventions (an owner question is open), the
  reference consumer, performance, and any claim about runtime behavior or
  exploitability.

## Executable acceptance fixed before production

There is no production change. The tests are the deliverable.

- **Integrity:** every vendored file's SHA-256 equals `NOTICE.md`, and the file set
  equals the notice. Required compiler absence fails.
- **Source-line oracle, library level** (debug builds, in process): for every named
  prototype in every module, every caller that `attribute_file_callers` lists from the
  accepted facts lies on a source line that calls the target by its declared name.
  Counts are recorded, at least one caller per library module is required, and anonymous
  targets are counted, not skipped silently.
- **Oracle negative control:** a fabricated caller (a real call site of a different
  function) and a shifted line both fail the source-line check.
- **Pinned answers:** on the command, for a few targets with meaningful callers, the
  exact call ids, source lines and first-argument origin kinds. Debug and stripped twins
  give identical call ids.
- **Strict linking boundary:** one corpus-wide `callers --link-convention
  luci-module-setglobal` run pins `degraded: true` and the exact set of
  `dynamic_providers`.
- **Suites:** focused tests, one pinned-Rust `scripts/check.sh` and final CI.

Stop at accepted, final-CI-green merged code and a neutral checkpoint.
