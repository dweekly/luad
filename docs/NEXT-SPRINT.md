# Chunk-wide instruction budget (issue #117)

Fresh as of: 2026-10-23. Lane: bounded hostile-input resource correction; no target
promotion, no model or schema-semantics change.

## Outcome and decision

luad analyzes potentially hostile bytecode, and AGENTS.md requires bounded allocation.
Today only the 64 MiB input ceiling bounds the parsed model:
- each prototype may hold up to 1,000,000 instructions;
- a chunk may hold up to 10,000 prototypes;
- each instruction word costs about 300 bytes in memory (three heap allocations).

A 3.8 MB generated Lua 5.1 chunk peaks at 557 MB under `inspect` and 807 MB under
`callers` (#117). Add one chunk-wide budget, `max_total_instructions` (default
2,000,000), charged in `SafeReader` when each prototype's declared code size is read,
before its instruction vector is allocated. Crossing it is a `CORE-LIMIT-004` error and
exits 5, like the existing prototype and depth budgets. The default is about 80 times the
largest compiled LuCI module in the vendored corpus, and it bounds the model near 600 MB.
Representation work that shrinks the per-word footprint stays open in #117.

## Scope

- **Production:** `ResourceLimits` and `SafeReader` in `luad-core`; the code-size read in
  the five dialect parsers; the diagnostic catalog; the CLI limit-code list.
- **Tests:** per-dialect controls through `SafeReader::with_options`.
- **Docs and snapshots:** the generated schema snapshots and examples that serialize
  `ResourceLimits` gain the additive field; MACHINE-INTERFACE limits; CHANGELOG.
- **Out of scope:** footprint reduction, constant budgets, changes to the per-prototype
  limits, new CLI flags.

## Executable acceptance fixed before production

- **Every dialect:**
  - a chunk whose cumulative declared code size exceeds a lowered budget fails with
    `CORE-LIMIT-004`, naming the prototype and the byte location of the size field;
  - the same chunk at exactly the budget parses;
  - the charge happens before allocation, so a declared size far beyond the remaining
    input fails on the budget rather than on EOF.
- **Mapping:** `CORE-LIMIT-004` maps to exit 5 and appears in the diagnostic catalog with
  an explanation.
- **Default:** the measured 3.8 MB chunk still parses under the default, and every
  vendored LuCI module and fixture is far below it.
- **Suites:** the existing parser, limits, catalog and schema-golden suites (updated
  only for the additive field), one pinned-Rust `scripts/check.sh`, and final CI.

Stop at accepted, final-CI-green merged code and a neutral checkpoint.
