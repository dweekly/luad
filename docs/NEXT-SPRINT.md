# Active product batch: uniform serialized-string limits

Lane: product. Roadmap position: Stage 1 exact disassembly and the cross-cutting
hostile-input robustness workstream.

## Public claim

`ResourceLimits::max_string_bytes` bounds every newly serialized Lua string before its
payload is read or retained by the Lua 5.1, 5.2, 5.3, 5.4, and 5.5 chunk parsers. The
limit applies consistently to source names, string constants, local-variable names,
upvalue names, and Lua 5.5 string-table insertions.

The bound measures string content bytes, excluding a format's serialized terminator or
length marker. A string exactly at the configured limit is accepted. A declared string
one byte over the limit fails before a truncation or end-of-input error can mask the
violated limit. The stable diagnostics are `L51-STR-001`, `L52-STR-001`,
`L53-STR-001`, the existing `L54-STR-001`, and `L55-STR-002` (`L55-STR-001`
continues to identify an invalid reuse-table index).

This batch hardens existing parser paths. It does not promote a dialect, profile,
layout, command, or support tier.

## Acceptance matrix

Exercise all five stock-Lua parser families through their ordinary chunk decode path:

| Target | Length encoding that must be covered |
|---|---|
| Lua 5.1 | Header-declared 32-bit and 64-bit `size_t` |
| Lua 5.2 | Header-declared 32-bit and 64-bit `size_t` |
| Lua 5.3 | Short one-byte length and `0xff` extended `size_t` length |
| Lua 5.4 | Variable-length integer |
| Lua 5.5 | Variable-length integer and insertion into the string-reuse table |

For each target, acceptance proves:

- the encoded size is normalized to content bytes according to that exact format;
- content length equal to the configured limit parses;
- content length one byte over the limit returns that dialect's pinned diagnostic;
- a declared over-limit length with no payload returns the limit diagnostic rather than
  an end-of-input diagnostic;
- every string-bearing field uses the same bounded loader rather than a parallel
  unbounded read path;
- Lua 5.5 validates a new string before inserting it into the reuse table, while a reuse
  reference can only retrieve a string that passed the bound when first decoded;
- default-limit parsing of maintained valid fixtures is unchanged.

One table-driven suite may cover format variants. Reuse existing parser fixtures,
diagnostic machinery, and hostile-input test infrastructure. Do not create a gate per
dialect or per string-bearing field.

## Scope

Production work is limited to serialized-string length enforcement and the minimum
shared reader support needed to implement it once. Stable diagnostics, focused tests,
diagnostic documentation, and the aggregate check are in scope.

CLI limit flags, input-size policy, collection-count limits, recursion limits, fuzz
infrastructure, capability-manifest wiring, release publication, query behavior,
analysis semantics, and opcode validation are non-goals.

## Evidence and stop condition

Run the focused cross-dialect string-limit suite, one
`gate-string-limits-stock-lua` gate carrying the complete matrix, and the aggregate
repository check. The gate includes a mutation probe demonstrating that bypassing a
dialect's length check is rejected, enumerates the exact test set, and permits no skipped
or ignored matrix rows.

Stop after one reviewable production-and-test diff proves the full matrix. A failure in
one dialect is a failure of the batch; it does not become a follow-on dialect sprint.
