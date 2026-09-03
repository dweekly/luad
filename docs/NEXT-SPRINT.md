# Sprint contract: Lua 5.1 integral-number constants

Lane: product. Roadmap position: a silent incorrect answer interrupts planned feature
work (`ROADMAP.md`, sequencing rules); this batch precedes Milestone 2.

## Outcome

A stock Lua 5.1 chunk whose header declares an integral `lua_Number` yields the integer
its bytes encode, on every public surface, instead of an IEEE-754 reinterpretation of
those bytes.

## Public claim

For a Lua 5.1 header with integral flag 1, every LUA_TNUMBER (tag 3) constant is a typed
`Integer` of the declared 4- or 8-byte width, preserved raw bytes unchanged. Under
integral flag 0 the same bytes remain a typed `Float`. The LNUM32 profile is untouched:
its byte 11 is `sizeof(lua_Integer)`, its tag-3 constants stay floating-point, and its
integers continue to arrive through tag 9. Stock integral layouts remain experimental;
this batch corrects a wrong value and promotes nothing.

## Scope

Allowed paths:

- `crates/luad-dialect-lua51/src/chunk.rs` — the tag-3 constant arm only
- `crates/luad-oracle/tests/test_lua51_integral_numbers.rs`
- `CHANGELOG.md`, `docs/NEXT-SPRINT.md`, `README.md` — the documentation index row for the sprint file only

## Non-goals

No schema, diagnostic, capability, target, profile, or documentation-claim change. No
change to floating-point decoding, to the LNUM32 tag-9 path, or to header validation. No
new fixture from a compiler: the pinned official compilers cannot emit an integral
layout, so evidence is hand-built chunks through the public CLI.

## Evidence

1. `cargo test -p luad-oracle --test test_lua51_integral_numbers`: for 4-byte and 8-byte
   integral layouts, `inspect --summary` reports the declared layout, `disasm --format
   json` carries the integer `val` with no float classification, and `origins --format
   text` renders the integer; the same bytes under integral flag 0 decode as the
   expected floats.
2. `bash scripts/check.sh` with all five official compilers present, including the
   LNUM32 authority gate and the existing Lua 5.1 layout and profile gates.

## Stop condition

Stop when the evidence holds. Product work resumes only after a dedicated planning
change replaces this contract with one unmet outcome selected from `ROADMAP.md`.
