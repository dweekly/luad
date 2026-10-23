# Lua 5.1 call-frame value lifetimes

Fresh as of: 2026-10-22. Lane: product; no capability promotion.

## Outcome and evidence boundary

A researcher must not receive an old callee label, literal argument or captured value
when a call can overwrite its temporary stack slot. The public minimized control
loads `luci.sys.exec` into R2, calls `os.getenv("PATH")` in R0 with C=1, then calls R2;
the current public CLI falsely retains the label and a unique cross-chunk target.
The standard C function pushes string/nil into R2. Source authority is Lua 5.1.5
[`luaD_precall`/`luaD_poscall`](https://www.lua.org/source/5.1/ldo.c.html),
[`OP_CALL`, `OP_TFORLOOP`, `OP_TAILCALL`](https://www.lua.org/source/5.1/lvm.c.html),
and [`os_getenv`](https://www.lua.org/source/5.1/loslib.c.html#os_getenv).
No crafted bytecode is executed.

## Public claim

Callee and origin transfers must invalidate the temporary tail at CALL A (all result
families: C=0, C=1, C>1), then establish explicit fixed result origins and the existing
exact literal-require label where proven. A later definition restores its own fact;
live registers below A survive. The Lua 5.1 generic iterator call uses the same rule
from A+3; the conditional control update also invalidates A+2. Iterator/state
inputs A and A+1 survive. Captures of
stack cells overlapping a reachable call tail must not retain their pre-call value,
including calls after closure creation and terminal tailcalls. Closure descriptors and
SETLIST data words remain non-executable; encoded IR writes/raw facts remain unchanged.
Cross-chunk links must not recover a target from a stale caller label.

This models ordinary VM call-stack reuse, conditional on normal return and the current
symbolic lookup assumptions. It does not prove runtime targets, account for arbitrary
C/reflection/debug mutations, or qualify all implicit metamethod/VM temporary effects.

## Scope and non-goals

Allowed production: `crates/luad-analysis/src/{lib,callees,origins,capture_mutation}.rs`
and one small private shared call-frame helper if useful. Tests: existing
`test_symbolic_callees_lua51.rs`, `test_argument_origins_lua51.rs`,
`test_cross_chunk_linking.rs`, and a shared ordinary test helper under `tests/common/`.
Update their existing gate expected-test lists, README, architecture, machine reference,
CHANGELOG, ROADMAP and this indexed contract as needed. No new proof framework,
dialects, inference precision, schema shapes, source execution or supported status.

## Executable assertions and stop condition

Before production changes, add and run these ordinary public-boundary controls with
required official Lua 5.1.5 (missing compiler fails):

- `cargo test -p luad-oracle --test test_symbolic_callees_lua51 test_call_frame_`:
  C=0/1/2/3 tails lose old paths; below-base locals, fresh definitions and literal
  require results retain exact paths; reachable CALL/iterator/tailcall effects refuse
  stale captures, while non-overlapping and companion-word controls retain them.
- `cargo test -p luad-oracle --test test_argument_origins_lua51 test_call_frame_`:
  corresponding stale literals/captures become typed unknown, fixed results retain
  exact call/result indices, open tails remain open, and ordinary locals remain exact.
- `cargo test -p luad-oracle --test test_cross_chunk_linking test_call_frame_`:
  the crafted caller has an unresolved callee and no eligible link/target, while
  its redefined/ordinary twin resolves. Link omission is not an absence proof.

Tests compile source templates, patch declared-width/order bytes using parsed offsets,
parse and validate each control, and assert semantic content rather than only counts.
Retain an old-failing run before correction. Existing named gates
`gate-symbolic-callees-lua51`, `gate-argument-origins-lua51`, `gate-closures-lua51` and
`gate-cross-chunk-link` must pass on the clean candidate, reusing prerequisite results
and LNUM authority fixtures. Run one pinned-Rust `bash scripts/check.sh` aggregate.
Require zero failed/ignored tests and record compiler identity. The capture/control-flow
interaction triggers one independent public-source Opus review, with at most one
bounded evidence-bearing follow-up. Stop this batch at a reviewed, CI-green merged
candidate and neutral checkpoint; select the next roadmap outcome separately.
