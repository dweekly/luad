# Sprint checkpoint

## Next outcome: choose one, no contract recorded yet

Two candidates remain, both recorded in [ROADMAP.md](../ROADMAP.md):

- **The private-corpus re-measurement**, now owed by more than one change. Every origin
  precision change since 0.3.1 was accepted on public fixtures with a measured before and
  after; none has been measured corpus-wide. That measurement cannot be run here and is the
  downstream consumer's to produce.
- **The unknown-reason saturation at 2000 (B-9)**, which has to be localized to a layer
  before it is a `luad` obligation at all.

Record a contract, with acceptance criteria mapping to exact executable commands, before
implementation begins.

## Not authorized here

Big-endian chunk parsing. The parser refuses endianness 0 at header offset 6 and exits 4, and
that refusal is pinned. It bounds what an argument-level origin fixture can cover, so it is a
dependency of the remaining half of issue #94 rather than a separate wish; reading that layout
is a dialect-profile change needing its own evidence gate, not an extension of origin work.

The loop-widening site and `MAX_BLOCK_REVISITS` are closed, not pending: widening to a bounded
set there was tried and measured to be unavailable, for the reason recorded in `ROADMAP.md` and
in the constant's own comment. Reopening it needs a new mechanism for bounding lattice height,
not another attempt at the same change.

Interprocedural parameter origins are declined, not deferred: the union over callers is a
two-key join over facts already shipped, and the record would read as a path fact that it is
not. Issue #93 carries the reasoning and the public-fixture demonstration.

No second link convention. No reverse-edge fact family. No source-text parsing: reading plain
Lua source stays out of scope, and a downstream consumer whose corpus is partly source closes
that gap on its own side. No supported-target promotion, no 1.0 release, no new dialects.

## Stop conditions

Stop and record a decision rather than widening if: a precision gap turns out to be bounded by
an analysis constant rather than by the lattice, which would make the constant, not the
expression family, the deliverable; or an acceptance criterion can only be stated against a
private corpus, which means it is not yet an acceptance criterion.

## Accepted and closed out

`gate-argument-origins-lua51` owns every item below, with a public fixture per claim, a
measured before and after, and each claim mutation-verified against the plausible wrong
implementation rather than only against no implementation.

- A control-flow join with one bounded and one unresolved predecessor emits the `alternatives`
  set, keeping the unresolved definition as an option with its own reason. `has_unknown` is
  public so the conservative reading stays derivable. An aliased table inside an expression is
  invalidated by a later write, on both the candidate and the base side.
- `TESTSET` is modelled per edge, so the `a or b` and `a and b` idioms over locals resolve to
  their reaching definitions instead of reporting `overwritten`. The cheaper whole-instruction
  model is unsound in the other direction and the gate pins that it is not used.
- An open argument window reports the arguments at fixed registers before its top-dependent
  tail, dense from index zero, bounded by the open-result marker. Without that marker the
  prefix is empty rather than counted to the frame size.
- A table access whose key register holds only literals names its field; a key that is not
  determinable still reports `dynamic-key`.
- A table-literal field written before the table escaped to a callee, a global or an upvalue is
  no longer reported. That was a defect in 0.3.1: the escape was detected but recorded as
  `incomplete`, which means something else, so possibly-overwritten values were presented as
  known. The previously pinned behaviour was wrong and is corrected.
- Each prototype reports its parameter field accesses, resolved by the dataflow rather than by
  register number, which is a prototype's input contract. Issue #99.
- A captured register the parent writes after building the closure reports its reaching
  definitions instead of `mutable-capture`, which is sound only because the set is refused
  whenever it cannot be completed: a cell written through a closure, an unresolved member, a
  member holding a table, or an overflow of the alternatives limit. Issue #97. The gate pins
  the refusals alongside the sets, and pins that a write the closure's binding precedes is not
  a member, since collecting every write to the register would report a value the closure
  cannot see.
- Argument-level origin verdicts are pinned on the 32-bit LNUM authority chunk together with
  its validated layout, since structural counts cannot catch a precision regression.

The cross-chunk caller edge needs no new fact family and no second binding convention. The
inverse of a resolved link is a regrouping of shipped facts, joined to `origin` facts on
`(caller_path, call_id)`; `luci-module-setglobal` binds the dotted-submodule shape with zero
unresolved links over a private vendor corpus. Issue #89 is closed as not planned, with the
measurement that settled it. `gate-cross-chunk-link` owns the interaction that investigation
exposed: the inverse caller set is per-prototype rather than per-module, an unreached export
yields an empty set distinguishable from a failed resolution, and the argument origin at each
reaching site is pinned by kind.
