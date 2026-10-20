# Sprint checkpoint

## Next outcome: choose one, no contract recorded yet

The join-site `alternatives` work is delivered. The two candidates left in
[ROADMAP.md](../ROADMAP.md) are the private-corpus re-measurement of that change, which is
owed to its own acceptance criteria and cannot be run here, and the unknown-reason saturation
at 2000 (B-9), which first has to be localized to a layer before it is a `luad` obligation at
all. Record a contract, with acceptance criteria mapping to exact executable commands, before
implementation begins.

## Not authorized here

The loop-widening site and `MAX_BLOCK_REVISITS` are closed, not pending: widening to a bounded
set there was tried and measured to be unavailable, for the reason recorded in `ROADMAP.md` and
in the constant's own comment. Reopening it needs a new mechanism for bounding lattice height,
not another attempt at the same change. No second link convention. No reverse-edge fact family.
No source-text parsing: reading plain Lua source stays out of scope, and a downstream consumer
whose corpus is partly source closes that gap on its own side. No supported-target promotion,
no 1.0 release, no new dialects.

## Stop conditions

Stop and record a decision rather than widening if: a precision gap turns out to be bounded by
an analysis constant rather than by the lattice, which would make the constant, not the
expression family, the deliverable; or an acceptance criterion can only be stated against a
private corpus, which means it is not yet an acceptance criterion.

## Accepted and closed out

A control-flow join with one bounded and one unresolved predecessor emits the `alternatives`
set, keeping the unresolved definition as an option with its own reason.
`gate-argument-origins-lua51` owns it: the option's specific reason is pinned, not merely its
kind; `has_unknown` is public so the conservative reading stays derivable from a set; the
killer-mutation control targets the unknown option inside a set, which is where a partly
resolved join can now lose it; and three unit tests pin that a bare or embedded
`control-flow-conflict` absorbs a join, which is the property termination depends on.

The cross-chunk caller edge needs no new fact family and no second binding convention. The
inverse of a resolved link is a regrouping of shipped facts, joined to `origin` facts on
`(caller_path, call_id)`; `luci-module-setglobal` binds the dotted-submodule shape with zero
unresolved links over a private vendor corpus. Issue #89 is closed as not planned, with the
measurement that settled it.

`gate-cross-chunk-link` owns the interaction that investigation exposed: the inverse caller
set is per-prototype rather than per-module, an unreached export yields an empty set
distinguishable from a failed resolution, and the argument origin at each reaching site is
pinned by kind.
