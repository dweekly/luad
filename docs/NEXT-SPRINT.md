# Sprint checkpoint

## Blocked on evidence: the uncovered binding convention (issue #89)

`--link-convention luci-module-setglobal` resolves the cross-chunk caller edge for the flat
`module()` / `require()` shape, at a 60% resolve rate over a private vendor corpus of ~175
bytecode files. It resolves 1 of the 43 shell sink arguments that motivated the request,
because the library layer those sinks live in uses a **dotted submodule** binding (`a.b.c`
where `a.b` is itself a module) that the convention does not recognize.

No implementation is authorized until the binding is specified, because a second convention
built on an assumption about how that binding is emitted would silently default an unknown
convention and could not be falsified. The two questions that select between the candidate
fixes, both answerable from an export that already exists, are recorded in #89: whether the
module-export index contains any entry under the dotted prefix (a definition-side gap), or
whether the unresolved call sites carry the full dotted path in their `callee` label segments
(a matching-side gap).

**To unblock:** a minimal reproducing chunk pair for the real binding shape, which becomes the
public fixture. The consumer that measured this has moved to vendor findings and is not
supplying it, so this is dormant rather than in progress.

## Accepted and closed out

The inverse of a resolved cross-chunk link needs no new fact family: it is a regrouping of
shipped facts, joined to `origin` facts on `(caller_path, call_id)`.
`gate-cross-chunk-link` now owns that interaction — the inverse set is per-prototype rather
than per-module, an unreached export yields an empty set distinguishable from a failed
resolution, and the argument origin at each reaching site is pinned by kind.

## Not authorized here

No second link convention, per the above. No bounded-`alternatives` work, which remains the
top-ranked origin-precision item in [ROADMAP.md](../ROADMAP.md) and is the next outcome to
select if #89 stays dormant. No supported-target promotion, no 1.0 release, no new dialects.

## Stop conditions

Stop and record a decision rather than widening if: resolving a target needs type inference
(`lookup-label` method calls stay unresolved by design); or a real corpus target's caller set
exceeds a traversal bound, which would make the bound, not the fact family, the deliverable.
