# Sprint checkpoint

## Open question, owned by the consumer: does the firmware convention match?

`--link-convention luci-module-setglobal` resolves the cross-chunk caller edge for the
`module()` / `require()` shape. Whether the library bindings in a real vendor firmware tree
use that shape, or another one, decides whether anything further is owed here. The downstream
consumer is measuring the resolved-versus-unresolved split over its corpus.

- If most sites resolve, no `luad` change is owed and the remaining gap is documentation
  (issue #95: a worked export → cross-chunk edge → argument origin chain).
- If a substantial share come back unresolved, the ask is the specific conventions
  `luci-module-setglobal` does not cover, named one at a time with a fixture each, and a new
  contract is recorded then. A second convention is not authorized by this checkpoint.

## Not authorized here

No new fact family for reverse edges. The inverse of a resolved cross-chunk link is a
regrouping of facts `luad` already emits, now pinned by `gate-cross-chunk-link`; adding a
command that returns the same facts in a different shape is a convenience, not a capability,
and needs its own decision.

No bounded-`alternatives` work, which remains the top-ranked origin-precision item in
[ROADMAP.md](../ROADMAP.md) and is independent of the above. No supported-target promotion, no
1.0 release, no new dialects.

## Stop conditions

Stop and record a decision rather than widening if: resolving a target needs type inference
(`lookup-label` method calls stay unresolved by design); or a real corpus target's caller set
exceeds a traversal bound, which would make the bound, not the fact family, the deliverable.
