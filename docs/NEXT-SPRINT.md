# Delivery checkpoint

Fresh as of: 2026-10-22.

No implementation is authorized by this checkpoint. Select one bounded outcome from
[`ROADMAP.md`](../ROADMAP.md) and commit its contract before editing production code.

The next public outcome is the nonfinite machine-scalar family: NaN/infinity `val`
currently serializes as null against numeric schemas and a numeric typed model. Define
and review an explicit representation that preserves raw bits, finite numbers and
strict refusal of unknown scalars before implementation. Keep archived candidate/gate
identities immutable; source-qualified generation and existing tests can extend their
executable assertions without rewriting accepted artifacts.

The reference-reader/caller workflows and private consumer coverage remain separate
outcomes. Qualification follows [`DEVELOPMENT-WORKFLOW.md`](DEVELOPMENT-WORKFLOW.md)
and [`ROADMAP-1.0.md`](ROADMAP-1.0.md); roadmap direction alone promotes no interface.
