# Sprint checkpoint: no active product batch

Lane: planning. Roadmap position: the next stage is the top unmet item under
[next steps](../ROADMAP.md#next).

## Current decision

No product implementation is authorized by this checkpoint. Before implementation
begins, this file is replaced with that stage's contract, following the lifecycle in
[the development workflow](DEVELOPMENT-WORKFLOW.md#12-preservation-documentation-and-escalation):
a target-qualification stage merges its contract in a dedicated planning change first;
every other stage places its contract here in the first commit of its own pull request
and restores this checkpoint in its last.

The execution sequence is a dependency order, not a standing batch authorization. Take
only the first unmet stage whose prerequisites are accepted; do not combine
public-contract, robustness, target-promotion, or customer-transfer work merely because
they share the 1.0 destination.

The contract must name:

- one public outcome and its exact target boundary;
- the production and ordinary-test paths allowed to change;
- the narrow regression and any already-established gate that prove the claim;
- explicit non-goals; and
- a stop condition that prevents adjacent roadmap work from entering the batch.

Qualification infrastructure, new evidence layers, and target promotion require their
own stated need and acceptance boundary. They are not implied by selecting a product
outcome.

## Stop condition

Stop before changing product code. Every implementation commit follows one that placed
its claim in this file; a checkpoint never coexists with a contract.
