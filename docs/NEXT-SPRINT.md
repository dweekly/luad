# Sprint checkpoint: no active product batch

Lane: planning. Roadmap position: select the next unresolved milestone from the
dependency-ordered version-1 release train.

## Current decision

No product implementation is authorized by this checkpoint. Before implementation
begins, the steward must replace this file with one forward-looking contract selected
from `ROADMAP.md`.

The roadmap's milestone order is a dependency plan, not a standing batch authorization.
Choose only the smallest unmet outcome whose prerequisites are accepted; do not combine
publication, schema, robustness, target-promotion, or customer-transfer work merely
because they share the 1.0 destination.

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

Stop before changing product code. Product work resumes only after a dedicated planning
change replaces this checkpoint with an active contract.
