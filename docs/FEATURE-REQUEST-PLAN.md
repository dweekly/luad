# Feature-request delivery plan

Status: proposed sequencing for future feature selection.

Fresh as of: 2026-09-18.

This plan retains the remaining Deco research requests. It is not an active implementation contract: a new contract in [`NEXT-SPRINT.md`](NEXT-SPRINT.md) must select an outcome before work begins. Private firmware measurements prioritize work but do not become fixtures, test authorities, or core security policy.

## Shared boundary and evidence

The product reports deterministic VM facts. It does not classify sinks, infer attacker-control, decide exploitability, reconstruct source, infer receiver types, or claim whole-program path feasibility. Each batch needs a public claim, allowed paths, public fixture authority, named evidence, and stop condition.

Required fixtures and compilers fail rather than skip. Every comparator needs a corruption control. The steward runs the focused gate and one clean-candidate aggregate `bash scripts/check.sh`.

## Caller-unioned parameter substitution (R-3)

Defer this pending a design-and-evidence spike. It must not replace bytecode-local `parameter` origins. The spike defines cross-file call-site identity, admissible proven `callgraph` edges, recursion, callbacks, cycles, depth limits, and cutoff behavior.

Any future opt-in record must visibly carry `context: "union-over-callers"` and per-caller call-site evidence. It is a union, not evidence for one feasible end-to-end path. A production contract follows only with a demonstrated public consumer benefit.

## Redistributable firmware-derived corpus evidence (R-7)

Create a small CI corpus of stripped, 32-bit LNUM32 chunks from the pinned public authority. Record source, compiler inputs, command, output hash, profile, layout, and expected semantic assertions in its manifest. Add an architecture-family layout only where provenance and a distinct retained claim require it.

The corpus must test semantic facts and failure behavior with corruption controls; stable total counts alone are not an oracle. It must not contain Deco binaries, vendor secrets, or private investigation findings.

## Selection order

- Caller-unioned substitution only after its safety and public-consumer spike.
- Firmware-derived corpus evidence when a public claim needs coverage beyond the existing firmware-shaped fixtures.
