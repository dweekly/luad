# Trace literal bytes to their instruction uses

Fresh as of 2026-11-21.

On stripped argparse, the query for a newline-prefixed usage message misses
the constant. On json.lua a backspace query selects the letter b. Following
matching constants to instructions also takes one xrefs invocation per ID.

Make quoted string equality, inequality and substring predicates use operand
UTF-8 bytes. Support backspace and form feed escapes and reject unknown escapes.
Add an exact UTF-8 literal filter to xrefs across the input's constant pools.
Intersect source and target filters. Keep the existing artifact scope, relation
semantics, order and analysis validation. Leave dialects and inference out of scope.

Change the query engine, xrefs CLI/response, their dependency manifests and locks,
ordinary oracle tests, public help and machine reference. Record the public project
trials in the prior-art document and supply a repository skill for this workflow.

Build with `cargo build -p luad-cli`, then run
`cargo test -p luad-oracle --test test_literal_retrieval`. Assert exact IDs for
control bytes, escaped lookalikes, binary data, nested owners and combined selectors.
Reject invalid flags and escapes. Check JSON, JSONL and text on the public boundary.
Replay the three project tasks on the candidate and stop at a reviewable diff.
