# Report encoded header widths and parser failure categories accurately

Fresh as of 2026-11-22.

The Lmod cache trial reported a native size_t width that Lua 5.4 does not
serialize. The OpenTX trial classified a malformed constant tag as exhaustion
of a configured resource. Correct these public inspect outcomes and their shared
parser metadata. Preserve declared widths in older formats and keep explicit
vendor-profile refusals distinct. Add no format support.

Scope the change to header and interpretation facts, parser diagnostics for
constant counts and tags, CLI classification, the diagnostic catalog, public
examples and the tests that own those contracts. For Lua 5.4 use zero in the
numeric size_t slot (as in 5.5) and include only the declared widths and
validated endianness in the layout. Invalid tags exit 1 and over-limit constant
counts exit 5 across exposed stock readers.

Build with `cargo build -p luad-cli`. Run `cargo test -p luad-oracle --test
test_layout_truth_matrix --test test_failure_provenance` for explicit and
detected layouts, malformed tags, and count controls. Run the diagnostic
catalog and machine contract gate scripts with a clean candidate and
`bash scripts/check.sh`. Replay the two original artifacts before closing.
