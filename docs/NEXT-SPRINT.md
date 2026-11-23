# Find constants after a semantic-analysis refusal

Fresh as of 2026-11-22.

For a parsed Lua 5.2, 5.3 or 5.5 file, single-file query and xrefs must
identify the structural constant export when semantic analysis is unavailable.
The diagnostic catalog and batch query diagnostic should carry the same advice.
Preserve exit 4, empty single-file stdout and the existing eligibility boundary.

Build with `cargo build -p luad-cli` and run `cargo test -p luad-oracle --test
test_analysis_eligibility`. Exercise both commands on the three stock hello
fixtures and follow the suggested command to a complete export with the expected
string. Verify that corrupt input takes the existing invalid-input path. Replay
the lookup against the shipped Debian VLC playlist package. Run
`bash scripts/gates/gate-diagnostic-catalog.sh OUT` and `bash scripts/check.sh`
on a clean candidate. Close at the neutral checkpoint and merge with the
previously verified trial changes after green pull-request checks.
