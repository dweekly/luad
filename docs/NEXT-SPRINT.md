# README identity and coverage contract

Add the existing project logo and truthful CI, Codecov, release, and license badges
to the README. Supply Codecov with measured Linux workspace test coverage, including
the CLI subprocesses exercised by the oracle suite.

Scope: `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, this checkpoint,
`.github/workflows/coverage.yml`, and `scripts/coverage.sh`. Reuse `site/logo.png`,
the pinned Rust toolchain, official compiler installer, and existing tests.

Use a separate coverage workflow on hosted Linux, with path filters and a job timeout.
Do not change existing correctness gates, release publication, product behavior, or
support claims. Coverage is a development metric, not semantic qualification.

Evidence: render the README; resolve badge/image targets; lint the workflow and shell;
run the coverage command against a clean candidate with the required compilers; verify
a nonempty report includes CLI and library sources; verify Codecov accepts the upload;
require existing aggregate CI. Do not substitute an invented percentage for a missing
report. Stop after integration and verification of the README and coverage badge.
