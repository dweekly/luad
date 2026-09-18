# Release documentation and runner repair contract

Publish the README and website correction for experimental 0.2.0. Unblock its
verification by correcting the subprocess tripwire's process-group signal command.

The observed boundary is Linux procps-ng parsing a negative PID as an option when
`kill` arguments omit `--`. Cleanup must address only the subprocess group created
by the tripwire. Keep deadlines and existing containment tests intact.

Scope: `README.md`, `site/index.html`, `CHANGELOG.md`, this checkpoint, and
`crates/luad-oracle/src/tripwire.rs`. No CLI feature change, support promotion,
release-asset replacement, or version-tag movement is authorized.

Evidence: a signal-0 regression must distinguish an existing isolated child group
from the same group after it is reaped, without sending a terminating group signal.
Run `cargo test -p luad-oracle --lib tripwire::tests` on macOS and Linux, then the
existing aggregate CI. Parse website metadata and links, execute its documented
installation commands, and verify the deployed Pages HTML against source.

Stop after the repair and corrected website are integrated and verified.
