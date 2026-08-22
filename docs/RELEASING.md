# Release procedure

## Current release stop

Do not make a production release while Milestones 0–3 in [ROADMAP.md](../ROADMAP.md) are incomplete. Pre-release tags must prominently identify the known correctness defects and experimental dialect status.

## Preconditions

Before cutting any release:

1. Confirm a clean worktree and review every generated evidence artifact.
2. Install and checksum-verify the exact official compiler releases required by the claimed support matrix.
3. Run every named proof gate with no skips.
4. Run `bash scripts/check.sh`.
5. Run the maintained fuzz corpus and configured time-bounded fuzz jobs.
6. Review `luad capabilities --format json --evidence` against actual gate results.
7. Ensure README support status is generated from or identical to the evidence manifest.
8. Update `CHANGELOG.md`, version metadata, schemas when necessary, and this release procedure.
9. Build release artifacts on each supported target and smoke-test their CLI and schemas.

## Evidence bundle

The release should include or link to a machine-readable evidence bundle containing:

- source commit and dirty-state flag;
- Rust toolchain;
- target platform;
- official Lua archive URLs and SHA-256 values;
- detected compiler versions;
- source and compiled fixture SHA-256 values;
- gate names and results;
- fuzz corpus revision and run summary;
- schema major versions.

A capability without a passing release gate must be reported as `experimental` or omitted.

## Versioning

Before 1.0, schema and CLI contracts may change, but changes must still be documented. A schema-incompatible machine-output change requires a schema-major increment even during pre-release development.

The workspace declares dual MIT/Apache-2.0 licensing. Release artifacts and repository license files must agree with Cargo metadata before public distribution.

## Tagging and publication

The project has not yet defined a crates.io publication order or binary-distribution channel. Do not improvise publication as part of an unrelated change. Once defined, document exact signing, checksum, tag, and rollback steps here.
