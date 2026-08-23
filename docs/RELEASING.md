# Release procedure

## Current release stop

Do not make a production release until the exact target-specific release gate in
the [active sprint](NEXT-SPRINT.md) or a later sprint passes from one clean revision.
The [product roadmap](../ROADMAP.md) defines the required target separation. Lua 5.4.8 and embedded Lua 5.1 use separate evidence manifests;
prerequisites for one target cannot promote the other. Pre-release tags must
enumerate every experimental or ungated public surface.

## Preconditions

Before cutting any release:

1. Confirm a clean worktree and review every generated evidence artifact.
2. Install and checksum-verify the exact official compiler releases required by the claimed support matrix.
3. Verify the fixture matrix covers every claimed architecture-dependent layout and explicit vendor profile, including stock Lua 5.1 with 32-bit and 64-bit `size_t` where claimed.
4. Run every named proof gate with no skips.
5. Run `bash scripts/check.sh`.
6. Run the maintained fuzz corpus and configured time-bounded fuzz jobs.
7. Review `luad capabilities --format json --evidence` against actual gate results.
8. Ensure README support status is generated from or identical to the evidence manifest.
9. Update `CHANGELOG.md`, version metadata, schemas when necessary, and this release procedure.
10. Build release artifacts on each supported target and smoke-test their CLI and schemas.

## Evidence bundle

The release should include or link to a machine-readable evidence bundle containing:

- source commit and dirty-state flag;
- Rust toolchain;
- target platform;
- official Lua archive URLs and SHA-256 values;
- detected compiler versions;
- resolved dialect/profile and validated chunk-layout matrix;
- source and compiled fixture SHA-256 values;
- gate names and results;
- fuzz corpus revision and run summary;
- schema major versions.

Private firmware corpora may be cited as supplemental field evidence using aggregate hashes and result counts, but a release claim also requires redistributable minimized fixtures and independently reproducible gates.

A capability without a passing release gate must be reported as `experimental` or omitted.

## Versioning

Before 1.0, schema and CLI contracts may change, but changes must still be documented. A schema-incompatible machine-output change requires a schema-major increment even during pre-release development.

The workspace declares dual MIT/Apache-2.0 licensing. Release artifacts and repository license files must agree with Cargo metadata before public distribution.

## Tagging and publication

The project has not yet defined a crates.io publication order or binary-distribution channel. Do not improvise publication as part of an unrelated change. Once defined, document exact signing, checksum, tag, and rollback steps here.
