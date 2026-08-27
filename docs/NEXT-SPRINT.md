# Sprint contract: assemble and verify a release archive

Lane: product. Roadmap position: Milestone 1, first publication outcome.

Fresh as of: 2026-08-27.

## Outcome

A maintainer can turn a clean `luad` revision into one conventionally named binary
archive, verify its contents and source identity independently, extract it, and run the
packaged binary without inventing release-day procedure.

This batch establishes the local non-promoting archive boundary. It does not publish a
release or claim that a platform build has qualified for distribution.

## Public claim

For the exact `linux-x86_64` and `macos-aarch64` platform names, the maintained release
packaging command:

- derives the version from the workspace package identity and refuses a dirty source
  tree, an unsupported platform name, or a version mismatch;
- writes `luad-<version>-<platform>.tar.gz`, a deterministic member ledger, and a
  `SHA256SUMS` entry for the archive;
- constructs byte-identical archive and ledger bytes when given the same binary,
  documentation, license, version, source revision, and platform inputs;
- includes one top-level `luad-<version>-<platform>/` directory containing executable
  `luad`, `README.md`, every license text required by the workspace license expression,
  and machine-readable version, source-revision, target-triple, and platform identity;
  and
- verifies the checksum, exact member set and order, safe relative paths, modes,
  per-member sizes and digests, version/source/platform identity, and absence of any
  promotion artifact before an extracted `luad --version` and
  `luad capabilities --format json` smoke run is accepted.

Archive verification must reject corruption rather than trusting a ledger or identity
record merely because it was emitted beside the archive. Packaging and smoke output
must remain deterministic, bounded, and separate from machine stdout produced by the
packaged CLI.

## Scope

The implementation may change only these production and ordinary-test paths:

- `Cargo.toml` and `Cargo.lock` for honest release identity and package wiring;
- `LICENSE` plus one additional root license file required by the declared
  `MIT OR Apache-2.0` license expression;
- `crates/luad-oracle/Cargo.toml`, `crates/luad-oracle/src/lib.rs`, existing reusable
  deterministic-archive primitives in `crates/luad-oracle/src/candidate.rs`, one new
  release-packaging module, and one new maintainer-facing release-packaging binary;
- `scripts/package-release.sh` for the clean-revision build, package, independent
  verification, extraction, and smoke workflow;
- one new `crates/luad-oracle/tests/test_release_package.rs` ordinary integration test;
  and
- `README.md`, `CHANGELOG.md`, `docs/RELEASING.md`, and this checkpoint for the exact
  command, archive contract, limitations, documentation index, and accepted history.

The implementation must reuse the established deterministic ustar/gzip parsing and
ledger behavior where it expresses this claim. New proof infrastructure is allowed
only for release-specific identity, exact membership, checksum, and install behavior
that the LNUM32 candidate packer does not own.

## Evidence

The focused regression is:

```console
cargo test -p luad-oracle --test test_release_package
```

It must prove all of the following through the maintained command or the same public
pack/verify boundary used by that command:

1. identical inputs produce byte-identical archives and ledgers with the exact required
   member names, order, modes, sizes, and digests;
2. a clean local dry run verifies `SHA256SUMS`, extracts into a fresh temporary
   directory, and records successful `--version` and machine-readable capabilities
   smoke results without changing supported capability status;
3. independent negative controls reject, at minimum, a changed archive byte, a
   substituted checksum, a missing or added member, an unsafe path, an executable-mode
   change, and mismatched version, revision, target triple, or platform identity; and
4. the command refuses a dirty tree and unknown platform before emitting an accepted
   artifact.

Because this batch may reuse archive primitives, the existing candidate archive
regression is the narrow compatibility check:

```console
cargo test -p luad-oracle --test test_candidate_lua51_lnum32 \
  test_candidate_tool_pack_deterministic_archive_and_ledger
```

The steward then runs the repository aggregate once:

```console
bash scripts/check.sh
```

The handoff records the focused command results, the exact dry-run archive name and
source revision, whether either official Lua compiler was present, and every skip. The
ordinary CI artifacts produced by this product batch are diagnostic only and are not
release evidence.

## Non-goals

This batch does not:

- create a Git tag, GitHub Release, uploaded asset, release note, retained evidence
  bundle, withdrawal operation, or rollback automation;
- add CI matrices or claim reproducible Rust compilation across different hosts;
- generate an SBOM, dependency-license report, vulnerability report, signature, or
  provenance attestation;
- advertise or exercise crates.io publication or `cargo install luad`, or establish an
  MSRV distinct from the contributor toolchain;
- change a public CLI/schema major, bytecode semantics, target layout, fixture,
  capability status, candidate manifest, or release manifest; or
- qualify either platform or any Lua target for 1.0 distribution.

Those remain separate Milestone 1 or later contracts after this local archive boundary
is accepted.

## Stop condition

Stop with one reviewable candidate diff when the local pack/verify/install workflow and
its corruption controls pass from a clean revision, documentation names only that
behavior, and `docs/NEXT-SPRINT.md` has returned to the neutral no-work checkpoint.

No target-promotion artifact or hosted release may be produced by this sprint.
