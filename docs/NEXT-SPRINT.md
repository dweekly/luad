# Sprint contract: reproduce both release archives on hosted builders

Lane: release infrastructure. Roadmap position: Milestone 1, after the accepted local
archive, dependency-audit, MSRV, and SBOM boundaries and before the evidence index,
durable release retention, or publication.

Fresh as of: 2026-08-27.

## Public outcome

A maintainer can point to one required GitHub Actions check that builds, verifies,
installs, and compares the two planned release-platform archives instead of relying on
a package assembled on one local machine.

The hosted check uses the accepted `scripts/package-release.sh` boundary unchanged. For
each exact platform it runs two independent clean-checkout jobs with the pinned Rust
1.97.1 release-builder toolchain:

| Platform | Host runner | Rust host triple |
|---|---|---|
| `linux-x86_64` | `ubuntu-latest` | `x86_64-unknown-linux-gnu` |
| `macos-aarch64` | `macos-latest` | `aarch64-apple-darwin` |

Each job must produce the conventionally named archive, member ledger, one-entry
checksum file, and installation transcript from the same clean revision. The existing
packaging command independently verifies canonical archive bytes and source inputs,
extracts into a fresh directory, and runs the packaged version and capabilities smokes
before the job may upload anything.

An aggregation job compares the two independent results for each platform byte for
byte. It retains one accepted copy per platform and constructs one lexicographically
ordered, two-entry `SHA256SUMS` covering the two archives. The resulting
`release-archives` Actions artifact is short-lived diagnostic evidence only.

This proves repeatable host-native builds on two independent jobs in the named GitHub
runner classes. It does not claim identical binaries across different operating
systems, runner-image revisions, Rust versions, target triples, or arbitrary build
environments.

## Allowed paths

Implementation may change only:

- `.github/workflows/ci.yml` for the hosted build replicas, comparison, checksum
  assembly, and short-lived diagnostic upload; and
- `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`,
  `docs/RELEASING.md`, and this checkpoint for the exact hosted behavior, limitations,
  documentation index, and accepted history.

The implementation must call `scripts/package-release.sh`; it must not duplicate the
archive member contract, invoke a second packer, or bypass the command's verify,
extract, and smoke boundary. The accepted package implementation and focused regression
remain unchanged prerequisites.

`Cargo.toml`, package manifests, `Cargo.lock`, `deny.toml`, toolchain files,
`scripts/package-release.sh`, Rust production or test code, candidate workflows,
archive membership, schemas, capabilities, fixtures, target manifests, release
manifests, and SBOM generation are outside this batch.

## Hosted evidence boundary

The required hosted workflow must satisfy all of these conditions:

1. The build matrix has exactly two replicas for each of the two platform rows above.
   Every replica is a distinct job, starts from a clean checkout of the workflow
   revision, confirms the expected Rust host triple, and runs the maintained packaging
   command from its own source path.
2. Each replica uploads exactly its archive, JSON member ledger, one-entry
   `SHA256SUMS`, and JSON installation transcript under a platform-and-replica-specific
   artifact name. Missing files, extra files, an unsupported host, a dirty tree, a
   build failure, verifier failure, or smoke failure fails the job.
3. One Linux aggregation job downloads all four replica results. For each platform it
   requires byte equality for the archive, ledger, checksum file, and installation
   transcript; comparing only self-declared hashes is insufficient.
4. The aggregation job independently checks that each accepted archive matches its
   one-entry checksum, then emits a canonical two-entry `SHA256SUMS` ordered by archive
   name and verifies it against the retained Linux and macOS archives.
5. A negative control changes one byte in a temporary archive copy and proves that the
   same byte comparator and checksum check reject it. The corrupted probe is never
   uploaded as accepted evidence.
6. The final diagnostic upload contains exactly one archive, ledger, and installation
   transcript for each platform plus the combined `SHA256SUMS`. It uses a seven-day
   retention period and is described as transport, not durable release authority.

The `Release Archives` aggregation check runs for pull requests and pushes to `main`.
The implementation pull request must be green before merge, and the landed `main` run
must also close successfully because its source revision differs from the pull-request
merge ref. No required matrix cell or comparison may skip.

The workflow may use ordinary platform tools for file enumeration, exact byte
comparison, and SHA-256 verification. It must keep the release-builder toolchain and
platform mapping in one matrix and avoid introducing a parallel archive format or
identity vocabulary.

## Acceptance evidence

The accepted local archive oracle remains:

```console
cargo test -p luad-oracle --test test_release_package
```

It must continue to pass all four tests, including deterministic archives and ledgers,
exact members and modes, installation smokes, dirty/unsupported-host refusal,
non-promotion, and corruption controls. The hosted jobs are the new evidence for
independent build repetition; source-text inspection or uploaded filenames alone are
not proof that the matrix executed or that the bytes matched.

The steward then runs the repository aggregate once from the clean implementation
candidate:

```console
bash scripts/check.sh
```

The handoff records the exact source revision, all four hosted build cells, the
aggregation and negative-control results, archive names and SHA-256 values, official
Lua compiler versions present during the aggregate, and every skip or ignored test.

## Documentation closure

Acceptance documents the required hosted check, exact platform/runner/toolchain matrix,
two-replica comparison, combined checksums, installation smokes, seven-day diagnostic
retention, and reproducibility limits. `CHANGELOG.md` records hosted archive evidence.
`ROADMAP.md` removes only the completed hosted-build and repeated-build obligation while
retaining the evidence index, SBOM composition, durable retention, release notes,
rollback, publication, and final-candidate rebuild requirements.

The implementation pull request returns this file and its README index entry to the
neutral no-work checkpoint.

## Non-goals

This batch does not create a Git tag or GitHub Release, publish or durably retain an
asset, assemble the 1.0 evidence index, merge the SBOM into the archive bundle, sign an
artifact, establish SLSA provenance, implement withdrawal or rollback, change archive
membership, or qualify reproducibility outside the exact hosted matrix.

It does not change dependencies, MSRV, runtime behavior, machine schemas, capability
status, bytecode semantics, target layouts, candidate identities, release manifests,
or Lua support claims. A short-lived Actions artifact is not a release candidate or a
promotion artifact.

## Stop condition

Stop after both two-replica platform builds, byte comparisons, combined checksum
verification, corruption probe, short-lived diagnostic bundle, and aligned
documentation are reviewable and green on the implementation pull request and landed
`main`.

Any platform mismatch, nondeterministic binary or sidecar, missing smoke, checksum
disagreement, skipped matrix cell, or unavailable runner blocks closure. It does not
authorize suppressing the mismatch, weakening the comparator, changing the archive
format, publishing partial assets, or beginning the evidence index.
