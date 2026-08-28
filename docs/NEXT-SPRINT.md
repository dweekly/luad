# Sprint contract: assemble and verify the release bundle

Lane: release infrastructure. Roadmap position: Milestone 1, after the accepted
dependency audit, local release archive, hosted repeated-archive, and deterministic
SBOM boundaries and before GitHub Release publication or durable evidence retention.

Fresh as of: 2026-08-27.

## Public outcome

A maintainer can assemble and verify one conventional, non-promoting release bundle
from the already accepted archive and SBOM outputs. For the current workspace version,
the output directory contains exactly:

```text
SHA256SUMS
evidence-index.json
luad-<version>-linux-x86_64.tar.gz
luad-<version>-macos-aarch64.tar.gz
luad-<version>.cdx.json
```

`SHA256SUMS` covers the other four files in lexicographic filename order. The evidence
index binds the exact source revision, both package platforms, archive hashes, member
ledgers, installation-smoke results, SBOM identity, and prerequisite result references.
It identifies itself as a non-promoting dry run and contains no supported target or
target-release-manifest entry.

The assembler consumes, but does not publish as separate bundle files, the two accepted
archive ledgers and installation transcripts. Their canonical facts are retained in the
evidence index so the five-file bundle remains small and familiar.

## Allowed paths

Implementation may change only:

- `crates/luad-oracle/src/release_bundle.rs` for bounded assembly and verification;
- `crates/luad-oracle/src/bin/luad_release.rs` and
  `crates/luad-oracle/src/lib.rs` to expose the maintainer command;
- `crates/luad-oracle/tests/test_release_bundle.rs` for the public command regression
  and corruption controls;
- `scripts/assemble-release-bundle.sh` for the maintained clean-revision entry point;
- `.github/workflows/ci.yml` for the prerequisite-dependent hosted dry run and
  short-lived diagnostic upload; and
- `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`,
  `docs/RELEASING.md`, and this checkpoint for the exact behavior, limits,
  documentation index, and accepted history.

No Cargo manifest, dependency, lockfile, toolchain, package builder, SBOM generator,
candidate workflow, target manifest, schema registry, fixture, capability, or product
runtime path may change.

## Input and composition contract

The maintained command accepts four explicit inputs:

1. a clean repository at the revision being described;
2. the exact seven-file output of the accepted hosted archive aggregation boundary:
   two archives, their two ledgers, their two installation transcripts, and the
   two-entry archive `SHA256SUMS`;
3. the one canonical `luad-<version>.cdx.json` output of the accepted SBOM boundary; and
4. a bounded JSON prerequisite-reference document supplied by the hosted workflow.

The prerequisite document contains exactly one successful record for each accepted
boundary:

| Evidence ID | Hosted check/result named by the reference |
|---|---|
| `dependency-audit` | `Dependency Audit` |
| `local-release-archive` | the Linux contributor check containing the accepted focused archive oracle |
| `release-sbom` | `Release SBOM` |
| `hosted-release-archives` | `Release Archives` |

Each record names the evidence ID, check name, exact source revision, successful
conclusion, and immutable HTTPS GitHub Actions result URL. IDs are unique and sorted.
All four revisions must equal the clean repository revision. Missing, duplicate,
failed, skipped, extra, cross-revision, non-GitHub, or unbounded references fail closed.

The assembler does not call GitHub or treat a caller-authored JSON document as proof.
In the hosted dry run, the workflow constructs these records only from its actual
`needs` results and run identity, and the bundle job cannot start unless all named jobs
succeeded. Review of the hosted run remains the authority that those references are
truthful; the index makes that evidence discoverable and composable.

The archive and SBOM gates remain accepted prerequisites. This batch must not rerun or
copy their internal semantic comparators. It owns only the new interaction among their
outputs and therefore verifies:

- the input directories have the exact filenames and no extra files;
- the workspace version and clean source revision agree across both installation
  transcripts, the SBOM identity, every prerequisite record, and the index root;
- the platform set is exactly `linux-x86_64` and `macos-aarch64`, with target triples
  `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin` respectively;
- the two-entry archive checksum file is canonical and matches the two archive bytes;
- each archive name agrees with its ledger and installation transcript, each sidecar is
  canonical JSON with no unknown fields, and the index preserves its exact facts;
- the SBOM is named for the same version, identifies CycloneDX 1.5, carries the same
  source revision, and records its component count and `Cargo.lock` digest in the
  index; and
- the output index and four-entry checksum file use canonical deterministic JSON/text
  bytes and contain no absolute paths, temporary paths, timestamps, hostnames, tokens,
  or mutable branch names.

Input reads, JSON arrays, strings, artifact counts, and output sizes are explicitly
bounded. Inputs must be regular files beneath their declared roots; absolute paths,
path traversal, symlinks, and pre-existing non-empty output directories are rejected.
The command never executes a bundled binary or Lua input.

## Evidence-index boundary

`evidence-index.json` is a release-maintainer artifact, not a public CLI schema. Its
first schema version has closed top-level fields for:

- schema and dry-run kind;
- tool version, clean source revision, and empty promoted-target set;
- the four prerequisite result references;
- exactly two platform records containing archive identity, SHA-256, canonical member
  ledger, and installation transcript; and
- the SBOM filename, SHA-256, CycloneDX version, component count, and `Cargo.lock`
  SHA-256.

Platform and prerequisite records are lexicographically ordered. Unknown fields and
unknown enum values fail verification. The index intentionally does not contain its own
digest or the digest of `SHA256SUMS`; `SHA256SUMS` instead covers the index, SBOM, and
both archives without a circular hash dependency.

The empty promoted-target set is a safety assertion, not a placeholder support claim.
Changing that set or adding a target release manifest requires a later exact-target
qualification contract.

## Acceptance evidence

The new focused regression is:

```console
cargo test -p luad-oracle --test test_release_bundle
```

It must prove deterministic assembly and successful independent verification from
bounded fixture artifacts, exact five-file output, canonical four-entry checksums,
same-revision/platform/SBOM composition, the four exact prerequisite identities, and
non-promotion. It must include effective negative controls for at least:

- a changed byte in an archive, SBOM, or evidence index;
- a missing, extra, failed, skipped, duplicated, substituted, or cross-revision
  prerequisite;
- a ledger, installation transcript, platform, target triple, or SBOM identity
  mismatch;
- a non-canonical checksum or JSON document, an extra output/input file, and an unsafe
  path or symlink; and
- any non-empty promoted-target or target-manifest claim.

The hosted `Release Bundle` job depends on the existing dependency-audit, Linux
contributor-test, `Release SBOM`, and `Release Archives` results. It downloads the
accepted diagnostic inputs, assembles the bundle twice into distinct fresh directories,
requires all five corresponding files to be byte-identical, verifies both bundles, and
proves a one-byte mutation fails verification before uploading exactly one
`release-bundle` artifact for seven days.

The job runs for pull requests and pushes to `main`. Both the implementation pull
request and the landed `main` revision must pass. The diagnostic upload is transport,
not publication or durable authority.

The steward runs the focused regression and then the repository aggregate once from the
clean candidate:

```console
bash scripts/check.sh
```

The close report records the exact revision, focused-test count, official Lua compiler
versions present, aggregate result, every skip or ignored test, all prerequisite and
bundle job results, the five bundle filenames, and all four published checksum values.

## Documentation closure

Acceptance documents the command, five-file bundle, evidence-index fields, prerequisite
references, checksum coverage, hosted dry run, bounds, and non-promotion limitation.
`CHANGELOG.md` records the release-bundle dry run. `ROADMAP.md` removes only the accepted
evidence-index and checksum-composition obligation while retaining GitHub Release
publication, source attachment, durable retention, release notes, tag behavior,
withdrawal/rollback execution, target promotion, and final-candidate assembly.

The implementation pull request returns this file and its README index entry to the
neutral no-work checkpoint.

## Non-goals

This batch does not create or edit a tag or GitHub Release, attach a source archive,
publish an asset, retain evidence beyond ordinary Actions expiry, select a signing
identity, generate provenance attestations, implement a release-note template, or
exercise withdrawal or rollback.

It does not change archive contents, SBOM contents, dependencies, MSRV, runtime
behavior, machine-output schemas, capability status, bytecode semantics, target
layouts, candidate identities, release manifests, or Lua support claims. It does not
authenticate GitHub over the network or claim that a short-lived workflow artifact is
durable release evidence.

## Stop condition

Stop when the bounded assembler, independent composition verifier, ordinary regression,
hosted two-run comparison and corruption probe, exact five-file diagnostic bundle, and
aligned documentation are reviewable and green on both the implementation pull request
and landed `main`.

Any prerequisite ambiguity, cross-revision input, checksum or identity mismatch,
non-deterministic output, skipped required result, extra file, unavailable hosted input,
or attempted target promotion blocks closure. It does not authorize weakening a
comparator, trusting self-declared evidence, publishing partial assets, extending
retention, or beginning GitHub Release automation.
