# Sprint contract: generate and verify the release SBOM

Lane: release infrastructure. Roadmap position: Milestone 1, after the locked dependency
audit and before hosted package assembly, the evidence index, durable release retention,
or publication.

## Public outcome

A maintainer can generate one conventionally named, deterministic CycloneDX document
for the `luad` executable's locked Cargo dependency graph and independently verify that
it describes the clean source revision rather than trusting a file merely because an
SBOM tool emitted it.

The maintained command writes exactly `luad-<version>.cdx.json` into a new or empty
output directory. It uses the official `cargo-cyclonedx` 0.5.9 generator to emit
CycloneDX 1.5 JSON for the `luad` binary with transitive normal and build dependencies,
default release features, and the conservative union of target-conditioned Cargo paths.
Build-only components remain present with their CycloneDX excluded scope; development-
only dependencies are absent.

This is a source dependency inventory. It does not claim that every listed conditional
component is linked into both platform archives, prove the contents of a compiled
binary, replace the required dependency audit, or promote a host or Lua target.

## Allowed paths

Implementation may change only:

- `crates/luad-oracle/src/lib.rs`;
- `crates/luad-oracle/src/bin/luad_release.rs`;
- `crates/luad-oracle/src/release_package.rs`, only to expose or reuse the existing
  clean-revision and workspace-version helpers without changing archive behavior;
- one new `crates/luad-oracle/src/release_sbom.rs` module;
- one new `crates/luad-oracle/tests/test_release_sbom.rs` integration test;
- one new `scripts/generate-release-sbom.sh` maintainer command;
- `.github/workflows/ci.yml`; and
- `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`,
  `docs/RELEASING.md`, and this checkpoint.

The implementation must use the existing `serde_json`, hashing, temporary-directory,
clean-revision, and version helpers where they express this claim. No new Rust package,
workspace dependency, or lockfile update is authorized.

`Cargo.toml`, every package manifest, `Cargo.lock`, `deny.toml`, toolchain files,
candidate workflows, archive membership, production CLI or dialect code, fixtures,
schemas, capability records, target manifests, and release manifests are outside this
batch.

## Document and identity boundary

The accepted document must have all of these properties:

- `bomFormat` is `CycloneDX`, `specVersion` is `1.5`, and the document version is `1`;
- generator identity is exactly `cargo-cyclonedx` 0.5.9;
- the metadata root is the `luad` application with the workspace version, description,
  repository URL, and exact `MIT OR Apache-2.0` project license expression;
- the source revision and SHA-256 of the checked-in `Cargo.lock` are recorded as
  namespaced metadata properties;
- the target scope records cargo-cyclonedx's all-targets property, while the public
  documentation explains the conservative source-graph meaning;
- every required or build-only component reachable from the locked `luad-cli` package
  under normal/build edges has a unique reference, name, version, scope, and declared
  license; registry components retain their Cargo.lock SHA-256 values and package URLs;
- every dependency reference resolves, the root dependency entry reaches the expected
  graph, and no development-only package is admitted merely because it exists in the
  workspace lock file;
- the timestamp is fixed through `SOURCE_DATE_EPOCH=0`, no random serial number is
  present, JSON is canonical pretty-printed UTF-8 with one trailing newline, and two
  clean checkouts of the same revision produce byte-identical output; and
- no absolute checkout, runner, home, target, or temporary path remains in the document.

The canonicalizer may replace generator-owned local path references with stable
workspace references and add the two namespaced identity properties. It must not invent
component versions, licenses, hashes, package URLs, scopes, or dependency edges.

Legacy upstream Cargo license strings that cargo-cyclonedx cannot parse as SPDX may be
retained only as named CycloneDX licenses and only when the exact encountered names are
passed explicitly to the generator. This does not create a `deny.toml` exception or
weaken the accepted license gate.

## Acceptance evidence

The focused ordinary regression is:

```console
cargo test -p luad-oracle --test test_release_sbom
```

It must exercise the same canonicalize/verify boundary used by the maintained command
and prove document identity, bounded parsing, exact graph closure, registry checksums,
path independence, deterministic bytes, output-directory refusal, and non-promotion.
The independent graph comparator derives the normal/build closure from locked Cargo
metadata or `cargo tree`; generator self-description is not sufficient proof of
completeness.

At least these negative controls must fail with actionable diagnostics:

1. remove a required component and all references to it, so only the independent locked-
   graph comparison can detect the omission;
2. substitute the root version, source revision, project license, or one registry
   component checksum;
3. add a development-only component or an unresolved dependency reference; and
4. inject an absolute checkout path or a noncanonical timestamp/serial number.

The required hosted `Release SBOM` job runs on `ubuntu-latest`. It downloads the
official `cargo-cyclonedx-0.5.9` Linux x86-64 GNU release archive, verifies SHA-256
`fb8dbee9f182173e062a64a387b21a0badc6fab8b2abf9294973f012972bf6d8`, confirms the
reported tool version, runs the maintained command twice from distinct clean checkout
paths, and requires byte equality plus a successful independent verification. The job
may upload the verified document as short-lived diagnostic evidence, but an expiring CI
artifact is not the durable 1.0 SBOM authority.

Missing Cargo metadata, missing or wrong generator version, unavailable locked graph,
generator warnings outside the explicitly admitted legacy license names, a skipped
comparison, or an unexpected negative-control pass fails acceptance.

The steward then runs `bash scripts/check.sh` once from the clean implementation
candidate and records official Lua compiler versions and all skips as usual.

## Documentation closure

Acceptance documents the one local command, exact output name and format, generator
version, source-graph scope, deterministic identity, and verification behavior.
`CHANGELOG.md` records the new release artifact. `ROADMAP.md` removes only the completed
SBOM obligation while retaining checksums, the evidence index, hosted archives,
retention, rollback, and publication. The implementation pull request returns this file
and its README index entry to the neutral no-work checkpoint.

## Non-goals

This batch does not modify dependency versions or policy, embed an SBOM in the binary or
platform archives, prove platform-specific binary composition or cross-host Rust build
reproducibility, build both archives in hosted CI, add the evidence index, alter
`SHA256SUMS`, publish or retain a GitHub release, implement withdrawal or rollback,
change runtime behavior or schemas, or promote a Lua target.

## Stop condition

Stop after the one deterministic CycloneDX document, independent locked-graph verifier,
required hosted job, corruption controls, and aligned documentation are reviewable and
green. Any graph mismatch, unknown generator warning, leaked host path, nondeterminism,
or unavailable prerequisite blocks closure; it does not authorize a suppression,
dependency change, second SBOM format, or adjacent Milestone 1 work.
