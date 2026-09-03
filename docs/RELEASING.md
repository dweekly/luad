# Release procedure

Status: release policy and operational checklist.

Fresh as of: 2026-09-02.

Revalidate or delete when: the release target matrix, qualification lifecycle, package
platforms, artifact channel, compatibility policy, signing/checksum policy, release
ownership, or rollback procedure changes.

## Current release stop

Do not make a production release. No exact target is currently promoted, the active
sprint is a no-work checkpoint, and the required public-contract, customer,
extended-fuzz, security-review, target-qualification, and final-candidate evidence has
not closed over one clean revision. The publication rehearsal below proves mechanics;
it does not authorize a `v*` tag or production release.

The dependency-ordered path is [the product roadmap](../ROADMAP.md). Exact release work
begins only under a qualification contract in [the active sprint](NEXT-SPRINT.md).
Passing an ordinary test, prerequisite gate, candidate packaging workflow, private
corpus run, or model review cannot remove this stop.

## Frozen version-1 boundary

The version-1 bytecode claim contains exactly three independent target identities:

| Lua release | Canonical profile | Serialized layout |
|---|---|---|
| OpenWrt-derived Lua 5.1.5 LNUM32 | `lua5.1-lnum32` | `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4` |
| Stock PUC Lua 5.1.5 | `lua5.1` | `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0` |
| Stock PUC Lua 5.4.9 | `lua5.4` | format 0; 4-byte instructions; 8-byte `lua_Integer`; 8-byte `lua_Number`; pinned official compiler's standard little-endian representation |

The package platforms are exactly `linux-x86_64` and `macos-aarch64`. Enveloped command
JSON and the other major-1 JSON schema families freeze at major 1 for the 1.x line;
capabilities JSON and streaming JSONL/export freeze at major 2. CLI exit codes 0 through
6 freeze with the meanings in
[the machine-interface contract](MACHINE-INTERFACE.md#exit-codes). Command and fact
families acquire a 1.x compatibility promise only when the public automation-contract
milestone qualifies them. Existing symbolic-callee, value-origin, call-relation, and
related derived facts remain experimental until then.

The workspace remains dual `MIT OR Apache-2.0`; this permits use under terms compatible
with the [MIT-licensed Lua project](https://www.lua.org/license.html). The release owner
is the repository owner, `dweekly`. Accepted qualification results, sanitized customer
records, candidate packages, and final evidence are retained in the matching candidate
or final GitHub release in `dweekly/luad`. Expiring Actions artifacts and local temporary
directories may transport evidence but are not its durable authority.

This boundary is a future compatibility promise, not current support evidence. The
supported target set remains empty until exact target manifests are accepted.

## Release scope and order

Qualification proceeds in this order:

1. OpenWrt-derived Lua 5.1.5 `lua5.1-lnum32`;
2. stock PUC Lua 5.4.9 `lua5.4`; and
3. stock PUC Lua 5.1.5 `lua5.1`.

The order exercises the vendor-profile workflow first, repeats promotion on the final
Lua 5.4 release, and then closes stock Lua 5.1 without conflating it with LNUM32. A
prerequisite for one target cannot promote another. The 5.4.8 evidence already present
in the repository can support 5.4.9 only where an exact source/chunk delta gate admits
it.

Every other dialect, release, profile, and layout remains `experimental` or is omitted
from the support claim. Public prose must name exact releases and profiles rather than
compressing them into “Lua 5.x support.”

## Candidate, promotion, and release artifacts

These artifacts have different authority:

- A **candidate archive** is an installable binary bound to a source revision and
  platform. It is useful for qualification and user trials but does not promote a
  target.
- A **target release manifest** closes one exact target over authenticated prerequisite
  results, negative controls, platform evidence, and one clean revision. It is the only
  artifact allowed to promote that target in capabilities.
- A **1.0 evidence index** binds all required target manifests, platform packages,
  schemas, fuzz/security evidence, SBOM, checksums, limitations, and customer-transfer
  records to the same candidate revision.
- A **Git tag and GitHub release** publish the already accepted candidate. They do not
  manufacture evidence or repair a partial qualification.

Candidate IDs are immutable. Rebuilding from another revision requires a new ID even
when the marketing version has not changed.

## Qualification checklist

Before promoting any exact target:

1. Merge a qualification contract that names the exact release, profile, layout,
   platforms, fixtures and hashes, authorities, prerequisite gates, mutation probes,
   artifact destination, and promotion boundary.
2. Freeze a clean candidate revision and stop unrelated feature or schema changes.
3. Authenticate the official source archive, compiler source/build recipe, patches and
   configuration where applicable, compiler binaries, fixtures, and target layout.
4. Run every named prerequisite and the canonical target gate with no required skips.
5. Run `bash scripts/check.sh` once from the candidate revision.
6. Review black-box CLI behavior, text/machine agreement, mutation rejection,
   prerequisite identity, deterministic output, and artifact completeness.
7. Verify `luad capabilities --format json --evidence` against actual accepted results
   and keep README support status identical to the manifest.
8. Build and smoke-test the installable candidate on every advertised package platform.
9. Retain the complete results in the matching GitHub release in `dweekly/luad`.

Before publishing 1.0, additionally:

1. Run the configured extended fuzz campaign and publish its duration, configuration,
   corpus identity, resource envelope, and result.
2. Complete the focused hostile-input and release-supply-chain security review.
3. Record the representative runtime and peak-memory tripwires required by the roadmap.
4. Complete the internal transfer checkpoint and the out-of-profile refusal test below.
5. Confirm no P0 correctness or security defect remains open.
6. Assemble and verify the two platform archives, evidence index, SBOM, and checksums.
7. Update `CHANGELOG.md`, version metadata, schemas, README, security policy, candidate
   guide, compatibility statement, and known limitations.
8. Verify the final public artifacts after downloading them into a fresh environment.

## Customer-transfer checkpoints

The LNUM32 candidate must complete both of these before its promotion can feed 1.0:

- **Independent internal workflow:** a different model family or researcher receives
  only the candidate, public documentation, independently authored objective, and a
  different firmware version or vendor. The record includes commands, elapsed work,
  adapters, incorrect or ambiguous answers, and remaining workarounds.
- **Out-of-profile refusal test:** a different stock/vendor layout fails with an
  actionable diagnostic and the documented exit code.

The outside-human in-profile workflow (an outside person receives the released binary
and public quick start without coaching, on public firmware pre-screened only far
enough to resolve to the exact LNUM32 profile) is the first post-1.0 obligation in the
[roadmap](../ROADMAP.md#outside-validation). Until it closes, release documentation
describes 1.0 evidence as internal usability evidence and never as independent
adoption evidence.

Retain a sanitized customer-trial record in the matching candidate GitHub release in
`dweekly/luad`. Do not commit private firmware, sensitive findings, model transcripts, or
investigation-specific security judgments. Every reproducible correctness defect
becomes a minimized redistributable regression and passes its named gate before the
candidate is eligible again.

## Evidence bundle

The 1.0 evidence bundle includes:

- source commit and dirty-state flag;
- tool version, Rust toolchain, MSRV, target triples, and build hosts;
- official Lua archive URLs and SHA-256 values;
- immutable vendor/upstream revisions, ordered patch hashes, target configuration, and
  compiler build recipe where applicable;
- detected compiler versions and compiler-binary hashes per platform;
- resolved dialect/profile and validated chunk-layout matrix;
- source and compiled fixture hashes;
- gate specifications, results, skip counts, and mutation-probe rejections;
- schema majors, stable command surface, and compatibility statement;
- fuzz corpus revision and extended-campaign summary;
- security-review disposition and performance tripwires;
- package archive hashes and member ledgers;
- canonical `luad-<version>.cdx.json` CycloneDX 1.5 SBOM;
- exact known limitations; and
- sanitized customer-transfer result identities.

Private firmware corpora may contribute aggregate hashes and result counts, but they do
not replace redistributable fixtures or independently reproducible gates.

## Packaging and publication policy

The primary 1.0 channel is a GitHub release containing:

```text
luad-1.0.0-linux-x86_64.tar.gz
luad-1.0.0-macos-aarch64.tar.gz
SHA256SUMS
evidence-index.json
luad-1.0.0.cdx.json
```

Each archive contains the `luad` executable, README, license files, and a machine-readable
version/source identity. The packaging gate fixes member order, timestamps, modes, and
the metadata allowed to vary by platform.

The accepted local packaging boundary is `scripts/package-release.sh`. From a clean
revision on a matching host, it derives the workspace version and Git revision, builds
`luad`, and writes one `luad-<version>-<platform>.tar.gz`, a JSON member ledger,
`SHA256SUMS`, and a JSON installation transcript into a new or empty directory. The
archive has exactly these lexicographically ordered members beneath its single
`luad-<version>-<platform>/` prefix:

```text
LICENSE
LICENSE-APACHE
README.md
VERSION.json
luad
```

Regular files use mode `0644`; `luad` uses `0755`; uid, gid, and mtime are zero. The
verifier checks canonical deterministic ustar/gzip bytes, checksum, ledger, safe paths,
exact source inputs, and version/revision/platform/target identity before extracting and
running `luad --version` plus machine-readable capabilities. The smoke refuses any
supported dialect in this non-promoting package.

This local command proves archive construction for identical inputs on the current
host. The required `Release Archives` job repeats it in two independent Rust 1.97.1
jobs for each of `linux-x86_64` and `macos-aarch64`, confirms the exact Rust host triple,
and requires byte equality for each platform's archive, ledger, one-entry checksum, and
installation transcript. A Linux aggregation job verifies one accepted archive per
platform, emits a canonical two-entry `SHA256SUMS`, and proves with a corrupted copy
that both byte comparison and checksum verification fail closed.

The resulting `release-archives` Actions upload expires after seven days. The workflow
routes Linux x86-64 work through the `luad-linux` self-hosted label and macOS arm64 work
through `luad-macos`; every matrix job verifies the declared OS and architecture, and
archive jobs also verify the exact Rust host triple. The upload is diagnostic transport,
not a GitHub Release, durable evidence, target promotion, or a claim of reproducibility
across different runner installations, operating systems, Rust versions, target triples,
or arbitrary build environments.

The accepted SBOM boundary is `scripts/generate-release-sbom.sh`. From a clean revision,
with the exact cargo-cyclonedx 0.5.9 executable, it writes one
`luad-<version>.cdx.json` document into a new or empty directory. The document is
CycloneDX 1.5 JSON with a fixed epoch timestamp, no random serial number or host paths,
and namespaced source-revision and `Cargo.lock` SHA-256 properties. It describes the
`luad` executable's default-feature normal and build dependency graph across all Cargo
target conditions; build-only components have excluded scope and dev-only dependencies
are absent.

The verifier compares the exact component set, scopes, dependency edges, declared
licenses, registry package URLs, and registry checksums with independent locked Cargo
metadata. The required `Release SBOM` job verifies the official Linux generator asset
SHA-256 and requires byte-identical documents from two clean checkout paths. Its
seven-day Actions upload is diagnostic transport, not durable release evidence. The
source inventory does not prove which conditional components were linked into either
platform binary, replace the dependency audit, publish an asset, or promote a target.

The accepted release-bundle boundary is `scripts/assemble-release-bundle.sh`. It consumes
the exact seven-file hosted archive result, the canonical SBOM, and a bounded document
referencing the successful dependency-audit, Linux archive-oracle, SBOM, and hosted
archive results from the same clean revision. It writes exactly:

```text
SHA256SUMS
evidence-index.json
luad-<version>-linux-x86_64.tar.gz
luad-<version>-macos-aarch64.tar.gz
luad-<version>.cdx.json
```

The four-entry checksum file covers every other bundle file. The canonical evidence
index binds the clean revision and version, exact platforms and target triples, archive
hashes, member ledgers, installation transcripts, SBOM identity, and four prerequisite
references. It has an empty promoted-target set and no target-release-manifest field.
The composition verifier checks only these cross-artifact identities and bytes; it
references rather than duplicates the accepted archive and SBOM semantic gates.

The required `Release Bundle` job obtains prerequisite conclusions from its actual
workflow dependencies, assembles twice, requires byte equality for all five files,
verifies both results, and proves a changed archive byte fails verification. Its
seven-day upload is diagnostic transport. The assembler does not query GitHub, so a
locally authored prerequisite document or copied index does not authenticate a hosted
result.

### Non-production publication rehearsal

The manually dispatched `Release Publication` workflow consumes one already successful
`main` `CI` run at the same full source revision. It reuses that run's exact
`release-bundle` bytes; it never rebuilds an archive, SBOM, checksum file, or evidence
index. A maintainer dispatches it from `main` with:

```console
gh workflow run release-publication.yml --ref main \
  -f revision=<full-main-revision> \
  -f ci_run_id=<successful-main-ci-run-id>
```

The script authenticates the repository, clean checkout, remote `main`, CI run, all 13
required jobs, and the one unexpired bundle artifact before making a release change. It
then exercises a corrupted draft cleanup probe and a valid published withdrawal probe.
Both probe releases and tags must be absent at completion.

The retained result is a prerelease named and tagged
`publication-rehearsal-<version>-<12-revision-hex>`. It is explicitly not a product
release, does not become the latest release, names no supported target, and is not
signed. Its five custom assets are the two platform archives, `SHA256SUMS`,
`evidence-index.json`, and the CycloneDX SBOM; GitHub's ordinary tag archives provide
source. The workflow freshly downloads and byte-compares every custom asset, reruns the
bundle verifier, checks both source archive forms, and verifies the tag target and short
release notes. The retained prerelease is durable mechanics evidence beyond Actions
artifact expiry, not target qualification or a 1.0 candidate.

Re-running the exact identity only reverifies it; no asset is overwritten and no tag is
moved. From a clean canonical `main` checkout with authenticated `gh`, withdraw that
exact rehearsal with the command recorded in its notes:

```console
scripts/release-publication.sh withdraw \
  publication-rehearsal-<version>-<12-revision-hex> \
  <full-main-revision>
```

Withdrawal deletes the release and tag and requires the release lookup, tag lookup, and
both tag source-archive endpoints to return absent. Failure to prove cleanup is a hard
failure requiring maintainer attention. Never reuse the deleted tag name or use this
command for a `v*` tag.

Crates.io is not a version-1.0 distribution channel. Every workspace package is marked
`publish = false`, and neither `cargo install luad` nor another registry package name is
advertised. A checked-out source tree may use
`cargo install --path crates/luad-cli --locked`; that is a source-build convenience, not
publication evidence. A post-1.0 registry channel requires its own package-name,
publication-order, dependency-version, and install contract. Homebrew, LuaRocks wrappers,
additional operating systems, and installer scripts are not 1.0 requirements.

The stable workspace MSRV is Rust 1.85. Every stable workspace package declares that
minimum, and routine CI builds the locked workspace and source-installed CLI with Rust
1.85.0 on Linux x86-64 and macOS arm64. `rust-toolchain.toml` separately pins Rust
1.97.1 for contributors and release builders; the fuzz workspace retains its pinned
nightly and has no stable `rust-version` claim. Passing the MSRV job does not qualify
release-platform archives or reproducible compilation.

The required `Dependency Audit` job runs `cargo-deny` 0.20.2 against the locked
Linux x86-64 and macOS arm64 graph, including dev dependencies. The policy admits only
the SPDX expressions enumerated in `deny.toml`, has no license exceptions or advisory
ignores, denies yanked packages, and fails for an unmaintained direct workspace
dependency. The final candidate must retain a passing audit result. This automated
metadata and RustSec check is not a legal opinion, manual source-license review, SBOM,
binary-composition proof, or complete supply-chain review.

The release publishes SHA-256 checksums. Detached signing is optional for 1.0 because
the project has not selected a durable signing identity; do not create an ephemeral key
solely to check a box. If a stable signing identity is selected later, amend this policy
under its own release-infrastructure contract.

Release archives, Cargo metadata, repository license files, and SBOM declarations must
agree with the dual-license decision in the frozen boundary.

## Versioning and compatibility

The tool uses semantic versioning independently of the Lua versions it reads. `luad
1.0.0` therefore names the tool contract, while each input target retains its exact Lua
release/profile/layout identity.

Before 1.0, an incompatible machine-output change requires a schema-major increment and
changelog entry. The frozen 1.x boundary already fixes enveloped command JSON and the
other major-1 JSON families at major 1, capabilities JSON and streaming JSONL/export at
major 2, and process exit meanings at codes 0 through 6. The release notes must
additionally define:

- stable command names;
- additive-field and open-vocabulary handling;
- closed tagged-union and enum handling;
- target/profile/layout naming and support duration; and
- compatibility guarantees for prototype-content identity schemes.

Text output remains human-oriented unless a specific text form is explicitly included
in the compatibility statement.

## Tagging, publication, and rollback

For the accepted candidate:

1. verify that the candidate commit is remote `main` and clean;
2. create the annotated `v1.0.0` tag at that exact commit;
3. publish release notes, packages, checksums, SBOM, and evidence index without rebuilding
   from a different revision;
4. download and verify every public artifact; and
5. update the public release pointer only after verification succeeds.

If upload or verification fails, mark the release unusable, remove or clearly label
partial downloadable artifacts, and leave capability evidence bound to the last
accepted state. Correct the bounded defect, choose a new candidate ID, and rerun the
evidence invalidated by the change. Never move an already published version tag to a
different commit; issue a new version when published bytes must change.
