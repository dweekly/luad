# Release procedure

Status: release policy and operational checklist.

Fresh as of: 2026-08-27.

Revalidate or delete when: the release target matrix, qualification lifecycle, package
platforms, artifact channel, compatibility policy, signing/checksum policy, release
ownership, or rollback procedure changes.

## Current release stop

Do not make a production release. No exact target is currently promoted, the active
sprint is a no-work checkpoint, the 1.0 publication workflow is not implemented, and
the required customer, extended-fuzz, security-review, packaging, and final
qualification evidence has not closed over one clean revision.

The dependency-ordered path is [the product roadmap](../ROADMAP.md). Exact release work
begins only under a qualification contract in [the active sprint](NEXT-SPRINT.md).
Passing an ordinary test, prerequisite gate, candidate packaging workflow, private
corpus run, or model review cannot remove this stop.

## Release scope and order

Version 1.0 is limited to three independently promoted targets:

1. OpenWrt-derived Lua 5.1.5 LNUM32 with
   `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4`;
2. stock PUC Lua 5.4.9 with the standard 64-bit little-endian layout emitted by the
   pinned official compilers; and
3. stock PUC Lua 5.1.5 with the pinned little-endian, non-integral-double, 64-bit
   `size_t` layout.

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
9. Retain the complete results outside temporary storage.

Before publishing 1.0, additionally:

1. Run the configured extended fuzz campaign and publish its duration, configuration,
   corpus identity, resource envelope, and result.
2. Complete the focused hostile-input and release-supply-chain security review.
3. Record the representative runtime and peak-memory tripwires required by the roadmap.
4. Complete the internal and outside-user transfer checkpoints below.
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
- **Outside-human in-profile workflow:** pre-screen the authorized public firmware only
  far enough to establish that it resolves to the exact LNUM32 profile, then give an
  outside human the binary and public quickstart without coaching.

An additional out-of-profile refusal test proves that a different stock/vendor layout
fails with an actionable diagnostic and the documented exit code. It does not consume
the outside-human checkpoint.

Commit a sanitized customer-trial record in the durable location named by the sprint.
Do not commit private firmware, sensitive findings, model transcripts, or
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
- generated SPDX or CycloneDX SBOM;
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
luad-1.0.0.spdx.json (or an equivalent CycloneDX document)
```

Each archive contains the `luad` executable, README, license files, and a machine-readable
version/source identity. The packaging gate fixes member order, timestamps, modes, and
the metadata allowed to vary by platform.

`cargo install` is a secondary channel only after package names, publication order,
metadata, dependency versions, and install behavior pass a dry run and are documented.
Homebrew, LuaRocks wrappers, additional operating systems, and installer scripts are not
1.0 requirements.

The release publishes SHA-256 checksums. Detached signing is optional for 1.0 because
the project has not selected a durable signing identity; do not create an ephemeral key
solely to check a box. If a stable signing identity is selected later, amend this policy
under its own release-infrastructure contract.

The workspace remains dual `MIT OR Apache-2.0`. This permits use under terms compatible
with the [MIT-licensed Lua project](https://www.lua.org/license.html) without a
relicensing project. Release archives, Cargo metadata, repository license files, and
SBOM declarations must agree.

## Versioning and compatibility

The tool uses semantic versioning independently of the Lua versions it reads. `luad
1.0.0` therefore names the tool contract, while each input target retains its exact Lua
release/profile/layout identity.

Before 1.0, an incompatible machine-output change requires a schema-major increment and
changelog entry. At 1.0, the release notes must define:

- stable CLI exit-code meanings;
- stable schema majors and command names;
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
