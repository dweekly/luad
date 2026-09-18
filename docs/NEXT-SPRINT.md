# Active sprint: Stage 8 / Package R (Publication Tooling & Attestations)

Status: active delivery contract.
Roadmap position: Stage 8, [ROADMAP.md](../ROADMAP.md#8-publish-verifiable-02-artifacts-automatically).

## 1. Outcome

Publish verifiable 0.2 release artifacts automatically, binding both platform archives,
checksums, source inventory, and build-provenance attestations to the same accepted
revision, with automatic CycloneDX SBOM attachment and verified fresh downloads.

## 2. Public claim

1. The publication script provides a production publication mode:
   `scripts/release-publication.sh publish <40-digit-revision> <ci-run-id>`.
2. It verifies that the CI run passed all 13 required jobs and generated the accepted
   unexpired `release-bundle` artifact.
3. It creates release `v${version}` (`--draft=false --prerelease=false --latest=false`)
   with all 5 required assets (`SHA256SUMS`, `evidence-index.json`, `linux-x86_64.tar.gz`,
   `macos-aarch64.tar.gz`, and `luad-${version}.cdx.json`).
4. It freshly downloads and verifies all 5 assets byte-for-byte against the accepted bundle,
   verifies `SHA256SUMS`, verifies source archive structure, and verifies build provenance
   for both platform archives via `gh attestation verify <archive> --repo dweekly/luad`,
   asserting exit code 0, matching subject digest, source revision, and `.github/workflows/ci.yml`.
5. It advances the latest release pointer to `v${version}` only after all verifications
   pass. Rerunning against an already published release at the same revision is idempotent;
   a tag conflict pointing to a different revision fails immediately and never moves the tag.

## 3. Scope

- `.github/workflows/ci.yml`: permissions and `actions/attest-build-provenance` + `actions/attest-sbom` steps in `release-bundle`.
- `.github/workflows/release-publication.yml`: `mode` dispatch parameter and `attestations: read` permission.
- `scripts/release-publication.sh`: `publish` subcommand, attestation verification, and latest pointer promotion.
- `crates/luad-oracle/tests/test_release_publication.rs`: offline mock testing for publication, attestations, and negative controls.

## 4. Non-goals

- No production publication during tooling acceptance.
- No new package manager, platform, or signing service.
- No 1.0 candidate evidence index or target promotion.
- No redesign of CI jobs beyond adding attestation steps.

## 5. Evidence

- Offline regressions in `crates/luad-oracle/tests/test_release_publication.rs` covering:
  - Full publication flow and idempotent rerun.
  - Verification of GitHub artifact attestations.
  - Negative controls: missing assets, stale git revision, failed prerequisites, altered bytes,
    attestation verification failure, attestation revision mismatch, attestation workflow mismatch,
    and tag-moved conflict.
- Focused acceptance:
  `cargo test -p luad-oracle --test test_release_package --test test_release_sbom --test test_release_bundle --test test_release_publication`
- Full repository check:
  `bash scripts/check.sh`

## 6. Stop condition

All offline publication tests pass with zero skips; `scripts/check.sh` passes cleanly;
no uncontracted CI jobs or external dependencies introduced.
