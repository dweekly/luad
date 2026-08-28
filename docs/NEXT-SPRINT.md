# Sprint contract: rehearse GitHub Release publication and withdrawal

Lane: release qualification infrastructure. Roadmap position: Milestone 1, after the
accepted dependency audit, platform archives, SBOM, and five-file release-bundle
composition boundaries and before the public automation-contract freeze.

Fresh as of: 2026-08-27.

## Public outcome

A maintainer can manually rehearse the repository's ordinary GitHub Release mechanics
from one already accepted `main` release bundle. The rehearsal publishes the exact five
bundle files without rebuilding, verifies fresh downloads and GitHub's source archive,
retains one plainly labeled non-production prerelease beyond Actions artifact expiry,
and proves that failed or withdrawn probe releases leave no release or tag behind.

The retained release is named and tagged
`publication-rehearsal-<version>-<12-revision-hex>`, is marked prerelease, is not the
latest release, and says prominently that it is not a product release and promotes no
Lua target. Its custom assets are exactly:

```text
SHA256SUMS
evidence-index.json
luad-<version>-linux-x86_64.tar.gz
luad-<version>-macos-aarch64.tar.gz
luad-<version>.cdx.json
```

GitHub's normal tag source archives supply source; the workflow does not build or attach
a second source package. This rehearsal is durable publication evidence for the release
mechanics only. It is not a 1.0 candidate, target manifest, support claim, or latest
public release.

## Allowed paths

Implementation may change only:

- `.github/workflows/release-publication.yml` for the manually dispatched,
  least-privilege hosted rehearsal;
- `scripts/release-publication.sh` for fail-closed preflight, publication, fresh
  verification, failure cleanup, and withdrawal;
- `crates/luad-oracle/tests/test_release_publication.rs` for the offline public-script
  regression and command/state negative controls; and
- `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`,
  `docs/RELEASING.md`, and this checkpoint for exact operation, retention, limitations,
  documentation index, and accepted history.

No Cargo manifest, lockfile, dependency, product runtime, schema, capability, package
builder, archive/SBOM/bundle generator, target manifest, candidate workflow, fixture,
or support-status path may change.

## Authenticated input boundary

The workflow is `workflow_dispatch` only and runs from `main` with `actions: read` and
`contents: write`; it receives one full source revision and one Actions run ID. Before
any tag or release mutation, the maintained script requires:

- the checkout ref is `refs/heads/main`, its clean `HEAD` is the supplied full
  lowercase revision, and the revision is remote `main` at dispatch time;
- the named run is a completed successful `push` run of `CI` on `main` at that exact
  revision;
- the run has one successful result for each current required job, including
  `Dependency Audit`, `Release SBOM`, `Release Archives`, `Release Bundle`, both
  contributor tests, both MSRV jobs, all four archive replicas, and fuzz smoke;
- the run exposes exactly one unexpired `release-bundle` artifact, downloaded into a
  fresh directory; and
- the accepted verifier approves its exact five-file set, checksums, source revision,
  four prerequisites, two platforms, SBOM identity, and empty promoted-target set.

Missing, extra, expired, failed, skipped, cancelled, substituted, cross-revision,
pull-request, non-main, dirty, or ambiguous inputs fail before `contents: write` is used.
The script accepts only `dweekly/luad` HTTPS result and repository identities. Caller
text, filenames, tag components, API documents, asset counts, and downloads are bounded;
temporary directories are fresh and no downloaded executable or Lua input is run.

## Publication and verification contract

For the accepted input, the workflow:

1. refuses any pre-existing rehearsal, failure-probe, or withdrawal-probe tag or
   release for the source identity;
2. creates a clearly labeled non-production prerelease at the exact source revision,
   uploads the five accepted bytes, and leaves the latest-release pointer unchanged;
3. downloads all five assets into a distinct fresh directory, requires byte equality
   with the accepted input, and runs the accepted bundle verifier there;
4. resolves the new tag through GitHub's API to the exact source revision and downloads
   both normal GitHub source archive forms into fresh files, proving each is non-empty
   and rooted at the tagged repository revision; and
5. verifies the public release metadata, custom asset name set, prerelease/latest
   state, notes warning, source revision, and immutable run link before declaring the
   retained rehearsal successful.

Release notes remain short and familiar: non-production warning, version and revision,
accepted CI run, four `SHA256SUMS` lines, supported-target set `none`, signing status
`not signed`, and the withdrawal command. They do not expose internal gate prose as a
user-facing release manual.

The retained rehearsal release and tag are not automatically deleted. They remain the
Milestone-1 durable result until a later accepted publication explicitly supersedes or
withdraws them. Re-running the same identity is idempotent only after every retained
remote byte and metadata field is reverified; it must never overwrite an asset or move
a tag.

## Failure and withdrawal controls

Two namespaced probes exercise destructive behavior without touching the retained
rehearsal or any `v*` tag:

- A draft `publication-failure-probe-<version>-<12-revision-hex>` receives a copy with
  one changed archive byte. Fresh verification must reject it before publication. The
  script deletes the draft and any probe tag, then proves both are absent.
- A `publication-withdrawal-probe-<version>-<12-revision-hex>` prerelease receives the
  valid five assets, passes the same fresh-download and tag checks, and is then deleted
  with its tag. The script proves the release lookup, tag ref, custom assets, and source
  archive endpoints are no longer available.

Any failure after a remote mutation invokes the same bounded cleanup for the affected
probe. Failure to prove cleanup fails the workflow and requires maintainer intervention;
it cannot be reported as successful withdrawal. The retained rehearsal is never used as
the corruption probe and is deleted only by an explicit `withdraw` invocation naming
its exact tag and source revision.

## Acceptance evidence

The focused offline regression is:

```console
cargo test -p luad-oracle --test test_release_publication
```

With a stateful fake `gh` placed first on `PATH`, it must exercise the maintained script
and assert the exact preflight queries, release names, target revision, prerelease and
not-latest flags, five upload/download names, notes fields, source checks, and cleanup
calls. Negative controls cover wrong run/revision/ref/repository, non-success or skipped
jobs, missing/extra/expired artifacts, pre-existing identities, changed downloads,
publication that accidentally becomes latest, failed cleanup, tag movement, unsafe
names, and any non-empty promoted-target claim. The fake must itself be perturbed to
prove the assertions catch a missing verification or cleanup command.

After the implementation merges, the steward dispatches the hosted workflow once for
that exact `main` revision and its successful `CI` release-bundle run. Acceptance
requires:

- the workflow and every owned corruption/cleanup assertion pass without a required
  skip;
- the retained rehearsal URL, tag target, source archive responses, notes, and exact
  five fresh-downloaded assets are independently inspected;
- the failure and withdrawal probe release/tag lookups are absent;
- all four retained checksums match the accepted input bytes; and
- the retained evidence index still has an empty promoted-target set.

The steward also runs the repository aggregate once from the clean implementation
candidate:

```console
bash scripts/check.sh
```

The close record names the implementation and hosted revisions, source CI and
publication run URLs, focused-test count, official Lua compiler versions, aggregate
result, every skip, retained release/tag URL, exact asset names and hashes, source
archive checks, probe cleanup results, and signing omission.

## Documentation closure

Acceptance documents the manual command, exact prerequisites, tag/release names, five
assets, GitHub source archives, short release-note fields, fresh verification,
retention, signing omission, explicit withdrawal, failure cleanup, and non-promotion
limits. `ROADMAP.md` removes only the accepted publication/retention/withdrawal
implementation obligation; final `v1.0.0` tagging, final candidate notes and source
identity, target promotion, durable qualification evidence, and final release execution
remain future work.

The implementation pull request returns this file and its README index entry to the
neutral no-work checkpoint.

## Non-goals

This batch does not create, edit, or delete a `v*` tag or production release; change the
workspace version; select a 1.0 candidate; update a latest/stable pointer; create a
target release manifest; promote a dialect; publish a registry package; add an
installer; select a signing identity; generate a signature or attestation; or retain
private customer/security material.

It does not change archive, SBOM, or evidence-index contents; rerun prerequisite
semantic gates; promise cross-host reproducibility; freeze the CLI/schema contract;
start robustness or exact-target qualification; or claim that one rehearsal proves the
future candidate's bytes.

## Stop condition

Stop when the offline regression, aggregate check, exact hosted `main` prerequisite
closure, retained non-production prerelease, fresh asset and source verification,
failed-release cleanup, valid-release withdrawal probe, aligned documentation, and
landed-main verification are reviewable and green.

Any ambiguous input, mutable/moved tag, unexpected asset, byte mismatch, failed or
skipped prerequisite, latest-pointer change, public corrupted probe, incomplete cleanup,
missing source archive, signing claim, or target promotion blocks closure. It does not
authorize weakening verification, overwriting an asset, deleting the retained result to
hide a defect, or advancing to Milestone 2.
