# Release contract: publish luad 0.2.0

The user authorizes preparation, integration, and publication of experimental 0.2.0.
Base candidate: `aa76348`. No supported target or 1.0 promise is introduced.

## Scope

Version metadata and lockfiles; README, changelog, release instructions and index;
version-sensitive release tests; publication notes and verification workflow; narrow
integration fixes required by the existing Linux/macOS release checks. Preserve the
reviewed parser and analysis scope. Close the two small documentation/test gaps during
release preparation without adding another feature or qualification program.

## Evidence and sequence

1. Set workspace version 0.2.0 and document actual fixes and remaining limitations.
2. Run focused release/version tests on the clean candidate. Submit one release PR.
3. Require successful existing CI on the PR, merge, and require the same checks and
   archive attestations on the exact resulting main revision.
4. Dispatch `release-publication.yml` in `publish` mode with that full revision and
   successful main CI run ID. Consume its accepted bundle without rebuilding.
5. Verify the v0.2.0 tag, all five downloaded assets, checksums, provenance, and native
   installation/walkthrough on both package platforms before declaring release complete.

The existing contributor aggregate runs in CI; do not duplicate it locally without a
specific failure. Record the run and release URLs, compiler versions, and any skips.

## Stop

Stop after v0.2.0 and its latest pointer refer to the verified accepted revision and
fresh downloads pass. No additional dialects, features, or capability promotions.
