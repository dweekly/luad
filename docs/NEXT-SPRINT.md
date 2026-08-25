# Active sprint: reproducible Lua 5.1 LNUM32 release candidate

Lane: qualification. Target: produce one installable, non-promoted release candidate
whose target identity, prerequisite evidence, schemas, binaries, and first-use workflow
can be independently verified.

## Claim and researcher value

An external researcher needs a fixed artifact—not a moving checkout—to attempt an
uncoached firmware investigation. The candidate must prove exactly which source,
platform, Lua profile, layout, schema majors, and gates it represents, while making no
support or publication claim before independent customer transfer succeeds.

## Candidate contract

### Exact target and provenance

The source-controlled candidate specification names the exact target
`lua5.1-lnum32`: OpenWrt-derived Lua 5.1.5, little-endian, 32-bit `size_t`, 32-bit
integer LNUM constants, and the pinned vendor patch/toolchain authority. It fixes the
schema majors, fixture hashes, compiler identities, required gate specifications, and
required platforms without attempting to predict output hashes from the commit that
defines the build.

Each platform job generates a typed attestation containing the clean source commit,
candidate-specification hash, platform and target triple, Rust toolchain and build-host
identity, binary SHA-256, archive SHA-256 and member ledger, prerequisite results, and
aggregate-check result. A post-build job verifies both attestations and generates the
candidate evidence index. The generated attestations and index are CI artifacts linked
to the source commit; they are not committed back into that revision. Substituting a
stock profile, another layout or source revision, a dirty tree, an unauthenticated
prerequisite, or one platform artifact for the other invalidates the candidate.

### Installable artifacts

CI builds release-mode archives for macOS arm64 and Linux x86_64. The evidence index
contains one typed artifact entry per platform; every entry names its platform, target
triple, toolchain, archive, binary, archive members, and checksums. Each archive contains
the `luad` binary, license files, version metadata, and a copy of the candidate
specification. The platform attestation is an external sidecar that hashes the complete
archive, avoiding self-referential archive metadata.

A packaging smoke verifier extracts each archive and checks its member ledger,
checksums, `--version`, capability identity, and schema discovery without a checkout.
Semantic qualification points the extracted binary at the maintained public acceptance
suite and existing redistributable fixtures. Existing gates remain the semantic
authorities; the archive harness only proves that they exercised the packaged binary.

### Customer handoff

A concise real-firmware quickstart starts from a firmware tree the researcher is
authorized to inspect, inventories compiled Lua, verifies interpretation identity,
searches constants, enumerates callees and unresolved reasons, inspects argument
origins, traverses closure captures, and records deterministic output. It does not claim
that firmware acquisition or unpacking is executed in CI. Every analysis command uses
only the archived binary plus standard shell/JSON tools and states the expected
exit/output contract.

A separate checked transcript runs the same analysis layer against named
redistributable fixtures with the extracted archive. CI verifies the command and
machine-output contract, while independent real-firmware transfer remains the next
roadmap checkpoint.

The candidate and its capability manifest remain experimental. This sprint creates no
tag, GitHub Release, package publication, supported-tier entry, or claim that customer
transfer has succeeded.

## Acceptance design

One candidate gate verifies the source-controlled specification, typed per-platform
attestations, generated evidence index, and complete prerequisite closure from one clean
commit. Platform jobs run packaging smoke and the canonical semantic gates against the
extracted binary; a post-build job verifies the complete two-platform set. Negative
controls reject mutations to the source commit, specification hash, target
profile/layout, compiler or fixture hash, schema major, artifact identity, prerequisite
result, platform set, dirty-state flag, archive checksum, or member ledger. Missing,
ignored, stale, cross-profile, and cross-platform substitutions fail.

The checked transcript is executed against named redistributable fixtures with the
extracted archive, not `cargo run` or a workspace binary. Its asserted outputs cover
every documented analysis workflow and preserve profile/input identity. Release
assembly is deterministic in file selection and metadata ordering; platform-specific
binary bytes are authenticated, not claimed equal across operating systems.

The acceptance outline must reuse the existing gate runner and semantic gates. It may
add one release-candidate manifest/schema and one gate; it must not duplicate semantic
oracles or re-run one prerequisite as many micro-gates.

## Allowed production paths

- release-candidate manifest/schema and prerequisite closure;
- CI release-mode archive assembly for the two target platforms;
- archive smoke verification, checksums, and evidence-bundle assembly;
- capabilities/evidence rendering required to describe the experimental candidate;
- real-firmware quickstart, checked fixture transcript, and candidate procedure;
- one qualification gate and its adversarial manifest mutations.

## Non-goals

This sprint does not add decompilation, sink classification, taint analysis, receiver
identity, runtime reachability, framework routing, persistent research state, firmware
unpacking, dynamic interpreter execution, arbitrary dataflow predicates, or a new Lua
dialect. It does not run the customer investigations, promote a support tier, tag a
version, publish a GitHub Release, sign artifacts, or publish crates/packages.

## Verification and stop condition

Acceptance requires the release-candidate gate from one clean commit, per-platform
attestations and extracted-binary verification on macOS arm64 and Linux x86_64, a
post-build evidence index, complete prerequisite closure with zero skips, aggregate
repository checks, one bounded model-diverse adversarial review, green pull-request CI,
and a clean merged revision equal to `origin/main`.

The sprint stops when any artifact cannot be rebuilt and verified by CI, any required
identity or prerequisite is absent or substitutable, the checked transcript depends on
the workspace, a semantic assertion is duplicated outside its canonical gate, or any
public surface claims `lua5.1-lnum32` is supported. Customer transfer begins only with
the accepted candidate bundle.
