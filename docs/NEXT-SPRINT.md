# Sprint contract: gate dependency licenses and advisories

Lane: release infrastructure. Roadmap position: Milestone 1, after the stable workspace
MSRV and before SBOM generation, hosted package assembly, evidence retention, or
publication.

## Public outcome

Every pull request and pushed `main` revision receives one required, reproducible
dependency-policy result for the exact locked workspace graph used by the two version-1
package targets. The gate rejects unapproved dependency licenses and current RustSec
advisories instead of discovering either class of release blocker on publication day.

Use `cargo-deny` 0.20.2 through the official
`EmbarkStudios/cargo-deny-action@v2.1.1`. The check covers
`x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`, includes dev dependencies, and
runs against `Cargo.lock` without updating it.

## Allowed paths

Implementation may change only:

- a new root `deny.toml`;
- `.github/workflows/ci.yml`;
- `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`,
  `docs/RELEASING.md`, and this checkpoint.

No production or ordinary Rust test path is authorized. The pinned external checker,
its reviewed policy, hosted execution, and explicit failure probes are the evidence for
this release-infrastructure claim.

`Cargo.toml`, every package manifest, `Cargo.lock`, `rust-toolchain.toml`,
`.github/workflows/candidate.yml`, `fuzz/Cargo.toml`, production Rust, tests,
fixtures, schemas, and dependencies are outside this batch.

## Policy boundary

The license allowlist contains only SPDX expressions present in the accepted locked
two-target graph:

- `Apache-2.0`;
- `Apache-2.0 WITH LLVM-exception`;
- `BSD-2-Clause`;
- `MIT`;
- `MIT-0`;
- `MPL-2.0`;
- `Unicode-3.0`;
- `Unlicense`; and
- `Zlib`.

Workspace packages remain included in the license check. The policy has no license
exceptions, clarifications, advisory ignores, or graph exclusions. Unused allowed
licenses fail. Unknown license expressions fail rather than becoming implicit
exceptions.

The advisory check uses the current RustSec database, denies yanked packages, and treats
an unmaintained direct workspace dependency as an error. It must not run frozen or
offline in hosted CI, because a cached or absent database cannot establish a current
vulnerability result.

## Acceptance evidence

The hosted `Dependency Audit` job must run exactly:

```text
cargo-deny 0.20.2 --locked check advisories licenses
```

through the pinned official action. A successful job must report both `advisories ok`
and `licenses ok` for the live locked graph.

Before implementation handoff, the steward runs the same pinned tool and policy from a
clean revision. The acceptance record includes the tool version, target triples,
included dependency kinds, advisory database freshness, allowlist, ignore count,
exception count, and final two-check result.

Two negative probes are required:

1. remove one encountered dev-only license such as `Zlib` or `MIT-0` from a temporary
   copy of the policy; the license check must fail and name the rejected expression and
   dependency path;
2. disable advisory fetching while pointing at a fresh empty database location; the
   advisory check must fail because current advisory evidence is unavailable.

An unexpected pass, missing tool/database, unrelated Cargo resolution failure, warning-
only result for the named corruption, or skipped check fails acceptance. The committed
policy is restored before the positive run.

The steward then runs `bash scripts/check.sh` once from the clean implementation
candidate and records the official Lua compiler versions and skip counts as usual.

## Documentation closure

Acceptance documents the required audit command and explains that it covers dependency
license metadata and RustSec advisories, not a legal opinion, manual source-license
review, SBOM, binary composition proof, or complete supply-chain review.
`CHANGELOG.md` records the new gate. `ROADMAP.md` removes only the completed
dependency-license and vulnerability-audit obligation. The implementation pull request
returns this file and its README index entry to the neutral no-work checkpoint.

## Non-goals

This batch does not update or remove a dependency, add an advisory ignore or license
exception, run cargo-deny bans or source policy, generate an SBOM, change the MSRV or
toolchain pins, build or publish archives, retain release evidence, change runtime
behavior or schemas, or promote a Lua target.

## Stop condition

Stop after the exact locked policy, required hosted audit, two failure probes, and
aligned documentation are reviewable and green. Any real rejected license, advisory,
yanked package, unmaintained direct dependency, or unavailable current advisory database
blocks closure; it does not authorize a suppression or dependency change in this batch.
