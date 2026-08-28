# Sprint contract: establish the stable workspace MSRV

Lane: release infrastructure. Roadmap position: Milestone 1, after package identity and
the local deterministic archive, before dependency audit, SBOM, hosted packaging, or
publication work.

## Public outcome

The checked-out version-1 source tree has one honest minimum supported Rust version:
Rust 1.85. Every stable workspace package declares `rust-version = "1.85"`, and CI
proves that Rust 1.85.0 can build the locked workspace and install and run the documented
`luad-cli` source path on both advertised package hosts, Linux x86-64 and macOS arm64.

This is a consumer/source-build floor, not the development or release-builder pin.
`rust-toolchain.toml`, ordinary contributor CI, and candidate packaging continue to use
Rust 1.97.1. The fuzz workspace continues to use its separately pinned nightly and does
not acquire a stable `rust-version` claim.

The selected floor is evidence-based: the current locked stable workspace builds and
the CLI installs under Rust 1.85.0, while Rust 1.84.1 cannot consume the locked CLI
dependency graph because it predates Cargo support required by an edition-2024
dependency manifest. The implementation must preserve a one-version-lower negative
control so the declared floor is enforced rather than merely documented.

## Allowed paths

Implementation may change only:

- `Cargo.toml` and the nine workspace package manifests beneath `crates/*/Cargo.toml`;
- `.github/workflows/ci.yml`;
- `crates/luad-oracle/tests/test_package_metadata.rs`;
- `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`,
  `docs/RELEASING.md`, and this checkpoint.

`Cargo.lock`, `rust-toolchain.toml`, `.github/workflows/candidate.yml`,
`fuzz/Cargo.toml`, production Rust, fixtures, schemas, dependencies, package names, and
binary names are outside this batch.

## Acceptance evidence

The ordinary metadata oracle must read live Cargo metadata and prove that all nine
stable workspace packages inherit exactly Rust 1.85. It must reject at least a missing
declaration, a lower declaration, substitution of the Rust 1.97.1 contributor pin, and
any stable `rust-version` added to the nightly fuzz package.

Run the focused regression on the contributor toolchain:

```console
cargo test -p luad-oracle --test test_package_metadata
```

The hosted `MSRV` CI job is the executable support gate. On `ubuntu-latest` and
`macos-latest` it must install exactly Rust 1.85.0, then run against the checked-in lock
file:

```console
cargo build --workspace --locked
cargo install --path crates/luad-cli --locked --root <fresh-install-root>
<fresh-install-root>/bin/luad --version
<fresh-install-root>/bin/luad capabilities --format json
```

The installed binary must report the workspace tool version, emit machine JSON without
stderr commentary, and retain an empty supported-dialect set. On one hosted Linux leg,
Rust 1.84.1 must fail the locked workspace build and the negative-control assertion must
confirm the failure identifies the Rust 1.85 requirement. A missing lower toolchain,
unexpected successful build, or unrelated failure does not satisfy the control.

The steward then runs `bash scripts/check.sh` once from the clean implementation
candidate and records the official Lua compiler versions and skip counts as usual.

## Documentation closure

Acceptance updates the build and contributor guidance to distinguish:

- Rust 1.85 as the stable workspace and checked-out-source minimum;
- Rust 1.97.1 as the contributor and release-builder pin; and
- `nightly-2026-08-25` as the fuzz-only pin.

`docs/RELEASING.md` records Rust 1.85 in the evidence and packaging policy without
claiming that the package-platform build or publication workflow is complete.
`CHANGELOG.md` records the established MSRV. `ROADMAP.md` removes only the completed
MSRV obligation. The implementation pull request returns this file and its README index
entry to the neutral no-work checkpoint.

## Non-goals

This batch does not update dependencies, adopt Cargo resolver 3, change the contributor
or release toolchain, make the fuzz crate stable-compatible, run license or vulnerability
audits, generate an SBOM, build release archives in CI, publish or retain artifacts,
change runtime behavior or schemas, or promote a Lua target.

## Stop condition

Stop after the Rust 1.85 declaration, the two-host positive CI evidence, the one-version-
lower negative control, and aligned documentation are reviewable. Do not enter any other
Milestone 1 obligation, and do not describe a passing MSRV job as release-platform,
artifact, or target qualification.
