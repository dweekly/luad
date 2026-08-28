# Sprint contract: make package identity honest

Lane: product. Roadmap position: Milestone 1, package metadata and Cargo-channel
decision after the accepted local release archive boundary.

Fresh as of: 2026-08-27.

## Outcome

Maintainers and source users see one accurate package identity everywhere: what each
workspace crate does, where its source lives, how it is licensed, whether it may be
published, and which Rust-version claims have actually been established.

GitHub release archives remain the only planned 1.0 distribution channel. A user with a
checked-out source tree can install the `luad` binary locally with Cargo, but crates.io
publication and `cargo install luad` are explicitly not 1.0 promises.

## Public claim

`cargo metadata --no-deps --format-version 1` reports every main workspace package with:

- a concise role-specific description;
- the canonical `https://github.com/dweekly/luad` repository and homepage;
- the root README;
- the existing `MIT OR Apache-2.0` expression backed by both repository license texts;
  and
- `publish = false`.

The manifests do not set `rust-version` until a separate MSRV contract proves one. The
existing `rust-toolchain.toml` remains the contributor build pin, not an MSRV claim. The
separate fuzz package remains unpublished and follows the same no-unproved-MSRV rule.

From a clean checkout, this source-only installation succeeds without changing package
names or publication policy:

```console
cargo install --path crates/luad-cli --locked --root <fresh-directory>
```

The installed `bin/luad` must report the workspace version and emit machine-readable
capabilities with no supported dialects. Documentation must call this a source install,
not a registry or release channel.

## Scope

The implementation may change only:

- root `Cargo.toml`, all nine `crates/*/Cargo.toml` workspace manifests, and
  `fuzz/Cargo.toml` for descriptions, inherited repository/homepage/README/publication
  identity, and removal of the unproved `rust-version` package field;
- one new `crates/luad-oracle/tests/test_package_metadata.rs` ordinary integration test;
  and
- `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`,
  `docs/RELEASING.md`, and this checkpoint for the source-install command, Cargo-channel
  decision, MSRV honesty, accepted history, remaining obligations, and documentation
  index freshness.

No production Rust module, dependency version, package name, workspace membership,
binary name, feature, or lockfile may change.

## Evidence

The focused regression is:

```console
cargo test -p luad-oracle --test test_package_metadata
```

It must:

1. inspect live Cargo metadata and require the exact license, repository, homepage,
   README, nonempty role description, unpublished state, and absent `rust_version` for
   every package, with the CLI package alone exposing exactly one `luad` binary target;
2. check the independent fuzz manifest remains `publish = false` and does not declare a
   `rust-version`;
3. prove the MIT and Apache-2.0 files are present and match their pinned canonical text
   digests;
4. install `luad-cli` with `--locked` into a fresh temporary root, then assert exact
   version output, parse capabilities JSON, and confirm `supported_dialects` is empty;
   and
5. include table-driven negative controls showing the metadata comparator rejects a
   missing description, wrong repository or homepage, missing README or license,
   publishable package, invented Rust version, wrong binary name, or absent license
   file.

The test must not contact a registry, publish or package a crate, infer availability of
the `luad` crates.io name, or treat source installation as publication evidence.

The steward then runs the aggregate repository check once:

```console
bash scripts/check.sh
```

The handoff records the installed binary path and version, official Lua compiler
versions present, and every skip. No release artifact is produced by this batch.

## Non-goals

This batch does not:

- publish to crates.io, reserve a crate name, add registry versions to path dependencies,
  run `cargo publish` or `cargo package`, or advertise `cargo install luad`;
- establish or test an MSRV, change the contributor toolchain, edition, dependency
  graph, lockfile, package/crate names, or release version;
- build or upload release archives, generate an SBOM, audit dependencies, add CI or
  release workflows, or retain hosted evidence; or
- change CLI/schema behavior, bytecode semantics, capability status, target evidence,
  candidate identity, or release manifests.

Crates.io may be reconsidered after 1.0 under its own package-name, publication-order,
and install contract. MSRV qualification remains a separate unmet Milestone 1 outcome.

## Stop condition

Stop with one reviewable candidate diff when live metadata is honest, the source install
and mutation controls pass, documentation states that crates.io is not a 1.0 channel,
the completed metadata/Cargo decision is removed from future roadmap obligations, and
`docs/NEXT-SPRINT.md` has returned to the neutral no-work checkpoint.

Do not publish, package, tag, upload, or promote anything in this sprint.
