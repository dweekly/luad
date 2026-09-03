# Bring-up

Three kinds of machine touch this repository: a **developer machine** that builds and
tests it, a **self-hosted GitHub Actions runner** that executes CI for it, and a
**release builder** that produces and rehearses release artifacts. Each has its own
section below, and each section ends with a single command whose success is the
definition of done. Sections 2 and 3 both assume section 1 is already complete on that
host.

If you have never seen this repository, start at section 1 and stop when
`bash scripts/check.sh` exits 0. Nothing else here is required to contribute.

## Where the pins live

Every tool version this document names is read from one file that owns it. Nothing is
restated in a second place, so a pin cannot drift from what CI installs.

| Pin | Owner |
|---|---|
| Contributor and release toolchain, Rust 1.97.1 | [`rust-toolchain.toml`](../rust-toolchain.toml) |
| Minimum supported Rust, 1.85 (rustup names the patch: 1.85.0) | [`Cargo.toml`](../Cargo.toml), `rust-version` |
| Fuzz nightly `nightly-2026-08-25` and cargo-fuzz 0.13.2 | [`scripts/fuzz_smoke.sh`](../scripts/fuzz_smoke.sh), `readonly pinned_*` |
| cargo-deny 0.20.2, cargo-cyclonedx 0.5.9, compiler directories | [`scripts/pins.env`](../scripts/pins.env) |
| Official Lua releases 5.1.5, 5.2.4, 5.3.6, 5.4.8, 5.5.1 | [`scripts/install_ci_compilers.sh`](../scripts/install_ci_compilers.sh), `build_lua` arguments |

`scripts/bringup.sh` reads all five files rather than carrying its own copies.
`crates/luad-oracle/tests/test_bringup_pins.rs` asserts that they agree with
`.github/workflows/ci.yml`, with the compiler-search constant in `luad-oracle`, and with
this document — including a check that every three-part version number written here is
one of the pins above.

## 1. Developer machine

Supported hosts are macOS on Apple silicon (arm64) and Linux on x86-64. You need a C
toolchain and `make` (Xcode command line tools, or `build-essential`), plus `curl`,
`tar`, `patch`, `cmp`, and `od`, which every supported host already provides.

You also need GNU `timeout`, which the fuzz smoke runner invokes with `--signal` and
`--kill-after`. Linux has it in `coreutils`; macOS does not ship it, so install
Homebrew's `coreutils`, which provides `gtimeout`.

### Install Rust through rustup, and put its shim first

The repository pins its compiler in `rust-toolchain.toml`. That pin is honored by the
**rustup shim** at `~/.cargo/bin/cargo`, and only by that shim.

A `cargo` installed by a package manager — Homebrew's `rust` formula is the common case —
is a fixed compiler version, not a shim. If it appears earlier in `PATH`, it silently
ignores `rust-toolchain.toml` and builds the workspace with its own version. Nothing
warns you; the build simply is not the pinned one. Put the shim first:

```console
export PATH="$HOME/.cargo/bin:$PATH"
```

Add that line to your shell profile. `scripts/bringup.sh --doctor` reports this case
explicitly, naming the binary that is shadowing the shim.

If rustup is not installed yet:

```console
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
export PATH="$HOME/.cargo/bin:$PATH"
```

### Install everything else

```console
git clone https://github.com/dweekly/luad.git
cd luad
bash scripts/bringup.sh --install
```

`--install` is idempotent: it inspects the machine first and installs only what is
missing or at the wrong version, then re-runs the report. It never uses `sudo` and never
installs Python packages; anything that would need root is printed for you to run
yourself. It performs the following.

- The pinned contributor toolchain from `rust-toolchain.toml`, with its `clippy` and
  `rustfmt` components. `scripts/check.sh` runs both, and a toolchain installed with
  `--profile minimal` has neither. `rust-toolchain.toml` also declares them, so a
  networked machine repairs this by itself on the next `cargo` command in the
  repository; the doctor reports the stored state, which is what an offline or
  network-restricted host actually has.
- The MSRV toolchain from `Cargo.toml`. CI builds the locked workspace and the
  source-installed CLI with it on both platforms.
- The fuzz nightly from `scripts/fuzz_smoke.sh`, with `llvm-tools-preview`, and
  `cargo-fuzz` at the version that runner requires. The runner refuses to start on any
  other toolchain or `cargo-fuzz` version, so these two move together.
- GNU `timeout`, on macOS through `brew install coreutils` when Homebrew is present.
  Every other package manager needs root, which this script never takes; there it
  prints the command for you to run.
- `cargo-deny` at the pinned version, for the dependency-policy check.
- `cargo-cyclonedx` at the pinned version, for the release SBOM. CI downloads the pinned
  Linux release asset and checks its SHA-256; a developer machine installs the same
  version from source with `cargo install --version <pin> --locked`, which works on both
  supported hosts.
- The five official Lua compilers, by running
  [`scripts/install_ci_compilers.sh`](../scripts/install_ci_compilers.sh). That script
  downloads each release, verifies its SHA-256, builds `luac`, and confirms the version
  banner of what it installed. They land in `$HOME/.cache/luad/lua-tools/bin`, which is
  under your home directory rather than `/tmp` because macOS clears `/tmp` on reboot; the
  oracle still searches `/tmp/lua-tools/bin` afterwards, so an older installation keeps
  working.
- The OpenWrt Lua 5.1 LNUM32 authority compiler, described next.

### The OpenWrt LNUM32 authority compiler

[`scripts/build_lua51_openwrt_lnum32.sh`](../scripts/build_lua51_openwrt_lnum32.sh) takes
one output root and builds a patched Lua 5.1.5 host compiler in it. It requires `curl`,
`tar`, `patch`, `make`, `cmp`, and `od`, a little-endian host, and an output root
**beneath `/tmp` or `/private/tmp`** — the script rejects any other location. It fetches
the OpenWrt patch series and the Lua release against recorded SHA-256 values, applies the
patches, builds `src/luac-host`, checks its banner reads `Lua 5.1.5 (double int32)`,
regenerates the LNUM32 fixtures, and verifies their headers and hashes.

The binary it leaves behind is at
`<output root>/lua-5.1.5/src/luac-host`. Nothing searches for it by path: the Linux
authority gate
[`scripts/gates/gate-authority-lua51-openwrt-lnum32.sh`](../scripts/gates/gate-authority-lua51-openwrt-lnum32.sh)
rebuilds it on every run and passes `--compiler-path` explicitly. Bring-up builds it at
the same root the gate uses so the doctor can report whether a usable build is present:

```console
bash scripts/build_lua51_openwrt_lnum32.sh /tmp/gate-authority-lua51-openwrt-lnum32/authority
```

Because that root is under `/tmp`, this build does not survive a macOS reboot. Rebuild it
with the command above, or let the gate rebuild it.

### Check the machine at any time

```console
bash scripts/bringup.sh --doctor
```

The report is a table of tool, expected version, found version, and `OK`, `MISSING`, or
`WRONG`, followed by one exact fix command per failing row. It compares versions rather
than presence, so an installed-but-wrong tool is reported as `WRONG` rather than passing;
where a version is not the right question it exercises the thing instead, running GNU
`timeout` with the flags the fuzz runner uses and reading each `luac` banner. It exits
non-zero if any row is not `OK`.

Compilers are resolved in the order the oracle uses, and a candidate is accepted only if
its banner names the pinned release, so a wrong-version binary in an earlier directory
does not hide a correct one later in the order.

`--scope ci-test` narrows the report to the toolchain, its components, and the five
official compilers,
which is what a CI `Test` job provides; the CI workflow runs the doctor in that scope
immediately after installing the compilers, so the doctor and CI cannot disagree about
them.

### Done

```console
bash scripts/check.sh
```

Exit code 0 means the developer machine is ready. That aggregate check is necessary
repository evidence, not instruction-level proof; see [CONTRIBUTING.md](../CONTRIBUTING.md)
for the test taxonomy and the named gates.

## 2. Self-hosted GitHub Actions runner

A self-hosted runner is a machine you own that executes this repository's workflow jobs.
Complete section 1 on that host first: the workflow installs the Lua compilers itself but
assumes a working C toolchain, `curl`, `tar`, and `make`, and the doctor step will fail
the job otherwise.

### Security boundary

A self-hosted runner registered to this repository is a persistent, trusted host: a
workflow job can read anything on it and leave anything behind for the next job. Do not
enable such a runner for workflows triggered by pull requests from public forks. Fork
workflow code is untrusted, and on a persistent runner it executes with the privileges of
every job that runs there afterwards. Repository pull request #68 records the condition:
isolated, single-use runners must be in place before fork-triggered workflows may run on
self-hosted infrastructure. Until then, keep self-hosted execution to branches in this
repository.

### Register the machine

Labels select which machine a job lands on. Use `luad-linux` for a Linux X64 host and
`luad-macos` for a macOS ARM64 host.

Get a registration token, which is short-lived:

```console
gh api -X POST repos/dweekly/luad/actions/runners/registration-token --jq .token
```

Download the runner archive offered by the repository's
Settings → Actions → Runners → New self-hosted runner page. That page names the current
runner release and its checksum for your platform; use those rather than a version copied
from here, which would go stale. Then, in the directory you unpacked it into:

```console
./config.sh \
  --url https://github.com/dweekly/luad \
  --token <registration-token> \
  --labels luad-linux \
  --unattended
```

Substitute `luad-macos` on an Apple silicon host.

### Install it as a service

On macOS the service runs as your user and needs no elevation:

```console
./svc.sh install
./svc.sh start
./svc.sh status
```

On Linux, installing the service writes a systemd unit and requires root. Run these in a
terminal on that host:

```console
sudo ./svc.sh install "$USER"
sudo ./svc.sh start
sudo ./svc.sh status
```

Confirm the runner appears online and carries the intended label:

```console
gh api repos/dweekly/luad/actions/runners --jq '.runners[] | {name, status, labels: [.labels[].name]}'
```

### Done

Push a branch, then confirm that a CI run on that host finished with every required job
successful:

```console
gh run list --branch <branch> --limit 1
gh run view <run-id> --json jobs --jq '.jobs[] | {name, conclusion}'
```

The runner is ready when every job in that listing reports `"conclusion": "success"`. A
skipped or missing job is not a pass. To confirm the work actually landed on your host
rather than a GitHub-hosted one, read the job's own log header, or check that the runner
has recent activity in Settings → Actions → Runners.

## 3. Release builder

A release builder produces release artifacts and rehearses publication. Complete section 1
on that host first; the SBOM step needs `cargo-cyclonedx` at the pin, and the archive step
must run on one of the two packaged platforms (Linux x86-64 or macOS arm64).

Run the three dry runs in order, each from a clean revision. Their exact commands, output
directories, and the regression test that accompanies each one are in
[CONTRIBUTING.md](../CONTRIBUTING.md#development-setup); the artifact contents, member
order, permissions, and verification rules they must satisfy are in
[docs/RELEASING.md](RELEASING.md#packaging-and-publication-policy). Do not paraphrase
either; run what those documents specify.

1. **Archive** — `scripts/package-release.sh` builds the host binary and writes the
   deterministic archive, member ledger, `SHA256SUMS`, and installation transcript.
2. **SBOM** — `scripts/generate-release-sbom.sh` emits the canonical CycloneDX source
   inventory and compares it against locked Cargo metadata.
3. **Bundle** — `scripts/assemble-release-bundle.sh` composes the accepted archives, the
   SBOM, and same-revision prerequisite results into the five-file release set.

Then run the hosted rehearsal. It is maintainer-only, consumes one already successful
`main` CI run at the same full revision, and never rebuilds an artifact. Dispatch it and
withdraw its result exactly as
[docs/RELEASING.md](RELEASING.md#non-production-publication-rehearsal) documents; that
section holds the authoritative dispatch and withdrawal commands, the required-job
preconditions, and the rule that a withdrawal must prove cleanup.

### Done

A retained prerelease named and tagged `publication-rehearsal-<version>-<12-revision-hex>`
exists, and its five custom assets, source archives, tag target, and release metadata
verify under the checks that
[docs/RELEASING.md](RELEASING.md#non-production-publication-rehearsal) requires. That
prerelease is durable mechanics evidence; it is not a product release, not latest, not
signed, and names no supported target.
