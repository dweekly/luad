# Active sprint: exact Lua 5.1.5 stock64 release qualification

Lane: exact-target qualification. Target: one frozen acceptance commit, one
implementation commit, and one canonical release gate.

## Claim and user value

A release manifest can qualify the exact target tuple Lua 5.1.5, stock numeric
profile, little-endian 64-bit `size_t` layout for public parsing, disassembly, and
validation. The manifest is the only authority that may move this target from
experimental to supported. It must not promote 32-bit `size_t`, LNUM32, another Lua
patch release, another host architecture, or an analysis surface outside this sprint.

This target gives users one reproducible supported baseline while embedded 32-bit and
LNUM32 profiles retain independent qualification boundaries.

## Exact target

The sprint pins:

- dialect release: `Lua 5.1.5`;
- compiler archive:
  `https://www.lua.org/ftp/lua-5.1.5.tar.gz`;
- compiler archive SHA-256:
  `2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333`;
- compiler binary SHA-256:
  `eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239`;
- profile: `lua5.1`;
- layout:
  `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0`;
- public surfaces: `inspect`, `disasm`, and `validate`;
- fixture matrix: debug and stripped forms of `hello`, `control_flow`,
  `closures`, `tables`, and `numerics`.

Every binary and source hash comes from the canonical fixture provenance manifest.
The compiler is mandatory; absence or hash mismatch is a hard failure.

## Public and release contract

Acceptance invokes every claimed public surface through the live CLI under automatic
and explicit dialect selection. JSON output validates against the live schema, text
output is deterministic, and validation returns no diagnostics for the complete
fixture matrix.

The release manifest records the exact dialect release, profile, layout, compiler,
fixture hashes, source revision, dirty state, platform, architecture, prerequisite gate
results, and capability mutations. Promotion applies only when all evidence comes from
one clean revision and every prerequisite result matches its frozen GateSpec hash.

`luad capabilities --format json --evidence` may report the exact stock64 target as
supported only when presented with or built from the verified release evidence defined
by this sprint. The base string `lua5.1` must not imply support for other layouts or
vendor profiles.

## Independent acceptance

The acceptance module will prove:

- exact three-way public disassembly agreement across all ten fixtures;
- zero-diagnostic public validation across all ten fixtures;
- deterministic, schema-valid `inspect`, `disasm`, and `validate` responses;
- exact target identity in the release manifest;
- rejection of a dirty revision, stale commit, compiler substitution, fixture
  substitution, omitted prerequisite, failed prerequisite, profile substitution,
  layout substitution, Lua 5.4 evidence, and an unclaimed capability mutation;
- rejection of attempts to use the stock64 manifest for the 32-bit or LNUM32 targets;
- capability status remains experimental when the verified manifest is absent.

Comparator killer probes mutate one fact at a time and must demonstrate rejection.
No test may skip because an authority, compiler, fixture, schema, or gate artifact is
missing.

## Gate boundary

The canonical gate will be `gate-release-lua51-stock64`. Its prerequisite closure
must include the Area 1 validator-and-diagnostic gate plus the exact parser, profile
selection, public disassembly, closure, resolved-constant, machine-contract, and proof
harness gates required by the three claimed public surfaces.

The gate emits a tamper-evident proof package containing the frozen GateSpec, GateResult,
release manifest, stdout/stderr hashes, compiler identity, fixture hashes, git revision,
dirty flag, platform, architecture, and adversarial rejection report.

No capability mutation is allowed before the release manifest verifies. The release
gate alone owns the narrowly scoped stock64 promotion.

## Allowed scope

Acceptance work may add one Lua 5.1 stock64 release test module. Steward work may add
the gate spec and script, update the active sprint and documentation freshness index,
and pin the exact prerequisite graph. Implementation work may change release-manifest
assembly, capability evidence ingestion, and the smallest public metadata surface
needed for the exact target.

The sprint may not change parsing, instruction semantics, validator rules, schemas
unrelated to release evidence, other dialects, the LNUM32 profile, the 32-bit
`size_t` layout, analysis algorithms, or persistent state.

## Verification and stop condition

Acceptance requires:

```console
cargo test -p luad-oracle --test test_release_lua51_stock64
bash scripts/gates/gate-release-lua51-stock64.sh /tmp/luad-gate-release-lua51-stock64
bash scripts/check.sh
```

The accepted revision is clean, all required tests execute with zero failures and zero
ignored tests, the official compiler and all fixture hashes match, every killer
mutation is rejected, the proof package verifies, CI is green, and local `main`
matches `origin/main`. Work on another target or roadmap capability begins only
after this checkpoint is merged and preserved remotely.
