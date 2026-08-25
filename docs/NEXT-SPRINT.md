# Active sprint: public OpenWrt Lua 5.1 LNUM32 authority

Lane: qualification. Target: one immutable upstream authority manifest, one
redistributable fixture family, and one canonical authority gate. This sprint does not
promote a capability.

## Claim and researcher value

A reproducible public compiler authority can generate the exact Lua 5.1.5
OpenWrt-derived LNUM32 bytecode profile used by the embedded target: little-endian,
32-bit serialized string lengths, 32-bit integer constants, double-precision numeric
constants, and integer constant tag 9.

This authority gives the next target-promotion sprint an independent oracle that does
not depend on private TP-Link firmware or a host-specific compiler executable hash.

## Immutable upstream boundary

The authority starts from:

- PUC-Rio Lua 5.1.5 archive
  `https://www.lua.org/ftp/lua-5.1.5.tar.gz`;
- archive SHA-256
  `2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333`;
- official OpenWrt repository revision
  `1da2e82c1182a3fd681da5760be96821213afadd` from the `openwrt-19.07`
  branch;
- package recipe and complete ordered patch series under
  `package/utils/lua/` at that revision.

The manifest will record SHA-256 hashes for the package recipe and every applied patch,
including the LNUM numeric model, integer tag, and architecture-independent bytecode
changes. It will record the exact target compiler, flags, environment, patch order,
and build command. A compiler-binary SHA-256 identifies one build artifact only; source,
patch, configuration, and output identities establish the portable authority.

The authority compiler will use the patched source tree's static `luac-host` target on
a little-endian build host. OpenWrt patch `030-archindependent-bytecode.patch` serializes
string lengths as 32-bit `unsigned int` rather than host `size_t`; the LNUM patches select
32-bit `lua_Integer` and double `lua_Number`. The authority therefore does not require a
32-bit host ABI, `-m32`, QEMU, or execution of a target binary. The builder will verify
the emitted `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4` header and tag-9
integer encoding rather than infer portability from build-host properties.

If this upstream recipe cannot generate the target header and constant encoding exactly,
the sprint stops at a failed authority result. It must not alter `luad` or relabel a
nearby profile to make the fixture fit.

## Public fixture family

Redistributable Lua sources will exercise:

- integer constants at zero, signed boundaries, and values distinct from floats;
- floating-point constants;
- short and long strings that prove 32-bit serialized lengths;
- nested prototypes and both closure-capture descriptor forms;
- representative RK, global/table, call, branch, and loop instructions;
- stripped and debug-bearing output where the compiler supports both deterministically.

Every generated chunk will record source, bytecode, upstream revision, patch-series,
configuration, compiler build, command, profile, layout, and content hashes. At least
one cross-profile negative fixture will prove that stock Lua 5.1 cannot accept the
LNUM32 interpretation.

## Independent acceptance

Acceptance will establish, through the public CLI and independent oracle:

- exact header, layout, integer-tag, constant, prototype, instruction, and debug facts;
- exact agreement between compiler listing, the independent Lua 5.1/LNUM decoder, and
  live `luad` JSON for the generated fixture family;
- automatic and explicit selection of `lua5.1-lnum32` with the complete interpretation
  identity in every response and stream;
- zero validation diagnostics for valid fixtures and exact rejection under stock
  profile substitution;
- deterministic reproduction from authenticated source inputs;
- rejection of a changed archive, OpenWrt revision, patch, patch order, configuration,
  target layout, fixture, or compiler output;
- zero skipped tests in the canonical authority gate: it provisions authenticated
  inputs or fails before comparison when its network or standard native build
  prerequisites are unavailable.

Ordinary offline workspace tests authenticate the committed manifest, sources, and
generated fixtures; they do not claim to reproduce the authority build. The canonical
gate alone performs download, patch, native compiler construction, fixture regeneration,
and byte-for-byte comparison in a disposable directory.

Existing Lua 5.1 gates are regression prerequisites, not independent evidence for the
new profile authority. If an authenticated compiler fact disagrees with an accepted
fixture-derived assumption, the authority gate fails and names the discrepancy. Tests
or implementation then require a separate corrective change; the authority must not be
weakened to preserve an earlier green gate or private-corpus result.

The supplemental customer check will run the accepted candidate over the private
firmware corpus and record only aggregate parse, validation, timing, and profile results.
Private bytes and findings remain outside the repository and cannot satisfy the gate.

## Allowed scope and roles

The acceptance author may add the authority manifest, fixture sources, generated
fixtures, an independent comparison module, acceptance tests, and the sprint gate. The
implementation agent may add a hermetic authority-builder script and the smallest
oracle integration needed to expose the generated compiler. Production parser,
disassembler, validator, analysis, query, and capability code are frozen.

The steward owns upstream pin review, fixture provenance, mutation sufficiency, the
canonical run, and the supplemental customer check. Opus supplies one bounded
read-only acceptance outline and, after approval, the independent acceptance edit.
Gemini Flash High implements only the builder and allowed oracle integration from the
frozen acceptance commit.

## Non-goals

This sprint does not:

- mark LNUM32, stock64, or base `lua5.1` as supported;
- add or change bytecode semantics;
- qualify a TP-Link-specific opcode permutation or another OpenWrt revision;
- add symbolic callee paths, value origins, call relations, prototype hashes, or schema
  fields;
- build firmware, execute target bytecode, or include private corpus artifacts;
- create a release manifest.

## Gate and stop condition

The canonical gate will be `gate-authority-lua51-openwrt-lnum32`. It will own only the
authority-builder, fixture-reproduction, three-way comparison, selection, provenance,
and substitution claims above. Existing parser, profile, public-disassembly, machine,
and proof-harness results will be referenced as prerequisites rather than reimplemented.

Acceptance requires the focused authority tests, the canonical clean-revision gate,
`bash scripts/check.sh`, green CI, a clean merged revision, and local `main` equal to
`origin/main`. The next sprint will use this authority to promote the exact embedded
target; no target promotion or downstream roadmap work begins inside this sprint.
