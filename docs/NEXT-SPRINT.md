# Active sprint: Lua 5.1 validator reference operands

Status: acceptance contract. No downstream roadmap work begins before this sprint is
accepted or explicitly respecified.

## Claim

For Lua 5.1 bytecode, `luad validate` applies the declared operand domain to upvalue,
child-prototype, and comparison-condition fields. It does not misclassify those fields
as registers, and it reports an exact diagnostic when an encoded reference or boolean
is outside its domain.

The public boundary is:

```console
luad validate CHUNK --dialect lua5.1 --format json
```

The same rules apply when the stock Lua 5.1 profile is selected automatically.

## Researcher value

A human or agent can trust validation results when triaging embedded Lua 5.1 chunks.
A valid high-numbered upvalue does not become a false register error, an invalid child
prototype cannot pass silently, and comparison-control bits are checked according to
their VM meaning.

## Acceptance base

- The accepted implementation baseline is revision
  `e78d51bd28fd8b438a3d4bddd9a05f13b33d0969`.
- Required gates are `gate-proof-harness`, `gate-public-disasm-lua51`, and
  `gate-validation-null-hypothesis`.
- The required official compiler is PUC-Rio Lua 5.1.5, reported as `Lua 5.1.5`, with
  compiler SHA-256
  `eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239`.
- All Lua 5.1 capabilities remain experimental; this sprint does not promote a target.

## Non-goals

- register-span rules for calls, returns, varargs, iterators, loops, or `SETLIST`;
- constant RK, jump, closure-descriptor, or stack-size rules governed by other named
  gates;
- a public diagnostic catalog or diagnostic-code migration;
- parser, disassembler, CFG, effect, or xref changes unrelated to the claimed operand
  domains;
- Lua 5.2 or later, LuaJIT, or another vendor profile;
- decompilation, security classification, or persistent research state.

## Public behavior

Validation follows these exact Lua 5.1 domains:

| Opcode field | Domain | Required result |
|---|---|---|
| `GETUPVAL B`, `SETUPVAL B` | parent prototype upvalue index | An index below the declared upvalue count is valid regardless of `maxstacksize`; an out-of-range index emits `L51-UPVAL-001`. |
| `CLOSURE Bx` | child prototype index | An index below the child-prototype count is valid; an out-of-range index emits `L51-PROTO-002`. |
| `EQ A`, `LT A`, `LE A` | boolean inversion flag | Values 0 and 1 are valid regardless of `maxstacksize`; any other encoded value emits `L51-BOOL-001`. |

For every diagnostic above:

- severity is `error`;
- category is `instruction`;
- target is the exact instruction stable ID;
- source identifies the exact four-byte instruction word;
- the message names the field, encoded value, and applicable bound or legal domain;
- permissive validation accumulates the diagnostic and returns an invalid verdict;
- strict validation returns a nonzero invalid-input result without changing the code,
  target, category, or source.

A field governed by this table must not also produce `L51-REG-001`,
`L51-REG-002`, or `L51-REG-003` merely because its numeric value is at or above
`maxstacksize`. Repeated invocations over identical bytes and options are byte-for-byte
deterministic on stdout and stderr.

## Fixture matrix

| Fixture | SHA-256 | Purpose |
|---|---|---|
| `tests/fixtures/precompiled/lua51/hello.luac` | `d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f` | Stock debug-bearing control. |
| `tests/fixtures/precompiled/lua51/control_flow.luac` | `d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40` | Comparison opcodes and condition flags. |
| `tests/fixtures/precompiled/lua51/closures.luac` | `62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e` | Nested upvalues and child-prototype references. |
| `tests/fixtures/precompiled/lua51_32bit/hello.luac` | `e3b4aecb3e5669ff3636603d38583acead47336d870377685716ed6dd32e4fb4` | Header-declared 32-bit `size_t` control. |
| `tests/fixtures/precompiled/lua51_lnum32/hello.luac` | `8376be37ec3042d3b0a87aa39db7d7396fb54ae390abe346d885e1527d23e353` | Explicit vendor-profile selection control. |

Acceptance may derive minimized mutants from these bytes. Each mutant records its base
fixture hash, exact byte offset, original and replacement word, decoded fields, and
resulting SHA-256. Generated fixtures are test-local and must not replace the pinned
controls.

## Independent authority

Acceptance transcribes only the relevant operand domains from the official PUC-Rio
Lua 5.1.5 `lopcodes.h`, `lopcodes.c`, and `lvm.c`. The reviewed source hashes are:

- `lopcodes.h`: `a15fe349da7c1e73b563e8c3249fe7d535eccc844cb30ec80b4e335b0699279b`;
- `lopcodes.c`: `63cd74edc75970092a8ce078c4ab970efa1ee18de960d00eb826d49fe98d8a76`;
- `lvm.c`: `b560aad0a1b8bfc4e4b732b2393e8f8ecc68b6c772e6d25763d6ef71c38ab709`.

The oracle decodes instruction words independently and invokes the serialized public
CLI. It must not call the production Lua 5.1 opcode, disassembly, or validation helpers.

## Acceptance assertions

- All pinned compiler-produced controls validate without the three claimed diagnostics.
- Valid upvalue indices at and above `maxstacksize` do not produce register diagnostics.
- The first out-of-range upvalue index produces exactly `L51-UPVAL-001` for both
  `GETUPVAL` and `SETUPVAL`.
- An out-of-range `CLOSURE Bx` produces exactly `L51-PROTO-002`.
- Comparison `A = 0` and `A = 1` remain valid when either numeric value would fail a
  register interpretation; `A = 2` produces exactly `L51-BOOL-001`.
- Public disassembly identifies each tested field with the same non-register operand
  kind expected by the independent table.
- JSON validates against the live validation schema, text reports the same code and
  target, and machine stdout contains no commentary.
- Strict and permissive modes preserve diagnostic identity while honoring their
  documented exit behavior.

## Killer mutations

The acceptance comparator must reject an otherwise-valid observation when a test:

- replaces an upvalue bound with `maxstacksize`;
- accepts an upvalue index equal to the upvalue count;
- accepts a child-prototype index equal to the child count;
- treats comparison `A = 1` as a register;
- accepts comparison `A = 2` as a boolean;
- changes a diagnostic code, target PC, source offset, severity, or category;
- removes the invalid verdict or changes strict-mode exit behavior;
- changes an independently decoded opcode or operand field while leaving the observed
  CLI record unchanged.

Every mutation reaches the same comparator used by the positive cases and records the
specific rejection reason.

## Canonical gate

The independent acceptance author creates one unique gate:

```console
bash scripts/gates/gate-validator-reference-operands-lua51.sh ARTIFACT_DIR
```

Its specification is
`tests/gates/gate-validator-reference-operands-lua51.json`. It depends on the three
required gates named above, pins every public fixture and the Lua 5.1.5 compiler, and
enumerates every positive and killer-mutation test exactly.

## Role boundaries

The acceptance-test author may change only the sprint acceptance tests, independent
oracle, test-local mutant builder, new gate specification, and new gate wrapper. The
implementation agent may then change Lua 5.1 operand metadata and validation code,
ordinary unit tests, schemas, examples, and command documentation, but not the frozen
acceptance material, fixtures, sprint contract, or shared proof harness.

## Handoff

Acceptance requires the base, frozen acceptance, and candidate commits; exact Claude
and Antigravity versions and model identities; red and green logs; a clean candidate;
canonical gate artifacts with zero failed, ignored, skipped, filtered, or missing
tests; fixture, compiler, and authority hashes; `bash scripts/check.sh` success; and
confirmation that capability tiers remain unchanged.

## Stop condition

Do not begin register-span validation, diagnostic-catalog, target-promotion, or other
roadmap work until this sprint passes independent review from one clean revision.
