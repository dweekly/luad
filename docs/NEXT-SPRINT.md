# Active sprint: Lua 5.1 fixed-role register `C`

Status: acceptance contract. No downstream roadmap work begins before this sprint is
accepted or explicitly respecified.

## Claim

For every stock Lua 5.1 opcode, `luad disasm` identifies an ordinary instruction's
encoded `C` field as a register exactly when the VM unconditionally uses `C` as a
direct register, and `luad validate` emits `L51-REG-003` exactly when that register
index is outside `0..maxstacksize`.

Boolean flags, result counts, table-size hints, list block indices, unused fields, and
combined `Bx` or `sBx` fields do not acquire a fixed-register `C` fact or diagnostic.
RK operands retain their conditional register-or-constant meaning and remain outside
this fixed-role claim.

## Researcher value

A human or agent can treat `C`-register facts and `L51-REG-003` as exact without
mistaking legitimate embedded-firmware counts, flags, or size hints for impossible
registers. `CONCAT` range endpoints become trustworthy while adjacent scalar fields
remain free of false validation findings.

## Starting evidence

- The accepted behavior baseline is revision
  `305a14ae128f47e96bdabc65fd4fabb540a371dc`.
- Required prerequisite gates are `gate-proof-harness`,
  `gate-public-disasm-lua51`, `gate-closures-lua51`,
  `gate-validator-reference-operands-lua51`, `gate-validator-register-a-lua51`, and
  `gate-validator-register-b-lua51`.
- The required compiler is PUC-Rio Lua 5.1.5, reported as `Lua 5.1.5`, with SHA-256
  `eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239`.
- Lua 5.1 remains experimental; this sprint does not promote a target.

## Non-goals

- conditional RK authority or constant bounds for `C`;
- implicit interiors of `CONCAT` or any other register span;
- register authority for `A` or `B`;
- closure capture-source bounds;
- argument, result, iterator, loop-working-set, vararg, or open-top spans;
- new domains for counts, booleans, size hints, constants, upvalues, prototypes, or
  jumps;
- effects, provenance, sink analysis, decompilation, persistent research state,
  diagnostic-catalog publication, dialect promotion, or vendor opcode recovery.

## Official `C`-field matrix

Acceptance owns an independent 38-row `(opcode -> C role)` table derived from executed
PUC-Rio Lua 5.1.5 VM semantics. The official opcode-mode table is a cross-check, not a
substitute for observing whether the VM reads the field.

The only fixed direct-register `C` opcode is:

```text
CONCAT
```

The conditional RK `C` opcodes are:

```text
GETTABLE SETTABLE SELF ADD SUB MUL DIV MOD POW EQ LT LE
```

All other opcodes classify `C` as a boolean, count, size hint, list block index,
unused field, or part of a combined `Bx`/`sBx` encoding. In particular:

- `LOADBOOL.C`, `TEST.C`, and `TESTSET.C` are control booleans;
- `NEWTABLE.C` is a hash-size hint;
- `CALL.C` and `TFORLOOP.C` are result counts or count encodings;
- `SETLIST.C` is a list block index;
- `TAILCALL.C` and the physical `C` bits of instructions that do not consume `C` are
  unused.

For `CONCAT`, `C` is valid exactly when its unsigned value is less than
`maxstacksize`. It is the inclusive end register of a range; this sprint validates and
publishes the encoded endpoint without inferring the range interior.

## Public behavior

The fixture matrix is:

| Fixture | SHA-256 | Purpose |
|---|---|---|
| `tests/fixtures/precompiled/lua51/hello.luac` | `d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f` | Simple automatic/explicit selection and scalar controls. |
| `tests/fixtures/precompiled/lua51/control_flow.luac` | `d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40` | Boolean, count, RK, loop, and unused-field controls. |
| `tests/fixtures/precompiled/lua51/closures.luac` | `62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e` | Recursive prototype traversal and combined-format controls. |

For each unmodified fixture, automatic stock selection and explicit
`--dialect lua5.1` produce schema-valid, deterministic, semantically identical JSON
with exit code `0` and empty stderr.

For a test-local `CONCAT` whose `C == maxstacksize - 1`, validation remains clean. At
`C == maxstacksize`, strict and permissive validation exit `1` and emit exactly one
`L51-REG-003` tied to the owning instruction ID and source word. Setting bit 8 on
`CONCAT.C` remains a register overflow and must not produce an RK-constant diagnostic.

High legal values for `NEWTABLE.C`, `SETLIST.C`, count fields, booleans, and unused
fields produce no `L51-REG-003`.

## Independent authority and acceptance

The acceptance table is transcribed from PUC-Rio Lua 5.1.5 `lopcodes.h`, `lopcodes.c`,
and `lvm.c`, using the source hashes pinned by the public Lua 5.1 evidence. It may not
call production opcode-role, disassembly, validation, effects, or closure-binding
helpers.

Acceptance fits in one module with no more than six named tests and one compact
table-driven oracle. It must prove:

- every official opcode occurs exactly once with one `C` role;
- live disassembly types `CONCAT.C` as `register` and no scalar, boolean, count,
  unused, RK, or combined-format `C` as a fixed register;
- the exact `maxstacksize - 1` / `maxstacksize` boundary and diagnostic identity;
- bit-8 `CONCAT.C` produces only the register diagnostic;
- recursive prototypes, strict/permissive validation, automatic/explicit selection,
  live schemas, and all three fixtures agree;
- mutations that omit `CONCAT`, add any false fixed-register row, alter the boundary,
  change diagnostic identity, remove recursion, or make public forms disagree are
  rejected by the same positive comparator.

The first authoring checkpoint is one durable red test demonstrating a current false
`L51-REG-003` on a legal scalar, count, or unused `C` field. The steward verifies that
red defect and the independent table before authorizing suite expansion.

## Canonical gate and boundaries

The sprint owns exactly:

```console
bash scripts/gates/gate-validator-register-c-lua51.sh ARTIFACT_DIR
```

with specification `tests/gates/gate-validator-register-c-lua51.json`. The gate pins
the compiler, fixtures, exact acceptance tests, prerequisite closure, clean revision,
and zero ignored, skipped, filtered, missing, or substituted evidence.

The acceptance author may change only its sprint module, independent table and minimal
test helpers, gate specification, and gate wrapper. The implementation agent may
change Lua 5.1 dialect-owned fixed-`C` facts and validation plus ordinary unit tests.
Neither role may change maintained fixtures, schemas, capabilities, shared proof
machinery, prerequisite gates, or this contract.

## Handoff and stop condition

Acceptance requires the base, frozen-acceptance, and candidate commits; exact CLI,
model, authentication, and allocation identities; approved outline; durable red and
green logs; frozen-path hashes; one clean canonical-gate artifact; zero failed,
ignored, skipped, filtered, or missing tests; one steward-run `bash scripts/check.sh`;
reviewed pull requests merged in dependency order; and clean local `main` identical to
`origin/main`.

Do not begin RK, closure capture-source, implicit-span, diagnostic-catalog, target
promotion, provenance, or later-dialect work until this sprint satisfies that handoff.
