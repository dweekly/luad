# Active sprint: Lua 5.1 direct-register operand authority

Status: acceptance contract. No downstream roadmap work begins before this sprint is
accepted or explicitly respecified.

## Claim

For every stock Lua 5.1 instruction word, `luad disasm` and `luad validate` agree with
the official VM about which encoded fields are direct register references. Validation
rejects each direct register index outside `0..maxstacksize` and never applies a
register diagnostic to a flag, count, upvalue, prototype, jump, unused field, RK
constant, or closure-binding metadata field.

The public boundaries are:

```console
luad disasm CHUNK --dialect lua5.1 --format json
luad validate CHUNK --dialect lua5.1 --format json
luad validate CHUNK --dialect lua5.1 --strict --format json
```

The same rules apply when the stock profile is selected automatically.

## Researcher value

A human or agent can treat a register operand and an out-of-bounds-register diagnostic
as a precise VM fact. Scalar operands cannot silently create false register findings,
and a corrupt direct register cannot pass merely because the same physical field has a
different role on another opcode.

## Starting evidence

- The accepted baseline is revision
  `17a63156105767c37fd5b6bd7a8e15c790ca2a89`.
- Required prerequisite gates are `gate-proof-harness`,
  `gate-public-disasm-lua51`, `gate-closures-lua51`,
  `gate-validator-reference-operands-lua51`, and
  `gate-closure-prototype-identity-lua51`.
- The required compiler is PUC-Rio Lua 5.1.5, reported as `Lua 5.1.5`, with
  SHA-256 `eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239`.
- Lua 5.1 remains experimental; this sprint does not promote a target.

## Non-goals

- implicit register-span bounds such as `A..A+n`, call arguments/results, loop working
  sets, varargs, or open-ended top-of-stack ranges;
- RK constant-index validation except proving that RK constants are not registers;
- upvalue, child-prototype, comparison-flag, jump-target, or constant-domain changes;
- effects, liveness, reaching definitions, provenance slices, or sink analysis;
- Lua 5.1 LNUM semantics, Lua 5.2 or later, LuaJIT, or vendor opcode mappings;
- diagnostic-catalog publication or exact-target promotion;
- persistent annotations, inferred names, or project state.

## Official direct-register matrix

Acceptance derives field roles independently from PUC-Rio Lua 5.1.5
`lopcodes.h`, `lopcodes.c`, and `lvm.c`. It covers all 38 opcodes and treats only these
encoded fields as direct registers:

| Field role | Opcodes |
|---|---|
| Always-register `A` | `MOVE`, `LOADK`, `LOADBOOL`, `LOADNIL`, `GETUPVAL`, `GETGLOBAL`, `GETTABLE`, `SETGLOBAL`, `SETUPVAL`, `SETTABLE`, `NEWTABLE`, `SELF`, `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `POW`, `UNM`, `NOT`, `LEN`, `CONCAT`, `TEST`, `TESTSET`, `CALL`, `TAILCALL`, `RETURN`, `FORLOOP`, `FORPREP`, `TFORLOOP`, `SETLIST`, `CLOSE`, `CLOSURE`, `VARARG` |
| Always-register `B` | `MOVE`, `LOADNIL`, `GETTABLE`, `SELF`, `UNM`, `NOT`, `LEN`, `CONCAT`, `TESTSET` |
| Always-register `C` | `CONCAT` |
| RK `B`: register when `BITRK` is clear | `SETTABLE`, `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `POW`, `EQ`, `LT`, `LE` |
| RK `C`: register when `BITRK` is clear | `GETTABLE`, `SETTABLE`, `SELF`, `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `POW`, `EQ`, `LT`, `LE` |

`LOADNIL.B` and `CONCAT.B/C` are encoded register endpoints and therefore belong in
this sprint. Bounds implied beyond a directly encoded endpoint or base remain reserved
for the register-span sprint.

For ordinary executable instructions, an encoded direct register is valid exactly
when its unsigned index is less than `maxstacksize`. Each invalid field produces the
field-specific `L51-REG-001`, `L51-REG-002`, or `L51-REG-003` diagnostic at the owning
instruction and source word. Strict and permissive validation agree on the first
direct-register defect; permissive mode may continue to report independent defects.

The physical words following `CLOSURE` are interpreted by their `closure_binding`
role. A `MOVE` binding uses `B` as a parent register and ignores its encoded `A`; a
`GETUPVAL` binding uses `B` as a parent upvalue and ignores its encoded `A`. Those words
do not acquire ordinary executable operand roles merely because their opcode bits name
`MOVE` or `GETUPVAL`.

## Fixture matrix

| Fixture | SHA-256 | Purpose |
|---|---|---|
| `tests/fixtures/precompiled/lua51/hello.luac` | `d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f` | Simple executable register operands and deterministic auto/explicit selection. |
| `tests/fixtures/precompiled/lua51/control_flow.luac` | `d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40` | Comparisons, jumps, tests, calls, returns, and loop base registers. |
| `tests/fixtures/precompiled/lua51/tables.luac` | `b9db891cc3f8ea04338194bfeace1847a06e5be3ad5e0222c4d19a10ad766a8f` | Table, RK, count, and register-field separation. |
| `tests/fixtures/precompiled/lua51/closures.luac` | `62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e` | Recursive prototypes and role-aware closure-binding descriptors. |

Acceptance may generate test-local chunks or mutate one pinned instruction word to
exercise every legal field boundary and every non-register control. Each derived case
records the base hash, prototype path, PC, original word, changed field, changed word,
and resulting hash. Maintained fixture bytes remain unchanged.

## Independent authority

The acceptance oracle transcribes the official operand comments, `OpArgMask` table,
instruction encodings, and VM uses without calling production opcode, disassembly,
validation, effects, or closure-binding helpers. It pins these official source files:

| Authority | SHA-256 |
|---|---|
| PUC-Rio Lua 5.1.5 `lopcodes.h` | `a15fe349da7c1e73b563e8c3249fe7d535eccc844cb30ec80b4e335b0699279b` |
| PUC-Rio Lua 5.1.5 `lopcodes.c` | `63cd74edc75970092a8ce078c4ab970efa1ee18de960d00eb826d49fe98d8a76` |
| PUC-Rio Lua 5.1.5 `lvm.c` | `b560aad0a1b8bfc4e4b732b2393e8f8ecc68b6c772e6d25763d6ef71c38ab709` |

The test-local comparator owns an exhaustive `(opcode, field) -> role` table. A
production enum, display operand kind, validator allowlist, or diagnostic is an
observation under test and cannot define the expected role.

## Acceptance assertions

- All 38 opcodes and all `A`, `B`, and `C` physical fields appear in the independent
  role sweep; missing or duplicate cases fail.
- Every direct-register field is typed as `register` in live disassembly JSON.
- A direct-register value of `maxstacksize - 1` validates without an
  `L51-REG-*` diagnostic; `maxstacksize` produces the exact field-specific diagnostic.
- Every non-register field can carry a value at or above `maxstacksize` without a
  register diagnostic when that value is otherwise legal for its role.
- RK register forms below `BITRK` follow the register rule, while RK constant forms do
  not produce register diagnostics.
- Closure binding descriptors follow binding roles, retain their physical PCs, and do
  not emit standalone executable-register diagnostics for ignored fields.
- Diagnostic code, target ID, source offset, field name, observed index, and stack
  bound are deterministic and agree between repeated invocations.
- Automatic and explicit stock-profile selection produce the same semantic records.
- Live JSON validates against the current disassembly and validation schemas.
- Every pinned compiler-produced fixture has no unjustified register diagnostic.

## Killer mutations

The positive comparator must reject an otherwise-valid observation when a test:

- marks one scalar, unused, upvalue, prototype, jump, count, or flag field as a
  register;
- removes one official direct-register field from the matrix;
- swaps the roles of `B` and `C` for one opcode;
- accepts `index == maxstacksize` or rejects `index == maxstacksize - 1`;
- treats an RK constant as a register or an RK register as a constant-only field;
- validates a closure-binding descriptor's ignored `A` as an executable register;
- omits or changes one diagnostic's target ID, source offset, code, or field identity;
- exercises fewer than all 38 opcodes or silently drops one prototype depth;
- makes auto and explicit profile output disagree.

Every mutation reaches the same comparator used by the positive cases and records a
specific rejection reason.

## Canonical gate

The independent acceptance author creates exactly one sprint gate:

```console
bash scripts/gates/gate-validator-direct-registers-lua51.sh ARTIFACT_DIR
```

Its specification is
`tests/gates/gate-validator-direct-registers-lua51.json`. It depends on every gate in
Starting evidence, pins the four fixtures and official compiler, enumerates every
positive and killer test exactly, and rejects missing, ignored, skipped, filtered, or
zero-test execution.

## Role boundaries

The acceptance-test author may add the sprint acceptance test, independent operand
matrix and decoder, test-local chunk mutator, gate specification, and gate wrapper.
Production code, maintained fixtures, current schemas, sprint contract, shared proof
harness, gate runner, capability tiers, and prerequisite tests remain forbidden.

The implementation agent may change Lua 5.1 dialect-owned operand facts and validation
plus ordinary unit tests and current interface documentation. It may not alter frozen
acceptance material, maintained fixtures, schemas, the sprint gate, prerequisite
evidence, shared proof machinery, or capability tiers.

## Handoff

Acceptance requires base, frozen-acceptance, and candidate commits; exact acceptance
and implementation CLI/model identities; red and green logs; a clean candidate;
canonical gate artifacts; fixture, compiler, authority, spec, and result hashes; zero
failed, ignored, skipped, filtered, or missing tests; `bash scripts/check.sh` success;
and confirmation that Lua 5.1 remains experimental.

## Stop condition

Do not begin implicit register-span validation, the public diagnostic catalog,
exact-target promotion, register provenance, or other roadmap work until this sprint
passes independent review from one clean revision.
