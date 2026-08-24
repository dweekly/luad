# Active sprint: Lua 5.1 register-`A` authority

Status: acceptance contract. No downstream roadmap work begins before this sprint is
accepted or explicitly respecified.

## Claim

For every stock Lua 5.1 opcode, `luad disasm` identifies the encoded `A` field as a
register exactly when the official VM uses it as a direct register, and `luad validate`
emits `L51-REG-001` exactly when such a register index is outside
`0..maxstacksize`. Flags, unused `A` fields, and ignored `A` fields in closure-binding
descriptors never acquire a register fact or register diagnostic.

## Researcher value

A human or agent can trust an `A`-register operand and `L51-REG-001` finding as precise
VM facts without manually remembering which opcodes reuse the same physical bits as a
flag or unused field.

## Starting evidence

- The accepted behavior baseline is revision
  `17a63156105767c37fd5b6bd7a8e15c790ca2a89`.
- Required prerequisite gates are `gate-proof-harness`,
  `gate-public-disasm-lua51`, `gate-closures-lua51`,
  `gate-validator-reference-operands-lua51`, and
  `gate-closure-prototype-identity-lua51`.
- The required compiler is PUC-Rio Lua 5.1.5, reported as `Lua 5.1.5`, with
  SHA-256 `eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239`.
- Lua 5.1 remains experimental; this sprint does not promote a target.

## Non-goals

- `B` or `C` register authority and `L51-REG-002` or `L51-REG-003`;
- RK register/constant discrimination;
- closure-binding `B` capture-source validation;
- implicit register spans, call arguments/results, loop working sets, varargs, or
  open-ended top-of-stack ranges;
- upvalue, child-prototype, comparison-flag, jump-target, or constant-domain changes;
- effects, liveness, register provenance, sink analysis, or decompilation;
- LNUM semantics, later Lua versions, LuaJIT, or vendor opcode mappings;
- diagnostic-catalog publication, exact-target promotion, or persistent project state.

## Official `A`-field matrix

Acceptance owns an independent 38-row `(opcode -> A role)` table.

The official direct-register `A` opcodes are:

```text
MOVE LOADK LOADBOOL LOADNIL GETUPVAL GETGLOBAL GETTABLE SETGLOBAL
SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN
CONCAT TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORLOOP
SETLIST CLOSE CLOSURE VARARG
```

`JMP` has no semantic `A` operand. `EQ`, `LT`, and `LE` use `A` as a boolean condition
flag. For an ordinary instruction in the register set, `A` is valid exactly when its
unsigned value is less than `maxstacksize`.

Physical `MOVE` and `GETUPVAL` words used as Lua 5.1 `closure_binding` descriptors are
contextual exceptions: their encoded `A` field is ignored and must not be typed or
validated as an executable register. Their physical PC and binding role remain visible.

## Public behavior

For a valid stock chunk:

```console
luad disasm CHUNK --dialect lua5.1 --format json
luad validate CHUNK --dialect lua5.1 --format json
luad validate CHUNK --dialect lua5.1 --strict --format json
```

- exit code is `0`;
- stdout is one JSON document validating against the live command schema;
- stderr is empty;
- automatic stock-profile selection produces the same semantic records as explicit
  `--dialect lua5.1`.

For a parsed chunk whose direct register `A == maxstacksize`:

- `validate` exits `1` in strict and permissive modes;
- stdout is one validation JSON document containing `L51-REG-001` at the owning
  instruction ID and source word;
- stderr is empty;
- strict and permissive modes agree on the first register-`A` defect.

## Fixture matrix

| Fixture | SHA-256 | Purpose |
|---|---|---|
| `tests/fixtures/precompiled/lua51/hello.luac` | `d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f` | Simple direct-register `A` instructions and auto/explicit selection. |
| `tests/fixtures/precompiled/lua51/control_flow.luac` | `d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40` | `EQ`, `LT`, `LE`, `JMP`, calls, returns, tests, and loop-base controls. |
| `tests/fixtures/precompiled/lua51/closures.luac` | `62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e` | Recursive prototypes and ignored descriptor-`A` cases. |

Acceptance may derive test-local chunks by changing one pinned instruction word or by
compiling recorded source with the pinned compiler. Every derived case records its
base hash, prototype path, PC, original word, changed `A`, changed word, and result
hash. Maintained fixture bytes remain unchanged.

## Independent authority

The acceptance table is transcribed from official PUC-Rio Lua 5.1.5 operand comments,
opcode modes, and VM uses without calling production opcode, disassembly, validation,
effects, or closure-binding helpers:

| Authority | SHA-256 |
|---|---|
| `lopcodes.h` | `a15fe349da7c1e73b563e8c3249fe7d535eccc844cb30ec80b4e335b0699279b` |
| `lopcodes.c` | `63cd74edc75970092a8ce078c4ab970efa1ee18de960d00eb826d49fe98d8a76` |
| `lvm.c` | `b560aad0a1b8bfc4e4b732b2393e8f8ecc68b6c772e6d25763d6ef71c38ab709` |

## Acceptance assertions

- The independent table contains every official opcode exactly once.
- Live disassembly types `A` as `register` for every ordinary register-`A` opcode.
- Live disassembly does not type `JMP.A`, comparison `A`, or descriptor `A` as a
  register.
- `A == maxstacksize - 1` produces no `L51-REG-001` diagnostic.
- `A == maxstacksize` produces exactly one `L51-REG-001` with deterministic code,
  target ID, source offset, field name, observed index, and stack bound.
- Legal non-register `A` values at or above `maxstacksize` produce no register
  diagnostic.
- Strict/permissive and automatic/explicit invocations satisfy the public behavior.
- The three unmodified fixtures produce no unjustified `L51-REG-001` diagnostic.
- Live JSON validates against the current disassembly and validation schemas.

## Killer mutations

The positive comparator rejects an otherwise-valid observation when a test:

- removes one opcode or changes one row in the independent `A` matrix;
- marks `JMP.A` or comparison `A` as a register;
- accepts `A == maxstacksize` or rejects `A == maxstacksize - 1`;
- validates an ignored closure-binding descriptor `A` as an executable register;
- changes the diagnostic code, field, target, source offset, observed index, or bound;
- omits a recursive prototype depth;
- makes automatic and explicit stock-profile records disagree.

Each mutation reaches the same comparator used by the positive cases and records a
specific rejection reason.

## Canonical gate

The independent acceptance author creates exactly one sprint gate:

```console
bash scripts/gates/gate-validator-register-a-lua51.sh ARTIFACT_DIR
```

Its specification is `tests/gates/gate-validator-register-a-lua51.json`. It depends on
the prerequisite gates above, pins the three fixtures and compiler, enumerates every
positive and killer test exactly, and rejects missing, ignored, skipped, filtered, or
zero-test execution.

## Role boundaries

The acceptance-test author may add one sprint acceptance test, the independent
`A`-role table and minimal decoder, test-local derived cases, gate specification, and
gate wrapper. Production code, maintained fixtures, schemas, sprint contract, shared
proof machinery, capability tiers, and prerequisite tests remain forbidden.

The implementation agent may change Lua 5.1 dialect-owned `A` operand facts and
validation plus ordinary unit tests. It may not alter frozen acceptance material,
fixtures, schemas, the sprint gate, prerequisite evidence, shared proof machinery, or
capability tiers.

## Handoff

Acceptance requires base, frozen-acceptance, and candidate commits; exact CLI/model,
authentication, allocation, and overage identities; approved outline; red and green
logs; a clean candidate; canonical artifacts and hashes; zero failed, ignored, skipped,
filtered, or missing tests; one steward-run `bash scripts/check.sh`; and confirmation
that Lua 5.1 remains experimental.

## Stop condition

Do not begin register-`B`, register-`C`, RK, implicit-span, diagnostic-catalog,
promotion, or provenance work until this sprint passes independent review from one
clean revision.
