# Active sprint: Lua 5.1 fixed-role register `B`

Status: acceptance contract. No downstream roadmap work begins before this sprint is
accepted or explicitly respecified.

## Claim

For every stock Lua 5.1 opcode, `luad disasm` identifies an ordinary instruction's
encoded `B` field as a register exactly when the VM unconditionally uses `B` as a
direct register, and `luad validate` emits `L51-REG-002` exactly when such a register
index is outside `0..maxstacksize`.

Boolean values, counts, size hints, unused fields, upvalue references, and combined
`Bx` or `sBx` fields do not acquire a fixed-register `B` fact or diagnostic. Deferred
RK operands retain their conditional register-or-constant interpretation but cannot
satisfy this fixed-role claim.

## Researcher value

A researcher can trust `B`-register facts and `L51-REG-002` without treating table-size
hints, argument counts, return counts, or unused physical bits as impossible registers.
This removes false findings from embedded chunks whose scalar `B` values legitimately
exceed a function's register count.

## Starting evidence

- The accepted behavior baseline is revision
  `911325f3caa57b5983d5cac25d33ceea31cb860c`.
- Required prerequisite gates are `gate-proof-harness`,
  `gate-public-disasm-lua51`, `gate-closures-lua51`,
  `gate-validator-reference-operands-lua51`, and
  `gate-validator-register-a-lua51`.
- The required compiler is PUC-Rio Lua 5.1.5, reported as `Lua 5.1.5`, with
  SHA-256 `eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239`.
- Lua 5.1 remains experimental; this sprint does not promote a target.

## Non-goals

- conditional RK register/constant authority for `B`;
- register authority for `C` or `L51-REG-003`;
- closure-binding capture-source bounds for descriptor `B`;
- implicit register spans, including the interiors of `LOADNIL` and `CONCAT` ranges;
- argument, result, iterator, loop-working-set, vararg, or open-top spans;
- new validation domains for counts, booleans, size hints, upvalues, constants,
  prototypes, or jumps;
- effects, provenance, sink analysis, decompilation, or persistent research state;
- LNUM semantics, later Lua versions, LuaJIT, vendor opcode mappings, diagnostic-catalog
  publication, or target promotion.

## Official `B`-field matrix

Acceptance owns an independent 38-row `(opcode -> B role)` table derived from executed
PUC-Rio Lua 5.1.5 VM semantics. The official opcode-mode table is a cross-check, not a
substitute for observing whether the VM reads the field.

The fixed direct-register `B` opcodes are:

```text
MOVE LOADNIL GETTABLE SELF UNM NOT LEN CONCAT TESTSET
```

The remaining roles are:

| Role | Opcodes |
|---|---|
| Conditional RK, deferred | `SETTABLE ADD SUB MUL DIV MOD POW EQ LT LE` |
| Upvalue reference | `GETUPVAL SETUPVAL` |
| Scalar or unused | `LOADBOOL NEWTABLE TEST CALL TAILCALL RETURN TFORLOOP SETLIST CLOSE VARARG` |
| No independent `B` field | `LOADK GETGLOBAL SETGLOBAL JMP FORLOOP FORPREP CLOSURE` |

`TEST.B` is unused even if an opcode-mode declaration assigns it a generic argument
role. `NEWTABLE.B` is an encoded array-size hint; `CALL.B`, `TAILCALL.B`, `RETURN.B`,
`SETLIST.B`, and `VARARG.B` are counts or count sentinels. `TFORLOOP.B` and `CLOSE.B`
are unused. None is a register merely because the physical word contains a nonzero
value.

For an ordinary fixed-register instruction, `B` is valid exactly when its unsigned
value is less than `maxstacksize`. `LOADNIL.B` and `CONCAT.B` are direct encoded range
endpoints; this sprint validates the endpoint field but does not infer or publish the
interior span.

Lua 5.1 closure-binding descriptors remain contextual records rather than ordinary
instructions. Acceptance uses valid descriptor sources as controls but leaves their
capture-source bounds to a separate contract.

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

For a parsed chunk whose fixed direct register `B == maxstacksize`:

- `validate` exits `1` in strict and permissive modes;
- stdout contains exactly one `L51-REG-002` for the changed field, tied to the owning
  instruction ID and source word;
- stderr is empty;
- `B == maxstacksize - 1` remains valid.

## Fixture matrix

| Fixture | SHA-256 | Purpose |
|---|---|---|
| `tests/fixtures/precompiled/lua51/hello.luac` | `d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f` | Simple fixed-register and scalar controls; automatic and explicit selection. |
| `tests/fixtures/precompiled/lua51/control_flow.luac` | `d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40` | Calls, returns, tests, loops, RK operands, counts, and unused-field controls. |
| `tests/fixtures/precompiled/lua51/closures.luac` | `62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e` | Recursive prototype traversal and valid closure-binding controls. |

Acceptance may derive test-local chunks by changing one pinned instruction word or by
compiling recorded source with the pinned compiler. Every derived case records its
base hash, prototype path, PC, original word, changed `B`, changed word, and result
hash. Maintained fixture bytes remain unchanged.

## Independent authority

The acceptance table is transcribed from official PUC-Rio Lua 5.1.5 VM reads and
operand comments without calling production opcode-role, disassembly, validation,
effects, or closure-binding helpers:

| Authority | SHA-256 |
|---|---|
| `lopcodes.h` | `a15fe349da7c1e73b563e8c3249fe7d535eccc844cb30ec80b4e335b0699279b` |
| `lopcodes.c` | `63cd74edc75970092a8ce078c4ab970efa1ee18de960d00eb826d49fe98d8a76` |
| `lvm.c` | `b560aad0a1b8bfc4e4b732b2393e8f8ecc68b6c772e6d25763d6ef71c38ab709` |

## Acceptance assertions

- The independent table contains every official opcode exactly once and assigns one
  `B` role to each.
- Live disassembly types `B` as `register` for every ordinary fixed-register opcode.
- Live disassembly does not type scalar, unused, reference, or combined-format `B` as
  a fixed register.
- Every fixed-register opcode accepts `B == maxstacksize - 1` and produces the exact
  `L51-REG-002` at `B == maxstacksize`.
- High legal values for `NEWTABLE.B`, count fields, and unused `B` fields produce no
  `L51-REG-002`.
- Recursive prototypes, strict/permissive validation, automatic/explicit selection,
  live schemas, and the three unmodified fixtures satisfy the public behavior.

## Killer mutations

The positive comparator rejects an otherwise-valid observation when a test:

- removes one opcode or changes one row in the independent matrix;
- marks `TEST.B`, `NEWTABLE.B`, a count, an unused field, or a combined-format field as
  a fixed register;
- omits one fixed-register opcode or types its `B` as an immediate;
- accepts `B == maxstacksize` or rejects `B == maxstacksize - 1`;
- changes the diagnostic code, field, target, source offset, observed index, or bound;
- omits a recursive prototype or makes automatic and explicit records disagree.

Each mutation reaches the same comparator used by the positive case and records a
specific rejection reason.

## Review budget

The acceptance outline must fit this claim into one test module, no more than six named
acceptance tests, and one compact table-driven oracle. It reuses existing public CLI,
schema, fixture, and gate infrastructure without copying a general Lua chunk parser.
If independent proof cannot fit that surface, the author returns a narrower contract
proposal before editing.

## Canonical gate

The independent acceptance author creates exactly one sprint gate:

```console
bash scripts/gates/gate-validator-register-b-lua51.sh ARTIFACT_DIR
```

Its specification is `tests/gates/gate-validator-register-b-lua51.json`. It depends on
the prerequisite gates above, pins the three fixtures and compiler, enumerates every
positive and killer test exactly, and rejects missing, ignored, skipped, filtered, or
zero-test execution.

## Role boundaries

The acceptance-test author may add one sprint acceptance module, its independent
`B`-role table and minimal test-local helpers, the gate specification, and the gate
wrapper. Production code, maintained fixtures, schemas, sprint contract, shared proof
machinery, capability tiers, and prerequisite tests remain forbidden.

The implementation agent may change Lua 5.1 dialect-owned fixed `B` operand facts and
validation plus ordinary unit tests. It may not alter frozen acceptance material,
fixtures, schemas, the sprint gate, prerequisite evidence, shared proof machinery, or
capability tiers.

## Handoff

Acceptance requires base, frozen-acceptance, and candidate commits; exact CLI/model,
authentication, allocation, and overage identities; approved outline; red and green
logs; a clean candidate; canonical artifacts and hashes; zero failed, ignored,
skipped, filtered, or missing tests; one steward-run `bash scripts/check.sh`; and
confirmation that Lua 5.1 remains experimental.

## Stop condition

Do not begin register-`C`, RK, closure capture-source bounds, implicit-span,
diagnostic-catalog, promotion, or provenance work until this sprint passes independent
review from one clean revision.
