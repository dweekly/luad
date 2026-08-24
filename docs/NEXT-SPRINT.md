# Active sprint: Lua 5.1 conditional RK operand `C`

Status: acceptance contract. No downstream roadmap work begins before this sprint is
accepted or explicitly respecified.

## Claim

For each stock Lua 5.1 opcode whose encoded `C` field is an RK operand, `luad disasm`
and `luad validate` agree on the bit-selected domain:

- bit 8 clear means a register index that must be inside `0..maxstacksize`;
- bit 8 set means a constant-table index that must be inside the owning prototype's
  constant table.

No fixed-register, scalar, boolean, count, size-hint, unused, or combined-format `C`
field acquires RK validation or an RK fact.

## Researcher value

A human or agent can trust every conditional `C` operand as either a bounded register
or a resolved constant without reimplementing Lua's `BITRK` rule. Corrupt bytecode
fails at the owning instruction with a domain-specific diagnostic instead of allowing
an invalid register reference to enter later analysis.

## Starting evidence

- The accepted behavior baseline is the clean `main` revision containing the
  `gate-validator-register-c-lua51` result.
- Required prerequisite gates are `gate-proof-harness`, `gate-public-disasm-lua51`,
  `gate-validator-reference-operands-lua51`, and
  `gate-validator-register-c-lua51`.
- The required compiler is PUC-Rio Lua 5.1.5, reported as `Lua 5.1.5`, with SHA-256
  `eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239`.
- Lua 5.1 remains experimental; this sprint does not promote a target.

## Non-goals

- RK authority for field `B`;
- fixed-register authority for `A`, `B`, or `C`;
- implicit register spans or register provenance;
- closure capture-source bounds;
- new constant encodings, constant preview policy, or global/prototype resolution;
- effects, sinks, taint, decompilation, persistent research state, dialect promotion,
  or vendor opcode recovery.

## Exact opcode authority

Acceptance owns an independent 38-row `(opcode -> C role)` table derived from executed
PUC-Rio Lua 5.1.5 VM semantics. Exactly these opcodes have conditional RK field `C`:

```text
GETTABLE SETTABLE SELF ADD SUB MUL DIV MOD POW EQ LT LE
```

The production opcode-role authority and the independent acceptance table must agree
on that set but may not call each other. `CONCAT.C` remains a fixed direct register;
`LOADBOOL.C`, `TEST.C`, and `TESTSET.C` remain booleans; `NEWTABLE.C` remains a size
hint; `CALL.C` and `TFORLOOP.C` remain result counts; `SETLIST.C` remains a list block
index; all other physical `C` bits retain their defined non-RK or unused role.

## Public behavior

For every RK-`C` opcode, acceptance constructs equivalent instructions at these exact
boundaries:

| Encoding | Expected public meaning | Expected validation |
|---|---|---|
| `C = maxstacksize - 1` | typed register | clean for the `C` operand |
| `C = maxstacksize` | typed register | exactly one `L51-REG-003` for field `C` |
| `C = BITRK | (constants.len() - 1)` | typed and resolved constant | clean for the `C` operand |
| `C = BITRK | constants.len()` | selected constant index | exactly one `L51-CONST-005` for field `C` |

Zero-length constant tables use index `0` as the first invalid selected constant.
Register bounds use the raw bit-8-clear index; constant bounds use the low eight-bit
index. Diagnostics retain the owning prototype/instruction identity and source word.

Automatic stock selection and explicit `--dialect lua5.1` must produce deterministic,
schema-valid, semantically identical JSON and identical validation findings in strict
and permissive modes. Recursive child prototypes use their own `maxstacksize` and
constant table rather than the parent's bounds.

Unmodified maintained Lua 5.1 fixtures remain free of new diagnostics. A control sweep
sets high legal `C` values on every non-RK role and proves that neither
`L51-REG-003` nor `L51-CONST-005` is emitted because of that field.

## Independent acceptance

Acceptance fits in one module with no more than six named tests and one compact
table-driven oracle. It must prove:

- every official opcode occurs exactly once and the exact 12-opcode RK-`C` set is
  non-vacuous;
- all four register/constant boundaries above hold for every RK-`C` opcode;
- public disassembly emits register kinds for bit-8-clear values and resolved constant
  facts for valid selected constants;
- invalid selected constants remain represented as selected constants and produce the
  exact constant diagnostic, never a register diagnostic;
- recursive prototypes, automatic/explicit selection, strict/permissive validation,
  live schemas, determinism, and maintained fixtures agree;
- mutations that add or remove an RK opcode, swap the selected domain, use parent
  bounds for a child, alter either boundary, remove a resolved fact, or change
  diagnostic identity are rejected by the same positive comparator.

The first authoring checkpoint is one durable red test showing that a bit-8-clear
RK-`C` register at `maxstacksize` currently fails to produce `L51-REG-003`. The steward
verifies the red defect and independent opcode table before authorizing suite
expansion.

## Canonical gate and boundaries

The sprint owns exactly:

```console
bash scripts/gates/gate-validator-rk-c-lua51.sh ARTIFACT_DIR
```

with specification `tests/gates/gate-validator-rk-c-lua51.json`. The gate pins the
compiler, fixtures, exact acceptance tests, prerequisite closure, clean revision, and
zero ignored, skipped, filtered, missing, or substituted evidence.

The acceptance author may change only its sprint module, independent table and minimal
test helpers, gate specification, and gate wrapper. The implementation agent may
change Lua 5.1 dialect-owned RK-`C` role facts and validation plus ordinary unit tests.
Neither role may change maintained fixtures, schemas, capabilities, shared proof
machinery, prerequisite gates, or this contract.

## Handoff and stop condition

Acceptance requires the base, frozen-acceptance, and candidate commits; exact CLI,
model, authentication, and allocation identities; approved outline; durable red and
green logs; frozen-path hashes; one clean canonical-gate artifact; zero failed,
ignored, skipped, filtered, or missing tests; one steward-run `bash scripts/check.sh`;
reviewed pull requests merged in dependency order; and clean local `main` identical to
`origin/main`.

Do not begin RK-`B`, closure capture-source, implicit-span, diagnostic-catalog, target
promotion, provenance, or later-dialect work until this sprint satisfies that handoff.
