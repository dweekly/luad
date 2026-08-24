# Active sprint: Lua 5.1 conditional RK operand `B`

Status: specification. Acceptance authorship begins from the accepted `main` revision.

## Claim

For each stock Lua 5.1 opcode whose encoded `B` field is an RK operand, `luad disasm`
and `luad validate` agree on the bit-selected domain in the root prototype:

- bit 8 clear means a register index inside `0..maxstacksize`;
- bit 8 set means a constant-table index inside the owning prototype's constant table.

## Researcher value

A human or agent can consume arithmetic, comparison, and table-write operands without
reimplementing Lua's `BITRK` rule or mistaking a selected constant for a register.
Malformed references produce a domain-specific diagnostic at the owning instruction.

## Required evidence

- Base: clean `main` with `gate-validator-rk-c-lua51` accepted.
- Prerequisites: `gate-proof-harness`, `gate-public-disasm-lua51`,
  `gate-validator-reference-operands-lua51`, and
  `gate-validator-register-b-lua51`.
- Compiler: PUC-Rio Lua 5.1.5, reported as `Lua 5.1.5`, SHA-256
  `eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239`.
- Target: stock Lua 5.1 root prototypes. The target remains experimental.

## Exact authority

Acceptance owns an independent 38-row `(opcode -> B role)` table derived from executed
PUC-Rio Lua 5.1.5 VM semantics. Exactly these opcodes have conditional RK field `B`:

```text
SETTABLE ADD SUB MUL DIV MOD POW EQ LT LE
```

The acceptance authority and production role table must agree on this exact set without
sharing classifier code. Fixed registers, counts, booleans, size hints, upvalue indices,
prototype indices, and unused fields retain their distinct roles.

## Public boundaries

For each of the ten RK-`B` opcodes, acceptance constructs otherwise-equivalent root
instructions at four boundaries:

| Encoding | Public operand | Validation result for `B` |
|---|---|---|
| `B = maxstacksize - 1` | typed register | clean |
| `B = maxstacksize` | typed register | exactly one `L51-REG-002` |
| `B = BITRK \| (constants.len() - 1)` | typed, resolved constant | clean |
| `B = BITRK \| constants.len()` | selected constant | exactly one `L51-CONST-004` |

A zero-length constant table uses selected index zero as its first invalid boundary.
Diagnostics preserve instruction identity, physical word, source location, and owning
prototype. Invalid constants remain typed as selected constants and never produce a
register diagnostic.

## Acceptance surface

One sprint module contains exactly four tests:

1. the independent 38-row authority has one row per official opcode, the exact ten-opcode
   RK-`B` set, and killer mutations for addition, removal, and role substitution;
2. every RK-`B` register boundary produces the exact public register behavior and
   diagnostic identity;
3. every RK-`B` constant boundary produces the exact public constant behavior,
   resolution, and diagnostic identity, including a zero-constant owner;
4. live JSON disassembly types the domain by bit 8 and agrees with the independent
   expectation for mnemonic, physical field, typed operand, and resolved fact.

The first authoring checkpoint is one durable red test demonstrating that a bit-8-clear
RK-`B` value at `maxstacksize` does not yet produce `L51-REG-002`. The steward verifies
the red defect and the exact authority before authorizing the remaining three tests.

Acceptance also includes comparator mutations for a swapped domain, shifted boundary,
missing resolved fact, and altered diagnostic target. Each mutation must be rejected by
the same comparator used for the positive case.

## Non-goals

- recursive child-prototype RK ownership;
- public exclusion sweeps for non-RK `B` or `C` roles;
- fixed-register fields or implicit register spans;
- closure capture-source bounds or register provenance;
- new schemas, diagnostics, fixtures, constant encodings, or preview policy;
- effects, sinks, taint, decompilation, persistent state, target promotion, or vendor
  opcode recovery.

## Canonical gate

The sprint owns exactly:

```console
bash scripts/gates/gate-validator-rk-b-lua51.sh ARTIFACT_DIR
```

with specification `tests/gates/gate-validator-rk-b-lua51.json`. It pins the compiler,
fixtures, four acceptance tests, prerequisite closure, clean revision, and zero ignored,
skipped, filtered, missing, or substituted evidence.

The acceptance author may change only the sprint test module, test-local oracle and
helpers, gate specification, and gate wrapper. The implementation agent may change
Lua 5.1 dialect-owned RK-`B` role facts and validation plus ordinary unit tests. Neither
role may change maintained fixtures, schemas, capabilities, shared proof machinery,
prerequisite gates, or this contract.

## Handoff and stop condition

Acceptance requires base, frozen-acceptance, and candidate commits; exact provider and
model identities; approved outline; durable red and green logs; frozen-path hashes; one
clean canonical-gate artifact; zero failed, ignored, skipped, filtered, or missing tests;
one steward-run aggregate check; reviewed pull requests merged in dependency order; and
clean local `main` identical to `origin/main`.

Do not begin recursive RK ownership, non-RK exclusion, capture-source bounds,
implicit-span validation, diagnostic-catalog work, or target promotion before this
sprint is accepted or explicitly respecified.
