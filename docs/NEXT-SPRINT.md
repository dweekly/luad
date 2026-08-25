# Active sprint: Lua 5.1 count-encoded register windows

Lane: semantic matrix. Target: one frozen acceptance commit, one implementation
commit, and one canonical gate.

## Claim and researcher value

Lua 5.1 validation treats `CALL`, `TAILCALL`, `RETURN`, `SETLIST`, and `VARARG`
count fields as scalar counts while validating every statically bounded register
window those counts describe. Fixed argument, result, return-value, table-source, and
vararg-result windows cannot extend beyond the owning prototype's `maxstacksize`.
Open-ended count value zero remains explicitly unbounded and receives no invented
static endpoint.

This closes the remaining count-encoded register spans without making `B` or `C`
look like direct registers in diagnostics or machine disassembly.

## Semantic authority

Acceptance derives each row from the executed Lua 5.1.5 VM rule and independently
encodes the iABC word. With a prototype bound of six registers and `A = 1`, prove:

| Instruction role | Fixed window | Last valid count | First invalid count |
|---|---|---:|---:|
| `CALL.B` arguments, including function | `R(A)..R(A+B-1)` | 5 | 6 |
| `CALL.C` results | `R(A)..R(A+C-2)` when `C > 1` | 6 | 7 |
| `TAILCALL.B` arguments, including function | `R(A)..R(A+B-1)` | 5 | 6 |
| `RETURN.B` returned values | `R(A)..R(A+B-2)` when `B > 1` | 6 | 7 |
| `SETLIST.B` table sources | `R(A+1)..R(A+B)` when `B > 0` | 4 | 5 |
| `VARARG.B` results | `R(A)..R(A+B-2)` when `B > 1` | 6 | 7 |

For each fixed row, changing only the named count across the boundary produces
exactly one `L51-REG-SPAN-001` with the mnemonic, exact window, owning bound,
instruction stable ID, physical word, source offset, source length, and raw bytes.
The valid boundary produces none. `CALL` proves its argument and result windows
independently so one field cannot mask the other.

For every applicable zero-count form, prove that validation does not invent a static
span. Prove that `TAILCALL.C` and `SETLIST.C` remain non-register fields even at their
largest encoded value. No matrix case may emit `L51-REG-002` or `L51-REG-003` for a
count field.

The acceptance comparator must reject at least these mutations: omitted expected
span, wrong endpoint formula, wrong owner bound or target ID, scalar count retyped as
a register, and a diagnostic invented for an open-ended count.

## Public boundary and fixtures

Use the manifest-pinned Lua 5.1 `control_flow.luac` fixture and derive its root
`maxstacksize` through live `inspect --format json`. Mutate one root instruction word
at its recorded byte location while preserving the rest of the chunk. Exercise live
`validate --format json` and selected-prototype `disasm --format json`, validate both
documents against their published schemas, and pin the fixture hash.

The frozen acceptance module is
`crates/luad-oracle/tests/test_validator_count_spans_lua51.rs`. The canonical gate is
`gate-validator-count-spans-lua51`, comprising:

- `tests/gates/gate-validator-count-spans-lua51.json`;
- `scripts/gates/gate-validator-count-spans-lua51.sh`;
- the exact non-skipping acceptance tests enumerated by the gate specification;
- `gate-proof-harness`, `gate-public-disasm-lua51`, and
  `gate-validator-reference-operands-lua51` as prerequisites.

The gate pins Lua 5.1.5 compiler identity and the fixture hash. A missing compiler,
fixture, test, boundary row, mutation, or schema check is a hard failure.

## Allowed scope

Acceptance author:

- `crates/luad-oracle/tests/test_validator_count_spans_lua51.rs`.

Steward-owned gate and planning paths:

- `tests/gates/gate-validator-count-spans-lua51.json`;
- `scripts/gates/gate-validator-count-spans-lua51.sh`;
- `docs/NEXT-SPRINT.md` and the documentation index freshness entry.

Implementation agent:

- `crates/luad-dialect-lua51/src/validator.rs`;
- ordinary validator unit tests in that file only when they clarify the production
  helper independently of the frozen public acceptance module.

The implementation may introduce one small dialect-local helper for expressing
statically bounded windows. It may not change disassembly, lifting, schemas, fixture
bytes, the diagnostic shape, or frozen acceptance and gate files.

## Non-goals

`LOADNIL` and `CONCAT` already carry direct endpoint operands and are outside this
count-field matrix. Dynamic top-of-stack inference for zero-count forms, register
provenance, CFG changes, diagnostic-catalog publication, capability promotion, and
other Lua dialects are outside this sprint.

## Verification and stop condition

Freeze the acceptance commit only after the focused test fails for the absent span
behavior while all comparator mutations are demonstrably live. The steward then runs:

```console
cargo build -p luad-cli --bin luad
cargo test -p luad-oracle --test test_validator_count_spans_lua51
bash scripts/gates/gate-validator-count-spans-lua51.sh /tmp/luad-gate-count-spans
bash scripts/check.sh
```

Acceptance requires a clean candidate revision, zero skipped or ignored tests, a
tamper-evident gate artifact, unchanged frozen acceptance files during implementation,
and exact public diagnostics for every matrix boundary. After merge and remote
verification, replace this document with the diagnostic-discoverability sprint and
remove the temporary branches and worktrees.
