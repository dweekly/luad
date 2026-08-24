# Active sprint: Lua 5.1 numeric-for register spans

Lane: patch. Target: one focused public regression and one pull request.

## Claim and researcher value

Lua 5.1 `FORPREP` and `FORLOOP` validate their fixed four-register window
`R(A)..R(A+3)` against the owning prototype's register file. A valid base register
cannot conceal an out-of-range implicit control register. Diagnostics retain the exact
instruction identity and physical bytes so researchers can distinguish malformed loop
state from suspicious control flow.

## Focused public regression

Use the pinned `control_flow.luac` fixture. Its root prototype has
`maxstacksize = 6`; `FORPREP` at PC 10, byte offset 109 and `FORLOOP` at PC 12, byte
offset 117 both use `A = 2`, so their window ends at valid `R(5)`.

For each opcode, prove two independent public cases while preserving the original
signed jump field:

- the original `A = 2` instruction produces no register-span diagnostic;
- setting only `A = 3` leaves the base register valid but reports exactly one
  `L51-REG-SPAN-001` on that instruction because the window ends at `R(6)`.

Pin the fixture hash and obtain the root bound from live `inspect` JSON. Validate live
`validate` JSON against its schema. Assert exact diagnostic code, stable ID, source
offset, byte length, raw hex, and a message naming the opcode, window, and bound. Use
selected-prototype `disasm` JSON to prove the opcode, typed `A = R(3)`, unchanged signed
jump and target, and schema validity.

Acceptance/support code is capped at 250 formatted lines and production code at 30
formatted lines.

## Allowed scope

- one focused module at
  `crates/luad-oracle/tests/test_validator_numeric_for_span_lua51.rs`;
- `crates/luad-dialect-lua51/src/validator.rs`;
- `CHANGELOG.md`, `README.md`, `ROADMAP.md`, and the next forward-looking sprint handoff
  after acceptance.

Use the existing fixture, schemas, diagnostics, CLI selectors, and decoded instruction
facts unchanged. Do not add a fixture, schema, gate, shared test framework, or general
range-analysis abstraction.

## Non-goals

Variable-width `CALL`, `RETURN`, `SETLIST`, `TFORLOOP`, or `VARARG` spans; implicit
effects in disassembly; CFG changes; diagnostic-catalog publication; capability changes;
and target promotion are outside this patch.

## Verification and stop condition

The implementation agent runs only:

```console
cargo build -p luad-cli --bin luad
cargo test -p luad-oracle --test test_validator_numeric_for_span_lua51
```

The steward reviews the four-register VM rule, mutation isolation, exact diagnostic,
stable IDs, physical offsets, and unchanged jump facts, then pushes one pull request.
GitHub CI supplies the aggregate repository run. One bounded correction is available;
exceeding ten delegated minutes, 250 acceptance lines, 30 production lines, or the
allowed paths stops the turn for respecification.

After green CI, merge, verify clean `main == origin/main`, replace this document with
the next forward-looking patch, and remove the temporary branch and worktree.
