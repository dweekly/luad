# Active sprint: Lua 5.1 `CALL` argument-register span

Lane: patch. Target: one focused public regression and one pull request.

## Claim and researcher value

Lua 5.1 `CALL` validates its fixed argument window `R(A)..R(A+B-1)` when `B > 0`
against the owning prototype's register file. A valid function register and scalar
argument count cannot conceal an out-of-range argument register. The public diagnostic
retains exact instruction identity and physical bytes.

## Focused public regression

Use the pinned `control_flow.luac` fixture, whose root prototype has
`maxstacksize = 6`. At PC 0 and byte offset 69, replace the instruction word with an
official Lua 5.1 iABC `CALL` word using `A = 1`, a scalar argument-window count in `B`,
and `C = 1` so the call produces no result registers. Prove two public cases:

- `B = 5` produces no `L51-REG-SPAN-001` because the function/argument window ends at
  `R(5)`;
- changing only `B` to 6 reports exactly one `L51-REG-SPAN-001` because the window
  ends at `R(6)`.

Pin the fixture hash and derive the root bound from live `inspect` JSON. Validate live
`validate` and selected-prototype `disasm` JSON against their schemas. Prove the exact
mnemonic, typed `A` register, scalar `B` and `C` counts, raw word, stable instruction
ID, source offset and length, raw hex, and a message naming `CALL`, `R(1)..R(6)`, and
the bound. Assert that the words differ only in encoded field `B`, and that neither
case misclassifies `B` as a direct register or emits `L51-REG-002`.

Acceptance/support code is capped at 220 formatted lines and production code at 25
formatted lines.

## Allowed scope

- one focused module at
  `crates/luad-oracle/tests/test_validator_call_argument_span_lua51.rs`;
- `crates/luad-dialect-lua51/src/validator.rs`;
- `CHANGELOG.md`, `README.md`, `ROADMAP.md`, and the next forward-looking sprint handoff
  after acceptance.

Use the existing fixture, schemas, diagnostic, CLI selectors, and decoded instruction
facts unchanged. Do not add a fixture, schema, gate, shared test framework, or general
range-analysis abstraction.

## Non-goals

Open `B = 0` calls; `CALL` result registers; `TAILCALL`; fixed or generic-for spans;
`LOADNIL`, `CONCAT`, `RETURN`, `SETLIST`, or `VARARG` spans; disassembly effects; CFG
changes; diagnostic-catalog publication; capability changes; and target promotion are
outside this patch.

## Verification and stop condition

The implementation agent stops after a reviewable diff. The steward runs only:

```console
cargo build -p luad-cli --bin luad
cargo test -p luad-oracle --test test_validator_call_argument_span_lua51
```

The steward reviews the official `CALL` VM rule, isolated iABC encoding, fixed-count
argument semantics, exact diagnostic and provenance, stable ID, and typed public
operands, then pushes one pull request. GitHub CI supplies the aggregate repository
run. One bounded correction is available; exceeding ten delegated minutes, 220
acceptance lines, 25 production lines, or the allowed paths stops the turn for
respecification.

After green CI, merge, verify clean `main == origin/main`, replace this document with
the next forward-looking patch, and remove the temporary branch and worktree.
