# Active sprint: Lua 5.1 `TFORLOOP` register span

Lane: patch. Target: one focused public regression and one pull request.

## Claim and researcher value

Lua 5.1 `TFORLOOP` validates its count-dependent register window
`R(A)..R(A+2+C)` against the owning prototype's register file. A valid base and scalar
count cannot conceal an out-of-range iterator result register. The public diagnostic
retains exact instruction identity and physical bytes.

## Focused public regression

Use the pinned `control_flow.luac` fixture, whose root prototype has
`maxstacksize = 6`. At PC 0 and byte offset 69, replace the instruction word with an
official Lua 5.1 iABC `TFORLOOP` word using `A = 0`, unused `B = 0`, and a scalar
result count in `C`. Prove two public cases:

- `C = 3` produces no `L51-REG-SPAN-001` because the window ends at `R(5)`;
- changing only `C` to 4 reports exactly one `L51-REG-SPAN-001` because the window
  ends at `R(6)`.

Pin the fixture hash and derive the root bound from live `inspect` JSON. Validate live
`validate` and selected-prototype `disasm` JSON against their schemas. Prove the exact
mnemonic, typed `A` register, scalar `C` count, raw word, stable instruction ID, source
offset and length, raw hex, and a message naming `TFORLOOP`, `R(0)..R(6)`, and the
bound. Assert that the words differ only in encoded field `C`, and that neither case
misclassifies `C` as a direct register or emits `L51-REG-003`.

Acceptance/support code is capped at 220 formatted lines and production code at 25
formatted lines.

## Allowed scope

- one focused module at
  `crates/luad-oracle/tests/test_validator_tforloop_span_lua51.rs`;
- `crates/luad-dialect-lua51/src/validator.rs`;
- `CHANGELOG.md`, `README.md`, `ROADMAP.md`, and the next forward-looking sprint handoff
  after acceptance.

Use the existing fixture, schemas, diagnostic, CLI selectors, and decoded instruction
facts unchanged. Do not add a fixture, schema, gate, shared test framework, or general
range-analysis abstraction.

## Non-goals

Fixed numeric-for or `SELF` validation; `LOADNIL`, `CONCAT`, `CALL`, `RETURN`,
`SETLIST`, or `VARARG` spans; disassembly effects; CFG changes; diagnostic-catalog
publication; capability changes; and target promotion are outside this patch.

## Verification and stop condition

The implementation agent stops after a reviewable diff. The steward runs only:

```console
cargo build -p luad-cli --bin luad
cargo test -p luad-oracle --test test_validator_tforloop_span_lua51
```

The steward reviews the official `TFORLOOP` VM rule, isolated iABC encoding, count
semantics, exact diagnostic and provenance, stable ID, and typed public operands, then
pushes one pull request. GitHub CI supplies the aggregate repository run. One bounded
correction is available; exceeding ten delegated minutes, 220 acceptance lines, 25
production lines, or the allowed paths stops the turn for respecification.

After green CI, merge, verify clean `main == origin/main`, replace this document with
the next forward-looking patch, and remove the temporary branch and worktree.
