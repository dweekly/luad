# Active sprint: Lua 5.1 conditional RK operand `B`

Lane: patch. Target: one Gemini implementation turn and one pull request.

## Claim and researcher value

For the ten stock Lua 5.1 opcodes whose `B` field is conditional RK, public disassembly
and validation select the same domain by bit 8: a clear bit denotes a register bounded
by the root prototype's `maxstacksize`; a set bit denotes a constant bounded by its
constant table. Researchers can consume typed operands and exact diagnostics without
reimplementing `BITRK`.

The exact opcode set is:

```text
SETTABLE ADD SUB MUL DIV MOD POW EQ LT LE
```

## Focused red regression

Add one compact table-driven public regression covering all ten opcodes at these four
boundaries:

- `B = maxstacksize - 1`: typed register, no `L51-REG-002`;
- `B = maxstacksize`: typed register, exactly one `L51-REG-002`;
- `B = BITRK | (constants.len() - 1)`: typed resolved constant, no `L51-CONST-004`;
- `B = BITRK | constants.len()`: typed selected constant, exactly one
  `L51-CONST-004` and no register diagnostic.

The test includes a zero-constant owner and one high-bit scalar control proving that a
non-RK `B` field does not enter the constant domain. Expected mnemonics and the ten-name
set are test-local; the regression may reuse existing chunk mutation, CLI, schema, and
provenance helpers. New acceptance/support code is capped at 400 changed lines.

The initial test is red because a bit-8-clear RK-`B` value at `maxstacksize` does not
produce `L51-REG-002`.

## Allowed scope

- `crates/luad-dialect-lua51/src/opcodes.rs` for exact RK-`B` role authority;
- `crates/luad-dialect-lua51/src/validator.rs` for bit-selected register and constant
  bounds plus ordinary unit tests;
- one focused public regression module under `crates/luad-oracle/tests/`;
- `CHANGELOG.md`, `README.md`, and the next forward-looking sprint handoff after
  acceptance.

Use existing fixtures, schemas, diagnostics, proof machinery, and gate specifications
unchanged. The existing register-`B` authority already labels conditional RK rows as
deferred and therefore does not conflict with this claim.

## Non-goals

Recursive RK ownership, exhaustive non-RK role qualification, fields `A` or `C`,
implicit register spans, new schemas or fixtures, target promotion, taint, decompilation,
persistent state, and vendor opcode recovery are outside this patch.

## Verification and stop condition

The implementation agent runs only:

```console
cargo build -p luad-cli --bin luad
cargo test -p luad-oracle --test test_validator_rk_b_lua51
```

The steward reviews the exact classifier and bound predicates, runs the focused test
once if needed, then pushes one pull request. GitHub CI supplies the single aggregate
repository run. One bounded correction is available; exceeding ten delegated minutes,
400 acceptance lines, or the allowed paths stops the turn for respecification.

After green CI, merge, verify clean `main == origin/main`, replace this document with
the next forward-looking patch, and remove the temporary branch and worktree.
