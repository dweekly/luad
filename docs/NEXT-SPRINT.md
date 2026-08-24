# Active sprint: Lua 5.1 nested RK owner isolation

Lane: patch. Target: one focused public regression and one pull request.

## Claim and researcher value

Lua 5.1 conditional RK operands in a nested prototype are bounded by that prototype's
register file and constant table. Root-prototype bounds cannot make an invalid child
operand appear valid. Validation diagnostics and disassembly facts identify the exact
child instruction so researchers can trust nested-function results without reconstructing
prototype ownership.

## Focused public regression

Use the pinned `closures.luac` fixture and mutate child `proto:0/0`, PC 0 at its recorded
instruction offset into `ADD` probes. The child declares `maxstacksize = 3` and one
constant while the root declares `maxstacksize = 6` and two constants. Prove these four
owner-separating cases independently:

- clear-bit `B = 3` reports exactly one `L51-REG-002` on the child instruction;
- clear-bit `C = 3` reports exactly one `L51-REG-003` on the child instruction;
- selected `B = BITRK | 1` reports exactly one `L51-CONST-004` on the child instruction;
- selected `C = BITRK | 1` reports exactly one `L51-CONST-005` on the child instruction.

In every case, keep the other RK operand valid for the child. Validate the live CLI JSON
against its schema, assert the diagnostic's stable child ID and source offset, and use
`disasm --proto proto:0/0 --format json` to assert `ADD`, the selected operand domain,
and the matching unresolved out-of-range constant or register value. Pin the fixture
hash and assert the differing root and child bounds so the test cannot collapse into a
same-owner comparison.

The regression may be green without production changes. Acceptance requires the public
proof, not a minimum production diff. New acceptance/support code is capped at 250
changed lines.

## Allowed scope

- one focused module at
  `crates/luad-oracle/tests/test_validator_rk_nested_owner_lua51.rs`;
- `crates/luad-dialect-lua51/src/validator.rs` or `disasm.rs` only if the public
  regression exposes an owner-selection defect;
- `CHANGELOG.md`, `README.md`, `ROADMAP.md`, and the next forward-looking sprint handoff
  after acceptance.

Use the existing fixture, schemas, diagnostics, CLI selectors, and proof machinery
unchanged. Do not copy the large field-authority suites or add a shared test framework.

## Non-goals

New opcode-role authority, additional fixtures, recursive corpus sweeps, closure-capture
source bounds, implicit register spans, schemas, gates, capability changes, target
promotion, and fields outside the four probes are outside this patch.

## Verification and stop condition

The implementation agent runs only:

```console
cargo build -p luad-cli --bin luad
cargo test -p luad-oracle --test test_validator_rk_nested_owner_lua51
```

The steward reviews owner selection, stable IDs, physical offsets, and all four exact
diagnostic families, then pushes one pull request. GitHub CI supplies the aggregate
repository run. One bounded correction is available; exceeding ten delegated minutes,
250 acceptance lines, or the allowed paths stops the turn for respecification.

After green CI, merge, verify clean `main == origin/main`, replace this document with
the next forward-looking patch, and remove the temporary branch and worktree.
