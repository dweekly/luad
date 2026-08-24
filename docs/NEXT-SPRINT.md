# Active sprint: Lua 5.1 closure-capture source bounds

Lane: patch. Target: one focused public regression and one pull request.

## Claim and researcher value

Lua 5.1 closure-binding descriptors validate their capture source in the executing
parent prototype. `MOVE` descriptors use the parent's register-file bound and
`GETUPVAL` descriptors use the parent's upvalue bound. Diagnostics and disassembly
retain the descriptor's physical location, stable parent instruction identity, source
domain, destination upvalue position, and owning `CLOSURE` link.

## Focused public regression

Use the pinned `closures.luac` fixture and two independent descriptor mutations:

- `proto:0/0`, PC 4, byte offset 179 is the `MOVE` descriptor owned by the `CLOSURE`
  at PC 3. Set `B = 3`. The executing parent has `maxstacksize = 3`, while its child
  `proto:0/0/0` has `maxstacksize = 4`, so only parent ownership produces exactly one
  `L51-REG-002`.
- `proto:0/0/0`, PC 7, byte offset 260 is the `GETUPVAL` descriptor owned by the
  `CLOSURE` at PC 6. Set `B = 1` against the executing parent's single declared
  upvalue and require exactly one `L51-UPVAL-001`.

Pin the fixture hash and obtain the stated parent/child bounds from live `inspect`
JSON. Validate live `validate` and selected-prototype `disasm` JSON against their
schemas. For each probe, assert the exact diagnostic code, descriptor stable ID,
physical source range and raw bytes. Assert disassembly retains
`role = closure_binding`, the matching descriptor mnemonic, `companion_pc`, destination
`upvalue[0]`, and a typed unresolved capture source with raw value `3` or `1`.

The regression may be green without production changes. Acceptance requires the public
proof, not a minimum production diff. New acceptance/support code is capped at 250
formatted lines.

## Allowed scope

- one focused module at
  `crates/luad-oracle/tests/test_validator_closure_capture_bounds_lua51.rs`;
- `crates/luad-dialect-lua51/src/validator.rs` or `disasm.rs` only if the public
  regression exposes a descriptor-source defect;
- `CHANGELOG.md`, `README.md`, `ROADMAP.md`, and the next forward-looking sprint handoff
  after acceptance.

Use the existing fixture, schemas, diagnostics, CLI selectors, and closure-binding facts
unchanged. Do not copy a field-authority suite or add a shared test framework.

## Non-goals

Implicit register spans, descriptor count or opcode-class validation, new fixtures,
schemas, gates, capability changes, target promotion, CFG changes, and fields outside
the two capture-source probes are outside this patch.

## Verification and stop condition

The implementation agent runs only:

```console
cargo build -p luad-cli --bin luad
cargo test -p luad-oracle --test test_validator_closure_capture_bounds_lua51
```

The steward reviews parent ownership, stable IDs, physical offsets, descriptor roles,
and both exact diagnostic families, then pushes one pull request. GitHub CI supplies
the aggregate repository run. One bounded correction is available; exceeding ten
delegated minutes, 250 acceptance lines, or the allowed paths stops the turn for
respecification.

After green CI, merge, verify clean `main == origin/main`, replace this document with
the next forward-looking patch, and remove the temporary branch and worktree.
