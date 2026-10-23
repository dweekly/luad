# SETUPVAL operand classification in the Lua 5.2/5.3 validators

Fresh as of: 2026-10-23. Lane: bounded false-answer correction; no target promotion.

## Outcome and decision

Public issue #108. The Lua 5.2 and 5.3 validators check `SETUPVAL` operand B against
`maxstacksize` as a source register and report `L52-REG-002`/`L53-REG-002` errors on
official compiler output (pinned LuaSocket `ltn12.lua`, 5.2.4 and 5.3.6, three errors
each). Authority: official 5.2/5.3 `lopcodes.h`, `OP_SETUPVAL A B UpValue[B] := R(A)`.
B is an upvalue index, already checked as one (`L5x-UPVAL-002`); A is the source register,
already checked by the register-A rule (`L5x-REG-001`). Remove `SetUpval` from the
source-register-B arm in both validators. Lua 5.1/5.4/5.5 classify it correctly and are
unchanged.

## Scope

Production: `crates/luad-dialect-lua52/src/validator.rs` and
`crates/luad-dialect-lua53/src/validator.rs`, one arm each. Tests: the existing
`test_validator_bounds_lua52.rs` and `test_validator_bounds_lua53.rs`. CHANGELOG and this
checkpoint. No diagnostic code, catalog, schema, gate, or support-status change; no other
operand reclassification without its own counterexample.

## Executable acceptance fixed before production

- Required official 5.2.4/5.3.6 compile a source whose `SETUPVAL` B exceeds the writing
  function's `maxstacksize`. Assert that the compiled chunk contains such a word (so the
  control exercises the case) and that validation reports no error diagnostics. Compiler
  absence fails; the source is never executed. This control must fail before the
  production edit.
- Negative controls: a `SETUPVAL` whose A is out of range still yields `L5x-REG-001`,
  and one whose B is out of upvalue range still yields `L5x-UPVAL-002`.
- Focused validator suites, one pinned-Rust `scripts/check.sh`, and final CI. Replay the
  20 pinned public inputs: LuaSocket 5.2/5.3 structural export loses exactly the three
  false errors and keeps every fact unchanged.

Stop at accepted, final-CI-green merged code and a neutral checkpoint.
