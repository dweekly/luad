# Nonfinite machine scalars and header guards

Fresh as of: 2026-10-22. Lane: bounded product family; no target promotion.

## Outcome and authority

Valid NaN/infinity constants currently emit null `val` against numeric schemas and
cannot make typed round trips. Lua 5.3-5.5 also accept a NaN LUAC_NUM header sentinel
because a greater-than-epsilon comparison is false for NaN; required official listing
loaders reject the same header. Public source/declared-offset probes reproduce both
without executing crafted chunks. Source authority: official 5.3.6, 5.4.8 and 5.5.1
loader behavior and their fixed LUAC_NUM equality checks; Rust f64/RFC 3514 and
serde_json's documented float_roundtrip precision boundary.

## Public claim and decisions

Use one serde/schema adapter in the existing scalar authority for all serializable
f64 owners: ConstantValue::Float.val, Header.luac_num, TypedOperand::ImmediateFloat.value.
Finite output stays a JSON number, byte-identical to the previous producer. Nonfinite
output uses canonical `nan`, `inf`, `-inf` strings. Unknown strings, null and numeric
strings refuse; ordinary JSON numbers retain f64 conversion/range semantics. Enable
serde_json float_roundtrip for exact finite producer/typed-reader round trips, and
retain an old-failing numeric counterexample plus boundary cases.

NaN strings preserve the decoded class, not a host f64 NaN payload/sign. Exact source
bits remain separately in raw_hex and provenance, with declared number width/order.
This avoids exposing target-dependent binary32-to-binary64 NaN casts. Preserve distinct
source NaN payloads through typed raw fields and demonstrate that corrupting those bits
is detected even when both decoded strings are `nan`. No layout guessing or decoder
widening change is authorized. Correct the model's 8-byte-only raw-float description.
Schema validates scalar shape; it does not enforce cross-field consistency in manually
constructed JSON. Keep Rust f64 field types and existing envelope/JSONL versions; note
the experimental schema union in the next 0.4 release. No interface freeze follows.

Reject nonmatching LUAC_NUM sentinels exactly in Lua 5.3, 5.4, 5.5, including NaNs and
infinities. Valid constants remain readable; valid headers remain unchanged. Use
existing diagnostics and preserve their raw input evidence.

## Scope and executable evidence

Production paths: Cargo.toml (serde_json feature), core scalar.rs/model.rs/ir.rs, and
Lua 5.3/5.4/5.5 header.rs. Ordinary tests: core scalar tests,
test_scalar_rendering.rs, test_machine_interface.rs and an optional shared helper in
crates/luad-oracle/tests/common/. Regenerate affected tests/schemas goldens; use the existing workspace schemars crate as an oracle-only
dev dependency for direct model-schema assertions; update
indexed README, architecture, machine reference, CHANGELOG/ROADMAP/checkpoint.
Archived candidate/GateSpec/evidence files remain byte-identical.

Before production edits, extend existing canonical entry points and retain old failures:

- `cargo test -p luad-oracle --test test_machine_interface test_live_inspect_json_`:
  actual JSON/JSONL float facts, schemas and typed raw/class round trips for required
  official Lua 5.1.5/5.2.4/5.3.6/5.4.8/5.5.1; declared four-byte Lua 5.1 control;
  signed zero, finite extremes/subnormals, infinities and distinct/signed NaN payloads.
- `cargo test -p luad-oracle --test test_machine_interface test_live_validate_json_`:
  valid header twins pass; NaN/infinity/finite-mismatch LUAC_NUM controls agree with
  each required official 5.3-5.5 listing loader's refusal, never chunk execution.
- `cargo test -p luad-oracle --test test_scalar_rendering` and focused core scalar
  tests: all three model owners (including buffered tagged variants), finite exact
  values, NaN class/raw separation and malformed-token/type negative controls.

Missing required compilers/fixtures fail. Prove the existing entry points reach the
new controls against the previous binary. Record a workspace-wide f64 owner inventory;
run the unchanged gate-machine-contract plus one clean pinned-Rust scripts/check.sh.
Retain official compiler identities and all skip counts. Compare finite command bytes
with the retained previous CLI in durable evidence. The planning review is accepted;
its one evidence-bearing follow-up must assess the selected narrower NaN-class encoding,
header family, exact diff and executed evidence before integration. Stop at reviewed,
CI-green merged code and a neutral checkpoint; select the reader/caller workflow next.
