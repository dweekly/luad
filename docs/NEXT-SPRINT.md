# Active product batch: open-window callee independence

Lane: product. Outcome: a researcher can identify a statically resolvable Lua 5.1
callee even when the same call forwards an open vararg argument window.

## Public claim

For every reachable Lua 5.1 `CALL` or `TAILCALL`, `callees` derives the callee from the
value in register `A` at that program point independently of argument and result
cardinality. A preceding `VARARG` or another top-dependent write invalidates only the
register range it can write; it does not erase a proved callee below that range.

An open argument window remains explicit in `origins`. Open cardinality alone is never
the unresolved reason for a callee whose register value is otherwise proved. Text,
JSON, JSONL, recursive export, query, and call-relation consumers agree on the same
callee fact without a schema-major change.

## Evidence

- Add one Lua 5.1 fixture shape equivalent to `local function f(...) return g(...) end`
  with a resolvable global or module callee.
- Assert that `callees` resolves `g` with instruction evidence while `origins` reports
  an open argument window for the same call.
- Assert that a genuinely dynamic open-window callee remains unresolved for the reason
  established by callee-register analysis.
- Assert that query and recursive export preserve the resolved callee.
- Run the focused `test_symbolic_callees_lua51` suite and the existing
  `gate-symbolic-callees-lua51` gate. Reuse its compiler authority, fixture policy,
  comparator, and gate runner.

## Scope

Production work is limited to Lua 5.1 callee dataflow. Ordinary focused tests and the
minimum fixture/source manifest changes are allowed. The batch adds no new command,
schema major, oracle, gate, release manifest, or proof harness.

Path-sensitive origin alternatives, table-literal origins, corpus-wide queries,
selective export, cross-chunk module conventions, caller-union substitution, sink
classification, and taint policy are non-goals.

## Stop condition

Stop after one reviewable production-and-test diff demonstrates the focused regression.
The steward runs the existing gate, aggregate CI, integration, candidate rebuild, and
customer replay. Promotion remains blocked until the replay and outside-human trial
satisfy the customer-transfer checkpoint.
