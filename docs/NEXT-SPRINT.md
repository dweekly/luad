# Active sprint: bounded Lua 5.1 call-argument origins

Lane: semantic analysis. Target: emit one auditable, cycle-free origin expression for
every statically bounded call argument without turning dependency into taint policy.

## Claim and researcher value

For every Lua 5.1 `CALL` and `TAILCALL` with a fixed argument window, each argument will
carry an eagerly captured expression describing where its value came from. Researchers
will be able to distinguish literal-only values, parameter/upvalue-dependent
concatenations, Lua arithmetic including the LuCI `%` formatting idiom, fields, call
results, and explicit analysis cutoffs.

This supplies bytecode provenance, not a security verdict. `luad` will not label a value
tainted, sanitized, attacker-controlled, safe, or exploitable.

## Contract

The analysis will consume parsed prototypes, shared semantic instructions, CFG facts,
and the established conservative closure environments. It will not decode raw words or
reclassify callees.

The expression union will cover literal constants, fixed parameters, upvalues, global
and constant-key fields, call results, concatenations, unary operations, binary
operations, and typed unknown reasons. `MOD` will remain a binary operation with its
literal format operand and other origins visible; the fact will not assert that every
runtime `MOD` performs formatting.

Operands will be cloned from the pre-instruction register state before any destination
write. This is mandatory for self-aliasing instructions such as `CONCAT A A C` and
arithmetic whose destination overlaps a source. Fixed expression depth, node-count,
register-window, and transfer budgets will produce distinct cutoff reasons.

CFG joins will retain structurally identical expressions and union their stable evidence;
different incoming expressions become an explicit conflict rather than an invented
merge. Fixed call-result windows become indexed `call-result` expressions. Open argument
or result windows remain explicit unknowns. Closure-binding descriptors do not execute.

The CLI will expose `origins` in text, JSON, and self-identifying JSONL. Recursive export
will emit the same call-argument origin facts for Lua 5.1 artifacts.

## Acceptance matrix

A single compiler-shaped matrix will cover literal strings/numbers/booleans/nil,
parameters, upvalues across three levels, globals, constant and dynamic fields, fixed
call results, `MOVE`, `CONCAT`, all Lua 5.1 unary and binary opcodes, and especially
`MOD`. It will combine these with same-block aliases, identical/conflicting branches,
loops, overwritten ranges, open calls/varargs, unreachable calls, and expression limits.

The matrix will assert eager self-alias handling for `CONCAT`, distinguish a
constant-only concatenation from a parameter-dependent one, and retain the format
literal plus argument origins for `%`. Every fixed argument slot will have exactly one
fact. Open argument windows will produce one explicit call-level unresolved record.

Killer controls will replace a parameter-dependent subtree with a constant, create a
self-cycle, drop a concatenation operand, reinterpret `MOD` as formatting, leak one CFG
predecessor through a conflict, erase cutoff reasons, and omit one argument fact. The
public fixture will pin expression-shape and unresolved-reason histograms. A corpus survey
will report usefulness separately from acceptance.

Redistributable source fixtures will be compiled by the exact Lua 5.1 authorities. A
separate corpus survey may measure usefulness and unresolved-reason distribution, but it
will never decide correctness or gate acceptance.

## Allowed production paths

- `crates/luad-analysis/src/origins.rs` and minimal shared callee-analysis helpers
- command parsing and rendering in `crates/luad-cli`
- recursive export and public capability/schema discovery
- redistributable fixtures, focused oracle tests, one gate spec and runner
- indexed machine-interface, recipe, status, and changelog documentation

## Non-goals

This sprint does not classify sinks, infer attacker control, prove sanitization, resolve
dynamic table keys, perform points-to analysis, build a call graph, add SSA, structure
source code, add persistent state, or promote a support tier. It does not claim that
`MOD` is formatting or promise a corpus coverage percentage.

## Verification and stop condition

Acceptance requires the focused origin matrix and killer controls, canonical machine and
batch-export regression gates, aggregate repository checks, green pull-request CI, and a
clean merged revision with local `main` equal to `origin/main`. The sprint stops rather
than collapsing `unknown`, `computed`, and `analysis stopped` into one category.
