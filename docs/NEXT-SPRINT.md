# Active sprint: owner-relative Lua 5.1 query prototype identity

Lane: patch. Target: one silent factual error in query summaries.

## Claim and researcher value

For every Lua 5.1 `CLOSURE`, `luad query` will name the same owner-relative child
prototype as disassembly, xrefs, export, and the typed prototype operand. A query result
must not format the local `Bx` child index as a root prototype path.

This prevents a researcher or agent from following a plausible identifier to a real but
unrelated function.

## Affected boundary and regression

The affected public boundary is the instruction `summary` returned by `luad query` for
Lua 5.1 closure instructions. The focused regression uses the maintained nested-closure
fixture and independently derives each child path from the owning instruction ID plus
the encoded local child index. It compares every `proto:` reference reported by query
with the typed disassembly fact and xref target at the same physical instruction.

The expected failing case includes at least two nesting levels and repeated local child
index zero, where `proto:0/0`, `proto:0/0/0`, and `proto:0/0/0/0` must remain distinct.

## Allowed paths

- `crates/luad-dialect-lua51/src/lifter.rs`
- `crates/luad-oracle/tests/test_closure_prototype_identity_lua51.rs`
- `CHANGELOG.md`

The implementation must derive the summary from the existing typed owner-relative
prototype operand or equivalent prototype-path fact. It must not add a second chunk-tree
walk, parser, schema field, command, or analysis pass.

## Non-goals

This sprint does not change parsing, encoded operands, stable IDs, xrefs, export,
non-closure summaries, other dialects, target support status, or schema versions. It
does not include opcode-authority documentation, capability discovery, symbolic callee
resolution, or value provenance.

## Verification and stop condition

Focused verification:

```console
cargo test -p luad-oracle --test test_closure_prototype_identity_lua51 -- --nocapture
```

Acceptance requires the focused regression, a production diff within the patch lane,
green pull-request CI, a clean merged revision, and local `main` equal to `origin/main`.
No target-promotion work begins inside this sprint.
