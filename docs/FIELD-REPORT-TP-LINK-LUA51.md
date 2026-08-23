# Field report: TP-Link firmware using Lua 5.1

Date received: 2026-08-22

Status: retained external evidence and product requirements, not an execution plan. The firmware corpus is not included in this repository; release evidence uses redistributable reproducers plus an aggregate private-corpus report.

## Summary

A peer reverse-engineering project applied `luad` to a TP-Link firmware corpus containing 252 compiled Lua files. Before its fix, all 252 failed with:

```text
Invalid constant tag 71
```

The reported root cause was an architecture-dependent Lua 5.1 chunk-layout assumption:

- the header's declared `sizeof(size_t)` was parsed and discarded;
- every subsequent string length was read as a 64-bit little-endian value;
- the firmware used a 32-bit `size_t`;
- each string read consumed four bytes from the following field, desynchronizing the prototype;
- parsing failed later at a misleading constant-tag boundary.

The peer fix is on branch `fix/lua51-32bit-sizet-and-lnum`, commit `54e4b8d`. It threads the declared `size_t` width through Lua 5.1 parsing and accepts the corpus's LNUM constant tag 9. Reported result after the change:

```text
252/252 files parse and validate
20 existing test suites pass unchanged
```

This is strong real-world compatibility evidence. It is not proof of complete Lua 5.1 correctness. Promotion requires the F1–F4 public gates in [the coding-agent execution plan](CODING-AGENT-PLAN.md), including explicit profile identity, closure captures, resolved operands, diagnostics, and redistributable fixtures.

## Profile classification

Lua 5.1 chunks reflect host representation details declared in their headers, including endianness and widths. These are part of the stock format and must drive all width-dependent reads.

LNUM tag 9 is not an ordinary stock Lua 5.1 constant tag. It should be represented as an explicit LNUM/vendor profile rather than silently broadening the meaning of `lua5.1`. Output and durable artifact identity should record the resolved base dialect, profile, header layout, and parse mode.

The current corpus can therefore be described conservatively as:

```text
base dialect: Lua 5.1
profile: LNUM/vendor extension
size_t: 32-bit
corpus size: 252 compiled chunks
parse result after peer fix: 252/252
public closure gate: pending F2
redistributable fixture status: unknown
```

## Closure-binding defect

The peer found that Lua 5.1 words following `CLOSURE` were rendered and analyzed as executable instructions. In Lua 5.1, the next `nups` physical words are upvalue-binding descriptors:

```text
MOVE     0 B   => child upvalue[i] captures parent register B
GETUPVAL 0 B   => child upvalue[i] captures parent upvalue B
```

They are not dispatched as ordinary VM instructions. Rendering them as executable `MOVE`/`GETUPVAL` operations produces false register writes, incorrect explanations, poisoned use/definition sets, and potentially incorrect CFG structure.

Required model:

- preserve the raw physical words and PCs;
- mark them as closure-binding descriptors rather than executable instructions;
- attach ordered capture relations to the preceding `CLOSURE` record;
- exclude descriptor words from standalone execution effects and CFG block starts;
- validate the descriptor count and allowed opcodes against the child prototype's upvalue count;
- represent capture sources explicitly as parent register or parent upvalue at the closure site.

## Research-workflow feedback

Ranked by time cost reported by the peer:

1. **Resolve constants inline.** `LOADK 20 24` should retain `K24` and display a safely escaped preview of its value. This was the largest obstacle to identifying a hardcoded AES key. Resolution should cover all dialect-defined constant-bearing operands, not only selected mnemonic renderers.
2. **Correct CLOSURE descriptors.** Public output must never explain a binding descriptor as an executable operation or assign it standalone effects.
3. **Expose upvalue capture relations.** The researcher needed the inverse mapping from child upvalue slot to the parent register/upvalue captured at a specific closure site. The AES-key path crossed three binding hops.
4. **Preserve the actual error offset.** The top-level failure reported offset 0 even though desynchronization surfaced near `0x119`.
5. **Add a 32-bit Lua 5.1 fixture.** The compatibility bug must become a permanent, independently generated regression case.
6. **Consider bounded batch input.** The peer shell-looped over roughly 260 files. This is lower priority than factual correctness and can remain external unless profiling shows material startup overhead.

## Evidence and regression requirements

Before this field result contributes to a support claim:

- create a legally redistributable minimal 32-bit stock Lua 5.1 fixture;
- create a separate LNUM/profile fixture;
- record exact compiler/runtime source, patch, archive hash, platform, endianness, integer/number sizes, source hash, compiler flags, and output hash;
- test debug and stripped forms;
- test 32-bit and 64-bit `size_t` independently;
- add negative controls proving that reading the wrong width fails at the correct field;
- add closure fixtures with register and parent-upvalue captures;
- add exact error-offset assertions;
- run the corrected instruction/constant oracle and closure-effect gates;
- retain only aggregate hashes/results for private firmware unless redistribution is authorized.
