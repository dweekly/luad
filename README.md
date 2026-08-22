# `luad` — Safe, Production-Grade Lua Bytecode Disassembler, Decompiler Foundation & Analysis Toolchain

`luad` is a standalone, memory-safe, dialect-aware CLI and library for inspecting, disassembling, validating, analyzing, and diffing compiled Lua bytecode.

## Features

- **Multi-Dialect Support**:
  - **Lua 5.4.0 – 5.4.8**: Complete 83-opcode table, lossless varint parsing, register use-def traces, VM validation.
  - **Lua 5.5.0 – 5.5.1**: 85 opcodes, `ivABC` layout, string reuse tables, zig-zag signed varints, 4-byte code alignments.
  - **Lua 5.1 – 5.3 & LuaJIT**: In progress.
- **Analysis Capabilities**:
  - **CFG & Dominator Trees**: Basic block partitioning with typed edges (`Fallthrough`, `ConditionalTrue`, `ConditionalFalse`, `UnconditionalJump`, `LoopBack`, `ConditionalSkip`) and immediate dominator ($idom$) calculation.
  - **Cross-References (`xrefs`)**: Relational indexing of registers, upvalues, constants, and sub-prototypes.
  - **Query Engine (`query`)**: Safe, non-evaluating filter queries with limit and cursor pagination.
  - **Bytecode Diffing (`diff`)**: Structural and semantic comparisons.
- **Machine Interface**:
  - JSON and streaming JSONL outputs validated against Draft-07 schemas (`luad schema chunk`).
  - Stable exit codes and structured diagnostics taxonomy.
- **100% Byte Accounting & Memory Safety**:
  - Zero unverified pointers or unsafe memory loads.
  - Truncation-safe at every byte offset.

## Installation & Build

```bash
cargo build --release
```

## CLI Usage

```bash
# Inspect chunk metadata and prototype trees
luad inspect chunk.luac

# Disassemble with raw hex words, debug symbols, and register use/def effects
luad disasm chunk.luac --raw --effects --debug-info

# Validate structural and VM invariants
luad validate chunk.luac

# Explain instructions in context with Lua VM citations (lvm.c)
luad explain chunk.luac 'proto:0:pc:3'

# Control-flow graph in text or Graphviz DOT format
luad cfg chunk.luac --format dot | dot -Tpng -o cfg.png

# Query cross-references to/from an artifact
luad xrefs chunk.luac --to 'proto:0/0:upvalue:0'

# Structured search
luad query chunk.luac --where 'opcode == "OP_CALL"'

# Diff two bytecode chunks
luad diff old.luac new.luac --semantic
```

## License

MIT License.
