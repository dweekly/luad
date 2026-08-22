# `luad`

`luad` is a memory-safe, dialect-aware Rust CLI and library for inspecting, disassembling, validating, and analyzing compiled Lua bytecode.

## Project status

`luad` is a pre-release research tool. It is not currently suitable as the sole basis for security conclusions or production reverse-engineering decisions.

An independent correctness review found critical defects in Lua 5.4 operand decoding, signed-immediate interpretation, opcode modes, immediate-dominator calculation, validation verdicts, and—most importantly—the differential test oracle intended to catch those defects. The current test suite can be green without proving the advertised instruction-level claims.

Read these before relying on results or changing correctness-sensitive code:

- [Correctness review](docs/REVIEW-2026-08-22.md)
- [Embedded Lua 5.1 field report](docs/FIELD-REPORT-TP-LINK-LUA51.md)
- [Remediation roadmap](ROADMAP.md)
- [Coding-agent implementation plan](docs/CODING-AGENT-PLAN.md)

The architecture and product direction remain promising, but all stock-Lua dialects should be treated as **experimental** until their named proof gates pass. The output of `luad capabilities --evidence` is not yet authoritative; replacing hand-written evidence with verified gate results is part of the remediation plan.

## Intended scope

`luad` aims to provide deterministic facts derived from Lua bytecode:

- lossless structural parsing with byte provenance;
- dialect-specific instruction decoding and validation;
- semantic instruction effects;
- control-flow graphs, dominators, cross-references, queries, and diffs;
- stable machine-readable output and schemas;
- bounded behavior on malformed or adversarial input.

Researcher judgment, persistent interpretations, project state, and agent planning belong outside `luad`. See the deferred [composable research workflows proposal](COMPOSABLE_RESEARCH_WORKFLOWS_PROPOSAL.md).

## Implemented dialect surface

This table describes code present in the repository, not verified support status.

| Dialect | Opcode table | Parser/lifter present | Current evidence status |
|---|---:|---|---|
| Lua 5.1 | 38 | Yes | Experimental; embedded layouts, vendor profiles, and closure semantics need gates |
| Lua 5.2 | 40 | Yes | Experimental; proof gates incomplete |
| Lua 5.3 | 47 | Yes | Experimental; proof gates incomplete |
| Lua 5.4 | 83 | Yes | Supported (Lua 5.4.8); verified across proof gates P1–P5 (LUA-5.4.8-PROOF.json) |
| Lua 5.5 | 85 | Yes | Experimental; signed-immediate proof incomplete |
| LuaJIT 2.x | — | No | Planned; not supported |


Real-world testing against 252 Lua 5.1 chunks from TP-Link firmware exposed a host-layout assumption: string lengths were read as 64-bit values even though the chunk header declared a 32-bit `size_t`. A peer patch parsed the entire corpus and also added its LNUM tag, but that vendor extension must be modeled as an explicit profile and the result must pass independent fixtures and semantic gates before Lua 5.1 support is promoted. The same exercise found that Lua 5.1 closure-binding words are currently explained as executable instructions, which can produce false effects and xrefs.

## Build

The repository currently pins its contributor toolchain in `rust-toolchain.toml`. The long-term MSRV has not yet been established independently of that development-toolchain pin.

```console
git clone https://github.com/dew/luad.git
cd luad
cargo build --workspace
```

For the complete contributor check:

```console
bash scripts/check.sh
```

The full differential suite requires exact official Lua compilers. The installer is being hardened with archive checksums as part of the remediation plan:

```console
bash scripts/install_ci_compilers.sh
```

Until the plan is complete, a green local run must not be interpreted as instruction-level proof. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test taxonomy and required gates.

## First use

The repository includes precompiled fixtures, so no Lua compiler is needed for a basic smoke test:

```console
cargo run -q -p luad-cli -- \
  inspect tests/fixtures/precompiled/lua54/hello.luac --summary

cargo run -q -p luad-cli -- \
  disasm tests/fixtures/precompiled/lua54/hello.luac --raw --effects
```

Common commands:

```console
luad inspect chunk.luac
luad disasm chunk.luac --raw --debug-info --effects
luad validate chunk.luac --strict
luad explain chunk.luac 'proto:0:pc:3'
luad cfg chunk.luac --proto 'proto:0' --format dot
luad xrefs chunk.luac --to 'proto:0:upvalue:0' --format json
luad query chunk.luac --where 'opcode == "CALL"' --format json
luad diff old.luac new.luac --semantic --format json
```

The `compile` command is present in the CLI surface but intentionally returns an unsupported-format error; `luad` does not currently execute an external compiler through that command.

## Machine interface

Discover the live command and schema surface instead of scraping human-readable output:

```console
luad --help
luad capabilities --format json
luad schema capabilities
luad schema chunk
luad schema instruction
```

Machine consumers should read [docs/MACHINE-INTERFACE.md](docs/MACHINE-INTERFACE.md), including the current correctness warning, exit codes, stable-ID scope, truncation behavior, and stdout/stderr contract.

## Contributing

- Human contributors: [CONTRIBUTING.md](CONTRIBUTING.md)
- Coding agents: [AGENTS.md](AGENTS.md)
- Architecture and invariants: [ARCHITECTURE.md](ARCHITECTURE.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Release procedure: [docs/RELEASING.md](docs/RELEASING.md)
- Product requirements: [PRD.md](PRD.md)

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at your option.
