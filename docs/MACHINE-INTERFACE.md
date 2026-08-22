# `luad` machine interface

## Stability warning

`luad` is pre-1.0 and currently has confirmed correctness defects. JSON shapes are schema-governed, but semantic correctness and compatibility are not yet production guarantees. In particular, do not rely on current Lua 5.4 decoded operands, Lua 5.1 embedded-layout handling and closure effects, immediate-dominator results, or `capabilities --evidence` claims until the remediation gates pass.

See [REVIEW-2026-08-22.md](REVIEW-2026-08-22.md), [FIELD-REPORT-TP-LINK-LUA51.md](FIELD-REPORT-TP-LINK-LUA51.md), and [CODING-AGENT-PLAN.md](CODING-AGENT-PLAN.md).

The field report found that 252 of 252 Lua 5.1 files from a TP-Link firmware corpus initially failed because string lengths were read as 64-bit values even when the chunk header declared a 32-bit `size_t`. A peer fix parsed and validated the corpus, but production support remains experimental until the layout, profile, semantic, and regression gates pass in this repository.

## Discovery

Callers should discover the live interface rather than scrape documentation:

```console
luad --help
luad <command> --help
luad capabilities --format json
luad schema capabilities
```

Available schema names in the current schema major version are:

- `chunk`
- `diagnostic`
- `instruction`
- `cfg`
- `xrefs`
- `query`
- `diff`
- `capabilities`

Request another schema major with `--schema-version`. Unsupported versions fail with a usage error.

## Output formats

- `text`: human-oriented; not a stable parsing interface.
- `json`: one complete structured response.
- `jsonl`: streaming records where supported.
- `dot`: Graphviz output where supported, principally CFGs.

Machine consumers should use JSON or JSONL. Human diagnostics are written to stderr. Successful JSON/JSONL stdout should contain no commentary or ANSI styling.

Output ordering is intended to be deterministic for identical input bytes, options, tool version, and parse interpretation. Treat any nondeterminism as a defect.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Command completed successfully |
| 1 | Input was parsed but failed the requested validity condition |
| 2 | Usage, selector, schema, or option error |
| 3 | Input/output failure |
| 4 | Unsupported or ambiguous format |
| 5 | Configured resource limit reached |
| 6 | Internal error |

Do not infer validity from the presence of output alone; inspect both the exit code and structured verdict/diagnostics.

## Input and parse modes

`inspect` documents `-` for stdin; the shared input path may accept it elsewhere, but callers should rely only on command help until stdin support is made a uniform contract.

`--strict` requests fail-fast parsing or stricter validation where exposed. Without `--strict`, parsing is permissive where recovery is implemented. Strict and permissive interpretations can produce different object trees; persistent references must therefore include parse interpretation, not only input SHA-256.

Default resource ceilings are part of `ResourceLimits` and may evolve before 1.0. Limit failures return exit code 5 rather than attempting an unbounded allocation or traversal.

## Stable IDs

Current IDs identify objects within one parsed artifact:

```text
chunk
proto:0
proto:0/2
proto:0/2:pc:37
proto:0/2:block:5
proto:0/2:k:7
proto:0/2:upvalue:1
proto:0/2:local:0
diagnostic:<code>:<target-id>
```

A `StableId` is not globally stable and does not imply equivalence across recompilation. External persistence must pair it with the exact input hash and, in the future, the resolved dialect/profile, validated chunk layout, and parse configuration.

Invalid or absent targets should fail closed. Report any command that silently falls back to another object.

## Commands

### `inspect`

Returns chunk identity, dialect detection, header, prototype tree, diagnostics, and verdict. JSON returns the `chunk` schema.

### `disasm`

Selects a prototype and renders physical instruction words. `--raw`, `--debug-info`, and `--effects` affect text presentation. Check command help and schema before assuming the JSON representation contains semantic effects.

The intended contract distinguishes a physical word from its semantic role. In Lua 5.1, the words following `CLOSURE` that bind child upvalues must be exposed as ordered closure-binding records, not as independently executed `MOVE` or `GETUPVAL` instructions. Until the closure gate passes, current text and effect output can state false register writes for these words.

Constant-bearing operands should ultimately include both their encoded index and a typed, structured resolved value. Text output may add an escaped, bounded preview; machine consumers must not parse that preview in place of the typed value. This contract is planned and is not guaranteed by the current schema.

### `validate`

Runs structural and dialect validation. Current validator correctness remains under remediation. A security-sensitive caller must not treat the existing valid-for-analysis verdict as authoritative.

### `explain`

Currently supports instruction targets. Other target kinds are not a stable contract. The composability proposal recommends eventually making explanation a renderer over a general exact-retrieval primitive.

### `cfg`, `xrefs`, `query`, and `diff`

Expose analysis results with schemas and bounded query pagination. CFG immediate dominators are currently known incorrect. The current query expression syntax is intentionally narrow; unsupported expressions must not be treated as a general programming language.

Capture xrefs are a required extension of the existing fact interface: callers must be able to traverse both parent register/upvalue to child upvalue and child upvalue back to its source binding. A convenience `upvalues` rendering can be added, but it must be a view of the same capture facts rather than a second analysis implementation.

## Planned layout and diagnostic records

Evidence-backed machine output should expose the selected dialect/profile and validated layout, including byte order, declared widths, number-integrality, and how the profile was selected. Vendor constant tags such as LNUM tag 9 must not be reported as stock Lua 5.1 support.

Parse failures should report the deepest known byte offset as the primary location. Prototype paths and enclosing fields are context, not replacements for that offset. The current top-level Lua 5.1 error path has been observed reporting offset 0 for a failure near offset `0x119`; callers should treat current offsets as unreliable until the diagnostic regression gate passes.

### `compile`

The command is visible but intentionally unsupported and exits with code 4. It must not be used to execute untrusted source.

## Pagination and truncation

`query` returns a bounded page, `next_cursor`, and `is_truncated`. Cursors are opaque caller tokens even if the current implementation resembles an integer offset. Callers should not construct or modify them.

Any future bounded export or neighborhood command must expose truncation explicitly and deterministically.

## Capability evidence

The current capability document is useful for discovering implemented surface, but its `supported` statuses and evidence strings are hand-authored and currently overstate verification. Until `gate-release-evidence` is implemented, callers should interpret stock dialects as `experimental` regardless of current output.

No machine consumer should need to infer support from README prose once the evidence-backed manifest is complete.
