# `luad` machine interface

## Stability warning

`luad` is pre-1.0 and currently has confirmed correctness defects. JSON shapes are schema-governed, but semantic correctness and compatibility are not yet production guarantees. In particular, do not rely on current Lua 5.4 decoded operands, immediate-dominator results, or `capabilities --evidence` claims until the remediation gates pass.

See [REVIEW-2026-08-22.md](REVIEW-2026-08-22.md) and [CODING-AGENT-PLAN.md](CODING-AGENT-PLAN.md).

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

A `StableId` is not globally stable and does not imply equivalence across recompilation. External persistence must pair it with the exact input hash and, in the future, the resolved dialect/profile and parse configuration.

Invalid or absent targets should fail closed. Report any command that silently falls back to another object.

## Commands

### `inspect`

Returns chunk identity, dialect detection, header, prototype tree, diagnostics, and verdict. JSON returns the `chunk` schema.

### `disasm`

Selects a prototype and renders physical instructions. `--raw`, `--debug-info`, and `--effects` affect text presentation. Check command help and schema before assuming the JSON representation contains semantic effects.

### `validate`

Runs structural and dialect validation. Current validator correctness remains under remediation. A security-sensitive caller must not treat the existing valid-for-analysis verdict as authoritative.

### `explain`

Currently supports instruction targets. Other target kinds are not a stable contract. The composability proposal recommends eventually making explanation a renderer over a general exact-retrieval primitive.

### `cfg`, `xrefs`, `query`, and `diff`

Expose analysis results with schemas and bounded query pagination. CFG immediate dominators are currently known incorrect. The current query expression syntax is intentionally narrow; unsupported expressions must not be treated as a general programming language.

### `compile`

The command is visible but intentionally unsupported and exits with code 4. It must not be used to execute untrusted source.

## Pagination and truncation

`query` returns a bounded page, `next_cursor`, and `is_truncated`. Cursors are opaque caller tokens even if the current implementation resembles an integer offset. Callers should not construct or modify them.

Any future bounded export or neighborhood command must expose truncation explicitly and deterministically.

## Capability evidence

The current capability document is useful for discovering implemented surface, but its `supported` statuses and evidence strings are hand-authored and currently overstate verification. Until `gate-release-evidence` is implemented, callers should interpret stock dialects as `experimental` regardless of current output.

No machine consumer should need to infer support from README prose once the evidence-backed manifest is complete.
