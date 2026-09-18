# `luad` machine interface

## Stability warning

`luad` is pre-1.0. JSON shapes are schema-governed, but semantic correctness and compatibility are not production guarantees. Every stock dialect remains experimental.

Lua 5.4.8 public disassembly has normalized typed agreement with the official
listing and an independent decoder. JSON command responses use a versioned envelope
with input identity, resolved interpretation, analysis configuration, typed data, and
diagnostics. Lua 5.1 stock and LNUM32 parsing, disassembly, constants, and closure
captures have public-boundary experimental evidence; no Lua dialect is promoted to
the supported tier.

The future [version-1 release boundary](RELEASING.md#frozen-version-1-boundary) keeps
enveloped command JSON and the other major-1 JSON families at schema major 1,
capabilities JSON and streaming JSONL/export at major 2, and the exit-code meanings
below for the 1.x line. This freezes numeric compatibility slots, not every command or
fact currently occupying them. Existing symbolic-callee,
value-origin, call-relation, and related derived-analysis records remain experimental
until the public automation-contract milestone qualifies an exact stable surface.

See the [product roadmap](../ROADMAP.md), [active sprint](NEXT-SPRINT.md), and
[embedded-firmware requirements](EMBEDDED-FIRMWARE-REQUIREMENTS.md).

## Discovery

Callers should discover the live interface rather than scrape documentation:

```console
luad --help
luad <command> --help
luad capabilities --format json
luad diagnostics --format json
luad schema capabilities
luad schema diagnostics
luad schema callees
luad schema callgraph
luad schema origins
luad schema export
```

Available schema names are:

- `chunk`
- `diagnostic`
- `diagnostics`
- `instruction`
- `disasm`
- `validate`
- `cfg`
- `callees`
- `callgraph`
- `origins`
- `xrefs`
- `query`
- `analysis`
- `diff`
- `capabilities`
- `manifest`
- `export`

Each schema family advances independently. Enveloped command JSON and the other
major-1 JSON families remain at major 1; capabilities JSON and streaming JSONL/export
use major 2. Omitting `--schema-version` selects the current major for the requested
schema. An explicit unsupported major fails with a usage error.

Those numeric majors are reserved for the future 1.x contract. Before 1.0, a command or
fact family remains experimental unless its own qualification closes; sharing a major
does not promote its semantics.

Within a schema major, object structure and tagged-union discriminants are closed:
consumers must reject an unknown required structure or variant rather than guessing its
meaning. Fields documented as labels, names, IDs, hashes, schemes, mnemonics, or other
open vocabularies remain strings and must be preserved even when the consumer does not
recognize the value. Typed reason, status, relation, basis, and expression-kind enums are
closed. The published JSON Schema is the authority for which rule applies to a field.

## Output formats

- `text`: human-oriented; not a stable parsing interface.
- `json`: one complete structured response.
- `jsonl`: streaming records where supported.
- `dot`: Graphviz output where supported, principally CFGs.

Machine consumers should use JSON or JSONL. Human diagnostics are written to stderr. Successful JSON/JSONL stdout should contain no commentary or ANSI styling.

Output ordering is intended to be deterministic for identical input bytes, options, tool version, and parse interpretation. Treat any nondeterminism as a defect.

### Stream lifecycle and early termination

Output writes to stdout are checked across all CLI output formats (incremental text, JSON, streaming JSONL, Graphviz DOT, schema dumps, diagnostic catalogs, and shell completions). When downstream consumers close the receiving pipe early (e.g. `head -n 1`, `grep -q`, or an early-exiting subscriber process), `luad` handles `io::ErrorKind::BrokenPipe` (`EPIPE`) by terminating quietly with exit code 0 (`ExitCode::Success`) without printing backtraces or diagnostics to stderr. Non-pipe output write errors (such as disk full or permission errors) return exit code 3 (`ExitCode::IoError`).

Callers consuming streaming JSONL output (e.g. `luad export --format jsonl`) must note that an early-closed or abandoned stream will lack its terminal completion records (`file_end` and/or `export_end`), even though the process terminated cleanly with exit code 0. Consumers that require complete batch verification must assert the presence of terminal records in the stream.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Command completed successfully, or downstream consumer closed output pipe early |
| 1 | Input was parsed but failed the requested validity condition |
| 2 | Usage, selector, schema, or option error |
| 3 | Input/output failure (file read failure, storage write failure, permission, etc.; non-pipe I/O) |
| 4 | Unsupported or ambiguous format |
| 5 | Configured resource limit reached |
| 6 | Internal error |

These numeric meanings are the future 1.x exit-code contract. Command-specific outcome
rules must remain consistent with them before a command enters the stable surface.

Do not infer validity from the presence of output alone; inspect both the exit code and structured verdict/diagnostics.

The following outcome rules apply at the process boundary:

| Outcome | Exit | Stdout |
|---|---:|---|
| Successful command, including a query with zero matches | 0 | Complete output in the requested format |
| Downstream closed output pipe early (`BrokenPipe`) | 0 | Truncated output up to pipe close point; no stderr commentary |
| Parsed input with validation findings | 1 | Complete validation result |
| Parse failure after a format has been recognized, such as a truncated chunk body | 1 | Empty for single-input analysis commands |
| Invalid predicate, selector, option, schema major, or command | 2 | Empty |
| Input/output failure | 3 | Empty, except a framed batch export described below |
| Unsupported, unrecognized, or ambiguous input format | 4 | Empty, except a framed batch export described below |
| Resource ceiling reached | 5 | Empty, except a bounded export that reports truncation |
| Internal defect | 6 | No result may be trusted |

Operational diagnostics use stderr. A mixed `export` follows its separately documented
aggregate rule and emits a terminal record for every requested input.

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

A `StableId` is not globally stable and does not imply equivalence across recompilation.
External persistence must pair it with the exact input hash and resolved interpretation.
Every JSONL fact carries that context directly.

Invalid or absent targets should fail closed. Report any command that silently falls back to another object.

## Lua 5.1 prototype subtree identity

Successful Lua 5.1 export emits one `prototype_identity` fact per prototype in
structural preorder:

```json
{"proto_id":"proto:0/2","scheme":"luad-prototype-v2","digest":"sha256:<64 lowercase hex>"}
```

The digest commits to decoded subtree content, not source identity or behavioral
equivalence. Equal digests under the same scheme mean that the two records have equal
canonical preimages. Unequal digests do not prove different runtime behavior.
Artifact-local `proto_id` remains the navigation key.

The current scheme is `luad-prototype-v2`. Its canonical instruction stream uses the
shared Lua 5.1 physical-role classification: ordinary executable words use
`instruction`, closure capture descriptors use `closure_binding`, and the raw word
following executable `SETLIST C == 0` uses `setlist_extra`. The extra word is encoded
with mnemonic `setlist_extra`, one raw `value` operand containing the complete `u32`,
and no opcode semantics. This prevents opcode-shaped list data from aliasing executable
prototype content.

The v2 preimage starts with ASCII `luad-prototype-v2` and a zero byte. The remaining
encoding, record tags, field order, and exclusions are the common contract specified
below. The normative empty-prototype preimage is 68 bytes:

```text
6c7561642d70726f746f747970652d7632000100000000000000066c7561352e310000020000000000000000000000000000000000000000000000000000000000000000
```

Its identity is:

```text
sha256:a4f418350f217b5477b6dc79e956e7b7b8ba248466fd720955d8324c0f0b0573
```

`luad-prototype-v1` is a compatibility scheme with a frozen encoder and normative
vector. Its role vocabulary is exactly `instruction` and `closure_binding`; a physical
word after `SETLIST C == 0` is encoded according to its low six bits. Consumers that
require the current physical-role semantics use v2.

Integers use
big-endian fixed widths; collection counts and byte-string lengths use `u64`. The tagged
prototype record contains, in order: length-prefixed base dialect `lua5.1`, `numparams`,
the exact Lua 5.1 vararg byte, `maxstacksize`, physical-PC-ordered typed disassembly
records, ordered constants, upvalue count, and ordered tagged raw child digests. Each
instruction contains its role, mnemonic, and ordered typed operands. Resolutions retain
only owner-local indices, target PCs, or metamethod bytes. Lua 5.1 closure capture
descriptors use the `closure_binding` role; synthesized generic upvalue descriptor fields
are not encoded.

The base executable mnemonic vocabulary is exactly:

```text
MOVE LOADK LOADBOOL LOADNIL GETUPVAL GETGLOBAL GETTABLE SETGLOBAL
SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN
CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP
TFORLOOP SETLIST CLOSE CLOSURE VARARG
```

An unknown six-bit opcode uses `OP_UNKNOWN_0xNN`, where `NN` is exactly two lowercase
hexadecimal digits. A closure-binding record appends the exact ASCII suffix
` (binding descriptor)` to its decoded base mnemonic. These strings are digest input,
not display aliases; changing any spelling requires a new identity scheme.

| Tag | Record or variant | Payload |
|---:|---|---|
| `0x01` | prototype | fixed ordered prototype fields |
| `0x02` | instruction | role, mnemonic, operands |
| `0x03` | operand | operand kind, resolution |
| `0x04` | child digest | 32 raw SHA-256 bytes |
| `0x10` | nil constant | none |
| `0x11` | boolean constant | `u8` |
| `0x12` | integer constant | length and exact chunk bytes |
| `0x13` | float constant | length and exact chunk bytes |
| `0x14` | short string | parsed payload bytes |
| `0x15` | long string | parsed payload bytes |
| `0x20` | register operand | `u8` index |
| `0x21` | unsigned immediate | `u64` |
| `0x22` | signed immediate | `i64` two's complement |
| `0x23` | flag operand | `u8` |
| `0x24` | raw operand | `u64` |
| `0x30` | no resolution | none |
| `0x31` | constant resolution | `u64` owner-local index |
| `0x32` | upvalue resolution | `u8` owner-local index |
| `0x33` | local resolution | `u64` owner-local index |
| `0x34` | prototype resolution | `u64` owner-local index |
| `0x35` | jump resolution | `u64` target PC |
| `0x36` | metamethod resolution | length-prefixed name bytes |

String payloads exclude Lua's serialized trailing zero because parsing has already
removed it. Numeric variants and byte widths remain distinct; no value coercion occurs,
so integer and float representations, signed zero, and NaN payloads remain different.
The preimage excludes artifact identity, structural paths, stable IDs, source/debug
metadata, byte offsets, raw words, display text, comments, diagnostics, and confidence.
Any encoding or decoded-fact mapping change that alters the preimage requires a new
scheme identifier; v1 and v2 each retain their defined meaning.

The v1 normative vector below is an empty Lua 5.1 prototype with zero parameters,
the exact vararg byte `0x00`, a maximum stack size of two, and no instructions,
constants, upvalues, or children. The preimage is 68 bytes:

```text
6c7561642d70726f746f747970652d7631000100000000000000066c7561352e310000020000000000000000000000000000000000000000000000000000000000000000
```

Its identity is:

```text
sha256:b5568c02c95499f55261b286ab13e7f86b2beab5b113ee15c7d0d47dbecfea50
```

## Commands

### `inspect`

Returns chunk identity, dialect detection, header, prototype tree, diagnostics, and verdict. JSON returns the `chunk` schema.

### `disasm`

Selects a prototype and renders physical instruction words. `--raw`, `--debug-info`, and `--effects` affect text presentation. Check command help and schema before assuming the JSON representation contains semantic effects.

The contract distinguishes a physical word from its semantic role. In Lua 5.1, the
words following `CLOSURE` that bind child upvalues are ordered closure-binding records,
not independently executed `MOVE` or `GETUPVAL` instructions. The word following an
executable `SETLIST C == 0` is a `setlist_extra` data record with one raw `u32` value,
not an opcode. These companion roles remain experimental evidence and are excluded
from standalone effects, executable CFG nodes, call enumeration, and branch semantics.
Owner instructions link forward to their companions; companion records link backward
to their owner. CFG block bounds remain physical while `instruction_pcs` lists only
executable PCs.

For Lua 5.1 `CLOSURE`, the structured operand's `resolved.id`, instruction `comment`,
text suffix, and `instantiates` xref identify the same owner-relative child prototype.
`Proto(i)` is the encoded child index within the owning prototype; it is not an
artifact-wide prototype identity by itself.

Constant-bearing operands must include both their encoded index and a typed,
structured resolved value. Text may add an escaped, bounded preview; machine
consumers must not parse that preview in place of the typed value. Lua 5.4.8 public
disassembly and experimental Lua 5.1 public disassembly provide this record.

### `validate`

Runs structural and dialect validation. A security-sensitive caller must not treat a valid-for-analysis verdict as authoritative until the exact dialect/profile and relevant analysis-precondition gate are represented in release evidence.

### `explain`

Currently supports instruction targets. Other target kinds are not a stable contract.
Explanation must remain a view over shared typed facts rather than a second decoder.

### `cfg`, `xrefs`, `query`, and `diff`

Expose analysis results with schemas and bounded query pagination. The query grammar
is intentionally narrow and rejects malformed expressions, unsupported operators,
trailing tokens, nonexistent targets, and invalid cursors with a usage error.

`query --where` accepts `and`, `or`, parentheses, `==`, `!=`, and the explicitly listed
`contains` forms. Quoted operands are strings; unquoted `nil`, booleans, and numbers are
typed literals. A quoted `"0"`, numeric `+0.0`, and numeric `-0.0` are distinct. The
complete retrieval vocabulary is:

| Field | Operand | Operators | Matching record |
|---|---|---|---|
| `constant` / `string` | Typed constant | `==`, `!=`; `contains` for a quoted string | Constant |
| `constant.type` | Closed: `nil`, `boolean`, `integer`, `float`, `short-string`, `long-string` | `==`, `!=` | Constant |
| `callee.status` | Closed callee-resolution status | `==`, `!=` | Call instruction |
| `callee.path` | Quoted symbolic path | `==`, `!=`, `contains` | Call instruction |
| `callee.lookup.kind` | Closed: `gettable`, `self` | `==`, `!=` | Call instruction |
| `callee.lookup.key` | Typed constant key | `==`, `!=`; `contains` for a quoted string | Call instruction |
| `callee.reason` | Closed callee unresolved reason | `==`, `!=` | Call instruction |
| `call.reason` | Closed call-relation unresolved reason | `==`, `!=` | Call instruction |
| `call.target` | Quoted existing `proto:...` ID | `==`, `!=` | Call instruction |
| `origin.kind` | Closed origin-expression kind | `==`, `!=` | Call instruction |
| `origin.argument.index` | Nonnegative integer | `==`, `!=` | Call instruction |
| `interpretation.profile` | Closed recognized profile | `==`, `!=` | Interpretation |
| `prototype.digest` | Quoted content digest | `==`, `!=` | Prototype |
| `opcode` / `mnemonic` | Mnemonic | `==`, `!=` | Instruction |
| `effect.read.register`, `effect.write.register`, `effect.read.upvalue`, `effect.write.upvalue` | Nonnegative byte index | `==`, `!=` | Instruction |

The `callee.*`, `call.*`, `origin.*`, and `prototype.digest` fields require a Lua 5.1
interpretation. Using them with another dialect is a usage error, not a zero-match result.
Closed members are discoverable from the corresponding schema. An operand that cannot
be applied to its field is a usage error; it never degrades to an empty or unfiltered
answer. Results use structural prototype order, then physical PC or constant order.

Capture xrefs support both parent register/upvalue to child upvalue and child upvalue
back to its binding evidence. Each Lua 5.1 closure site emits its own closure-owner and
descriptor-instruction `binds` edges. The descriptor's `reads` edge identifies the
site-specific parent register or upvalue, including when one child prototype is
instantiated more than once. A convenience `upvalues` rendering can be added, but it
must be a view of the same capture facts rather than a second analysis implementation.

### `callees`

Emits exactly one fact for every physical Lua 5.1 `CALL` and `TAILCALL`, across the
entire prototype tree. A resolution is a tagged union: `lookup-label` carries a lookup
form (`gettable` or `self`), exact typed constant key, and stable instruction evidence;
`resolved-path` carries a global or module label, ordered path segments, and stable
instruction evidence; `resolved-prototype` carries a directly constructed child
prototype identity and evidence; `unresolved` carries one typed reason.

Lookup labels and global/module paths are symbolic lookup selectors, not runtime object
identities. Module labels require an exactly shaped literal `require` call. Analysis
retains values across CFG joins only when all reachable predecessors agree, tracks
closure bindings across prototype levels, and rejects captures that may be mutated after
closure construction. Dynamic keys, conflicts, open register windows, overwritten
values, unreachable calls, ambiguity, and analysis bounds are reported rather than
omitted.

JSON uses the `callees` schema. JSONL emits self-identifying `callee` facts followed by
a summary. Text is a human rendering of the same typed facts.

### `callgraph`

Emits exactly one caller-to-prototype result for every physical Lua 5.1 `CALL` and
`TAILCALL`. A `resolved` result carries an exact child-prototype path, a closed
resolution basis, and sorted stable instruction evidence. An `unresolved` result carries
a typed stop reason (including `lookup-label-only`) and the available evidence;
constant-key lookup labels and symbolic names without a unique prototype store do not
become edges.

`closure-value` relations retain direct, aliased, CFG-agreed, and safely captured
closure identities. `unique-global-store` relations join a literal global lookup to one
closure-valued store in the analyzed chunk using the register value present at that
store instruction. Multiple stores, non-closure values, conflicts, mutable captures,
open windows, unsupported boundaries, and limits remain explicit.

Resolved records also appear as `calls` xrefs from the call instruction to the child
prototype. JSON uses the `callgraph` schema. JSONL and recursive export use
`call_relation` records. These bytecode-local relations do not assert runtime
reachability, execution order, or immunity from unobserved external mutation.

### `origins`

Emits one call-origin fact for every physical Lua 5.1 `CALL` and `TAILCALL`. A fixed
argument window contains exactly one owner-qualified, evidence-linked expression for
each argument register. A top-dependent argument window is represented explicitly and
never guessed.

Expressions preserve typed literals, parameters, safe closure captures, global and
constant-key field lookups, fixed call results, eager concatenations, table-construction
inputs, and Lua unary and binary operations. `MOD` remains an opcode fact with both
operands; callers may recognize a string-format convention without `luad` asserting
runtime formatting semantics. Conflicting control-flow definitions, dynamic keys,
mutable or ambiguous captures, varargs, aliasing boundaries, unreachable code, and
analysis limits remain distinct machine-visible reasons.

Operands are captured before the writing instruction changes its destination, so an
operation such as `CONCAT A A C` cannot recurse into its own result. JSON uses the
`origins` schema. JSONL emits self-identifying `origin` facts followed by a summary.

## Required layout and diagnostic records

Evidence-backed machine output must expose the selected dialect/profile and validated layout, including byte order, declared widths, number-integrality, and how the profile was selected. Vendor constant tags such as LNUM tag 9 must not be reported as stock Lua 5.1 support.

Parse failures must report the deepest known byte offset as the primary location.
Prototype paths and enclosing fields are context, not replacements for that offset.
Lua 5.1 profile identity and header-field meaning are present in machine output but
remain experimental until an exact target release is promoted.

### `diagnostics`

Discovers and queries the canonical catalog of all production-emittable diagnostic codes
without requiring an input artifact.

```console
luad diagnostics [CODE] --format text|json
```

With no `CODE`, the command emits the complete catalog in ascending bytewise order. With an exact `CODE`, it returns exactly one matching descriptor. An unknown, partial, or case-mismatched code exits with code 2, empty stdout, and stderr `error: Unknown diagnostic code '<CODE>'`.

JSON format returns a top-level `DiagnosticCatalogResponse` (`schema_version`, `tool_version`, `diagnostic_count`, `diagnostics`), described by `luad schema diagnostics`. Text format renders each descriptor across exactly three lines (`<CODE> [<severity>/<category>]`, `  Semantics: <semantics>`, `  Next action: <suggested_action>`).

### `export`

Batch exports firmware artifacts in streaming JSONL format.
`--max-facts-per-file N` bounds the number of counted fact records (`prototype`,
`instruction`, `constant`, `upvalue`, `prototype_identity`, `xref`, `callee`, `origin`,
`call_relation`)
emitted per input file while preserving stream framing, diagnostics, and per-file
truncation metadata.

`--facts FAMILY,...` selects a non-empty subset of those nine counted families. Names
are exact and may appear only once; an unknown, duplicate, or empty name is a usage
error with empty stdout. Control records and diagnostics are always emitted. Omitting
the option preserves the default all-family stream. When selection is explicit,
`export_start.fact_families` records the canonical family order regardless of argument
order; the field is absent from an unfiltered export.

Every data record has a required `context` object. Successful facts carry
`input_identity` and `interpretation`; parse-failure diagnostics carry identity with a
null interpretation; read-failure diagnostics carry null identity and interpretation.
Consumers may discard or interleave control records without losing fact attribution.
`export_start.schema_version` identifies the stream contract.

Each requested input produces exactly one terminal `file_end` status: `succeeded` for a
complete recognized chunk, `skipped` for readable source or unsupported/malformed
formats, and `failed` when input or an internal required export analysis cannot
complete. Duplicate paths are processed per occurrence. Every non-success is
path-qualified in both its records and stderr.
`export_end` is the completeness marker and reports `files_processed`,
`files_succeeded`, `files_skipped`, and `files_failed`, where processed equals the sum of
the three outcomes. Its absence means the stream is incomplete.

Default process status is zero when at least one input succeeds. `--strict` exits
nonzero when any input is skipped or failed, after emitting the complete framed stream.
Zero successful inputs are always nonzero. Stderr ends with a deterministic summary in
the form `N exported, N skipped, N failed`; stdout remains JSONL only.

## Pagination and truncation

`query` returns a bounded page, `next_cursor`, and `is_truncated`. Emitted cursors are
opaque, deterministic tokens bound to the input identity, query expression, and
offset by a checksum. The checksum detects cross-context reuse; it is not an
authentication mechanism. Bare integer offsets and malformed or cross-context tokens
are usage errors with empty stdout.

`export` supports `--max-facts-per-file N` to bound ordinary counted facts per
input while preserving control records (`export_start`, `file_start`,
`diagnostic`, `file_end`, `export_end`). Each `file_end` record reports
`is_truncated`, `emitted_fact_count`, and `available_fact_count`.
`instruction_count` and `export_end.total_instructions` count emitted
`instruction` records, so they can be lower than the number of available
instructions when a fact bound truncates the stream.

When `--facts` is present, availability, emission, truncation, and instruction totals
are relative to the selected families, and the per-file bound is applied after
selection. Analyses for unselected independent families are not eagerly constructed.

## Capability evidence

The capability document is useful for discovering implemented surface. Callers must
interpret every dialect/profile and command surface as `experimental` unless a
target-specific release manifest for the exact tool revision and interpretation
says otherwise.

Presence in a schema or capability feature list is not a version-1 compatibility
promise. In particular, current derived-analysis records remain experimental unless a
later public automation-contract result names and qualifies them.

`diagnostic_catalog` identifies the `diagnostics` command, its schema name, and output
formats so callers can discover the diagnostic authority without parsing help text.

No machine consumer should need to infer support from README prose once the evidence-backed manifest is complete.
