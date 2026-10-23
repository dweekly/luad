# Composition Recipes for `luad` Machine Output

This document contains practical command-line recipes for downstream tools, security auditing workflows, and automated pipeline scripts consuming `luad` structured JSON and JSONL streams.

---

## 0. Verify a corpus before joining its facts

Use the [export reference consumer](../../examples/export_reader/README.md) to capture
an explicit input set, pin producer/schema/input hashes, and require file/export
completion before returning facts. The filters below are views, not completion checks.
A zero producer exit code alone cannot detect a dropped file or an interrupted pipe.
Keep artifact identity and full interpretation beside every local fact ID.

---

## 1. Extracting SHA-256 Provenance and Input Metadata

To extract the cryptographic identity envelope from any JSON command:

```bash
luad inspect sample.luac --format json | jq '.input_identity'
```

Output:
```json
{
  "sha256": "3e0c03478950bb4db1f0cbdb098cfc8f001e74fa0ec33f8cfb274ffabdc4e6c1",
  "path": "sample.luac",
  "byte_length": 158
}
```

---

## 2. Corpus-Wide Constant and String Search with Prototype Context

Extract all string constants across a batch of precompiled files, capturing parent file and prototype structural path:

```bash
luad export firmware/*.luac --format jsonl --facts constant | jq -r '
  select(.record_type == "constant" and
         (.data.value.value.display? != null)) |
  "[\(.context.input_identity.path)]" +
  "[\(.data.id | sub(":k:[0-9]+$"; ""))] " +
  "\(.data.id): \(.data.value.value.display)"'
```

For large or mixed corpora, cap counted facts independently for each input while
retaining every file's completion or failure record:

```bash
luad export firmware/*.lua --format jsonl --facts prototype,instruction,constant \
  --max-facts-per-file 10000 | jq -c '
  select(.record_type == "file_end") |
  {path, status, is_truncated, emitted_fact_count, available_fact_count}'
```

Mixed firmware trees commonly contain both compiled chunks and plain source. Default
export status is successful when at least one input completes, while the terminal record
keeps coverage explicit:

```bash
luad export --input-list firmware-lua-files.txt --format jsonl |
  jq -c 'select(.record_type == "export_end") |
    {files_processed, files_succeeded, files_skipped, files_failed}'
```

Use `--strict` when any skipped or unreadable input must fail the surrounding shell
pipeline. In either mode, require a terminal `export_end`; its absence indicates an
incomplete stream.

---

For a corpus containing Lua 5.2/5.3/5.5, select structural facts explicitly:

```bash
luad export --input-list mixed-version-files.txt --facts prototype,constant,upvalue
```

Those profiles retain raw words in `inspect` and unverified human text listings without
`--effects`; structured disassembly and unavailable explicit fact families refuse. A default export includes instructions and emits complete per-file
failure accounting for them. Lua 5.1/5.4 disassembly remains available. Always check each
file result alongside the terminal summary.

---

## 3. Finding Globals and Call Sites

Find all `GETGLOBAL` / `SETGLOBAL` lookups and function invocation call sites (`CALL` / `TAILCALL`):

```bash
luad query firmware/main.luac --where "mnemonic == 'GETGLOBAL' or mnemonic == 'CALL'" --format json | \
  jq '.data.matches[] | {id, kind, summary}'
```

Or across an entire corpus using `query --input-list`:

```bash
luad query --input-list firmware-files.txt --where "mnemonic == 'GETGLOBAL' or mnemonic == 'CALL'" | \
  jq -c 'select(.record_type == "query_match") |
    {file: .context.input_identity.path, id: .data.id, kind: .data.kind, summary: .data.summary}'
```

Or from a batch JSONL export:

```bash
luad export firmware/*.luac --format jsonl --facts instruction | jq -c '
  select(.record_type == "instruction" and (.data.mnemonic | startswith("GETGLOBAL") or startswith("CALL"))) |
  {id: .data.id, mnemonic: .data.mnemonic, comment: .data.comment}'
```

---

## 4. Enumerating Symbolic Callees Without Silent Under-Counting

List every call in one chunk, including explicit unresolved reasons:

```bash
luad callees firmware/main.lua --format json | jq -c '
  .data.prototypes[].calls[] |
  {call_id, call_kind, callee_register, resolution}'
```

Survey a firmware tree from the recursive export while retaining file identity:

```bash
luad export firmware/*.lua --format jsonl --facts callee | jq -c '
  select(.record_type == "callee") |
  {file: .context.input_identity.path,
   profile: .context.interpretation.profile,
   call: .data.call_id,
   resolution: .data.resolution}'
```

Treat `global-label` and `module-label` as bytecode-derived lookup labels. Apply sink
classification and attacker-control policy in the consuming research layer.

Select calls directly by a resolved symbolic path or a typed lookup key:

```bash
luad query firmware/main.lua --where 'callee.path contains "luci.sys"' --format json
luad query firmware/main.lua --where 'callee.lookup.key == "execute"' --format json
```

Group explicit unresolved outcomes without treating omitted calls as benign:

```bash
luad export firmware/*.lua --format jsonl | jq -r '
  select(.record_type == "call_relation" and
         .data.resolution.status == "unresolved") |
  .data.resolution.reason' | sort | uniq -c
```

---

## 5. Inspecting Call-Argument Origins Without Embedding Sink Policy

List symbolic callees beside their bounded argument-expression facts using the stable
call instruction ID as the join key:

```bash
luad export firmware/*.lua --format jsonl | jq -c '
  select(.record_type == "callee" or .record_type == "origin" or
         .record_type == "call_relation") |
  {file: .context.input_identity.path,
   call: .data.call_id,
   fact: .record_type,
   data: .data}'
```

Find bytecode expressions that use `MOD` and retain a literal format operand. This is a
retrieval recipe, not a claim that the runtime operation necessarily formats a string:

```bash
luad origins firmware/controller.lua --format json | jq -c '
  .data.prototypes[].calls[] |
  . as $call |
  .argument_window.arguments[]? |
  select(.origin.kind == "binary" and .origin.operator == "MOD") |
  {call: $call.call_id, argument_index, origin}'
```

`CONCAT` and `table` nodes retain their contributing expressions recursively.
`prototype` nodes identify callback closures passed as arguments (`{"kind": "prototype", "prototype": "0/1"}`).
`table-literal` nodes retain constant-key field reconstructions and partial cutoffs (`incomplete: true`).
`alternatives` nodes retain deduplicated reaching definitions across bounded CFG paths (not path feasibility).
`unknown` nodes retain the reason analysis stopped or refused to invent a merge.

Group fixed arguments by their top-level origin shape:

```bash
luad export firmware/*.lua --format jsonl | jq -r '
  select(.record_type == "origin" and .data.argument_window.kind == "fixed") |
  .data.argument_window.arguments[].origin.kind' | sort | uniq -c
```

---

## 5a. Reading a Handler's Input Contract

The question a reader of a dispatch-table codebase arrives with: for a prototype whose entry
point is `function handler(params)`, which keys does it read out of `params`? `luad origins`
answers it directly, because the base of each access is resolved by the dataflow rather than
assumed from the register number.

```bash
luad origins firmware/dispatch.lua
# proto:0/0:pc:0 GETTABLE read  parameter[0]."name"
# proto:0/0:pc:3 GETTABLE read  parameter[0]."type"
# proto:0/0:pc:9 GETTABLE read  parameter[0]."enable"
```

The key set per parameter, per prototype, as machine output:

```bash
luad origins firmware/dispatch.lua --format json | jq -r '
  .data.prototypes[] |
  .proto_id as $proto |
  .parameter_fields[] |
  [$proto, .access, "parameter[\(.parameter_index)]",
   ([.base_path[].value.display] + [.key.value.display] | join("."))] | @tsv'
```

Only accesses whose base resolves to a parameter of that prototype appear. A key read off
another table, or off a register whose parameter was reassigned, is absent — which is the
difference between this and reading a flat constant dump, where adjacent strings invite a
contract to be inferred from proximity rather than evidence.

Keys reached through a non-constant index are not parameter fields. Where such an access
reaches a call argument it is visible as a `dynamic-key` origin, and where the index register
holds only literals the field is named instead:

```bash
luad origins firmware/dispatch.lua --format json | jq -c '
  .. | objects | select(.kind == "unknown" and .reason == "dynamic-key")'
```

---

## 6. Navigating Provable Caller-to-Prototype Relations

List every exact relation and every explicit stop reason without interpreting either as
runtime reachability:

```bash
luad callgraph firmware/controller.lua --format json | jq -c '
  .data.prototypes[].calls[] |
  {call: .call_id, caller, resolution}'
```

Find all bytecode-local callers of one prototype through the shared xref index:

```bash
luad xrefs firmware/controller.lua --to 'proto:0/5' --format json | jq -c '
  .data.entries[] | select(.relation == "calls")'
```

A `unique-global-store` basis means the analyzed chunk contains one compatible literal
global store. It does not claim the global cannot be replaced by code outside the chunk.

### 6a. Who calls this function, and with what arguments?

`luad callers` answers this in one command across a corpus, without joining exports:

```bash
luad callers firmware/luci/sys.luac --proto 0/3 firmware/**/*.luac \
  --link-convention luci-module-setglobal --format json | jq -c '
  .data.callers[] |
  {caller: .caller.path, call: .call_id,
   via: [.bases[].source], first_argument: .argument_window.arguments[0].origin.kind}'
```

Read the answer beside its coverage before treating an empty list as meaningful:

```bash
luad callers firmware/luci/sys.luac --proto 0/3 firmware/**/*.luac \
  --link-convention luci-module-setglobal --format json | jq '
  .data.summary, (.data.files[] | {path, status, counts})'
```

To answer the same question later without re-running analyses, keep a verified export
bundle and ask the reference consumer instead (`luad_export.py callers BUNDLE --target
PATH --proto 0/3`). It gives the same callers, windows and class counts from the bundle's
records alone.

`degraded: true` means a limit or an uncertain index may have hidden callers. The
`unattributed`, `unmapped_label` and `degraded` counts are sites that might still reach
the target; the command lists none of them.

A worked public example uses the pinned LuCI subset in `tests/corpus/luci-23.05` (see its
NOTICE). Compile it with the official Lua 5.1.5 compiler, never executing it, and ask who
calls `luci.sys.init_action`, the function that runs `/etc/init.d` actions:

```bash
luac5.1 -o sys.luac tests/corpus/luci-23.05/modules/luci-lua-runtime/luasrc/sys.lua
luad callers sys.luac --proto 0/28 --format json | jq -c '
  .data.callers[] | {call: .call_id, action: .argument_window.arguments[0].origin.value.value.display}'
```

The seven callers pass the literal actions `enabled`, `enable`, `disable`, `start`,
`stop`, `restart` and `reload`; the second argument is each wrapper's own parameter.
Across modules the strict `luci-module-setglobal` index admits only modules whose
initialization is a bare `module(...)` with plain stores, so most real LuCI libraries
make cross-file answers `degraded`; the command says so rather than returning an empty
list.

---

## 7. Convention-Gated Cross-Chunk Linking (`export --link-convention`)

Connect symbolic call sites across a firmware corpus to their defining LuCI module prototypes using `--link-convention`:

```bash
luad export firmware/*.lua --format jsonl --link-convention luci-module-setglobal | jq -c '
  select(.record_type == "cross_chunk_link") |
  {caller: .data.caller_path,
   call_id: .data.call_id,
   symbol: .data.label_segments | join("."),
   status: .data.status,
   target_artifact: .data.target_artifact.path?,
   target_proto: .data.target_proto?}'
```

Every emitted link fact carries an explicit auditable status:
- `resolved`: exactly one matching module export exists in the corpus.
- `absent`: no matching module export found in the corpus.
- `duplicate`: conflicting definitions exist across multiple artifacts.
- `dynamic`: dynamic module declaration in the corpus prevents proving absence.
- `unsupported`: non-Lua-5.1 chunk or invalid bytecode where convention analysis cannot apply.

Corpus indexing is bounded and order-invariant. Linking is opt-in and does not assert universal reachability or whole-program control flow.

---

## 8. Reconstructing a Multi-Hop Upvalue Binding Chain

Trace the capture of local variables and parent upvalues into nested closure upvalues across prototype boundaries:

```bash
luad export closures.luac --format jsonl --facts xref | jq -c '
  select(.record_type == "xref" and .data.relation == "binds") |
  {source: .data.source, target: .data.target, relation: .data.relation}'
```

Output:
```json
{"source":"proto:0/0:local:1","target":"proto:0/0/0:upvalue:0","relation":"binds"}
{"source":"proto:0/0/0:upvalue:0","target":"proto:0/0/0/0:upvalue:0","relation":"binds"}
```

For a repeated closure instantiation, start from its physical descriptor. The descriptor
has both a `reads` edge to the site-specific parent source and a `binds` edge to the
child slot; the preceding closure owner has its own `binds` edge to that slot:

```bash
luad xrefs closures.luac --from 'proto:0:pc:18' --format json | jq -c \
  '.data.entries[] | select(.relation == "reads" or .relation == "binds")'
```

---

## 9. Passing verified facts to a database

Verify the bundle first with the reference consumer, then use a database driver's bound
parameters to insert retained records. Include full artifact identity and interpretation
in every local-ID key. Never build SQL by interpolating paths, decoded byte strings or
IDs into statements: these are input-derived strings and may contain quotes or arbitrary
bytes. Database schema, persistence and investigation policy belong to the consuming
application; this reference example does not supply a database.

---

## 10. Joining Prototype Content Across Firmware Trees

Create sorted content-identity inventories and join them with ordinary command-line
tools. The path beside each digest is artifact-local evidence, not part of the digest:

```bash
luad export firmware_v1/*.luac --format jsonl | jq -r '
  select(.record_type == "prototype_identity") |
  [.data.digest, .context.input_identity.path, .data.proto_id] | @tsv' |
  sort > firmware_v1.prototypes.tsv

luad export firmware_v2/*.luac --format jsonl | jq -r '
  select(.record_type == "prototype_identity") |
  [.data.digest, .context.input_identity.path, .data.proto_id] | @tsv' |
  sort > firmware_v2.prototypes.tsv

join -t $'\t' -1 1 -2 1 firmware_v1.prototypes.tsv firmware_v2.prototypes.tsv
```

Equal `luad-prototype-v2` digests establish equal canonical content. A missing or changed
digest is a triage signal only; it does not by itself prove a behavioral change.
The scheme commits exact constant bytes and is intended for joins within the same Lua
5.1 profile. Equivalent source compiled for stock and LNUM32 number layouts is not
expected to produce equal digests.

Inventory the interpretation beside each digest before comparing artifacts:

```bash
luad export firmware/*.lua --format jsonl | jq -r '
  select(.record_type == "prototype_identity") |
  [.context.interpretation.profile, .data.scheme, .data.digest,
   .context.input_identity.path, .data.proto_id] | @tsv'
```

---

## 11. Pagination with Context-Bound Cursors

Run paginated queries and fetch consecutive chunks:

Continuation cursors emitted by `luad` include a deterministic checksum of the input,
query, and offset. They detect accidental reuse with a different query or artifact;
they are not authentication tokens. Treat emitted cursors as opaque.

```bash
# Fetch first page of 5 items
PAGE1=$(luad query sample.luac --limit 5 --format json)
echo "$PAGE1" | jq '.data.matches[] | {pc: .pc, mnemonic: .mnemonic}'

# Extract continuation cursor
CURSOR=$(echo "$PAGE1" | jq -r '.data.next_cursor')

# If non-null, request next page using cursor
if [ "$CURSOR" != "null" ]; then
  luad query sample.luac --limit 5 --cursor "$CURSOR" --format json | jq '.data.matches[]'
fi
```

---

## 12. Validating Live Output Against Schemas

Validate live output against canonical JSON Schemas using standard validation tooling:

```bash
luad schema chunk > chunk.schema.json
luad inspect sample.luac --format json | jsonschema -i - chunk.schema.json

luad schema callees > callees.schema.json
luad callees sample.luac --format json | jsonschema -i - callees.schema.json

luad schema callgraph > callgraph.schema.json
luad callgraph sample.luac --format json | jsonschema -i - callgraph.schema.json

luad schema origins > origins.schema.json
luad origins sample.luac --format json | jsonschema -i - origins.schema.json

luad schema export > export.schema.json
luad export sample.luac --format jsonl | while read -r record; do
  printf '%s\n' "$record" | jsonschema -i - export.schema.json
done

luad schema link > link.schema.json
luad export sample.luac --format jsonl --link-convention luci-module-setglobal | while read -r record; do
  if printf '%s\n' "$record" | grep -q '"record_type":"cross_chunk_link"'; then
    printf '%s\n' "$record" | jsonschema -i - link.schema.json
  fi
done
```

---

## 13. Reproducible Firmware Investigation Walkthrough

This recipe uses a public firmware-shaped fixture tree at `tests/fixtures/firmware_tree/` to demonstrate investigating mixed, non-standard, or corrupted Lua artifacts. It is not a redistributed firmware image. Fixture hashes and authority references are in `MANIFEST.json`:

- `dispatcher.lua`: Precompiled OpenWrt bytecode using a non-standard 32-bit `size_t` and `lnum32` integer representation, named `.lua` as typical in router images.
- `system_service.luac`: Stock Lua 5.1 bytecode declaring an 8-byte `size_t`.
- `network_setup.lua`: Plain uncompiled Lua source text.
- `corrupted_module.luac`: Bytecode with a truncated 10-byte header.
- `mips_be_legacy.luac`: An unsupported big-endian layout fixture. Its filename does not establish a target CPU.

### Phase 1: Directory Triage & Streaming Inventory

Triage the mixed directory in a single streaming pass using `luad export`:

```bash
luad export tests/fixtures/firmware_tree/*.lua tests/fixtures/firmware_tree/*.luac --format jsonl
```

Filter for file completion records and summary statistics:

```bash
luad export tests/fixtures/firmware_tree/*.lua tests/fixtures/firmware_tree/*.luac --format jsonl | jq -c '
  if .record_type == "file_end" then
    {file: .path, status: .status, emitted: .emitted_fact_count}
  elif .record_type == "export_end" then
    {processed: .files_processed, succeeded: .files_succeeded, skipped: .files_skipped, failed: .files_failed, total_instructions: .total_instructions}
  else empty end'
```

Output:
```json
{"file":"tests/fixtures/firmware_tree/dispatcher.lua","status":"succeeded","emitted":184}
{"file":"tests/fixtures/firmware_tree/network_setup.lua","status":"skipped","emitted":0}
{"file":"tests/fixtures/firmware_tree/corrupted_module.luac","status":"skipped","emitted":0}
{"file":"tests/fixtures/firmware_tree/mips_be_legacy.luac","status":"skipped","emitted":0}
{"file":"tests/fixtures/firmware_tree/system_service.luac","status":"succeeded","emitted":58}
{"processed":5,"succeeded":2,"skipped":3,"failed":0,"total_instructions":102}
```

This filter displays results; it does not verify stream completeness. An automated
consumer must require one completion record per expected input and a terminal
`export_end`, then reconcile its counts with those records. The equality
`processed == succeeded + skipped + failed` alone cannot detect a dropped file result.
The walkthrough test exercises this check with truncated and missing-record controls.

For automated CI/gate scripts where any invalid or skipped input should stop execution, add `--strict` to exit with status code 1:

```bash
luad export tests/fixtures/firmware_tree/*.lua tests/fixtures/firmware_tree/*.luac --format jsonl --strict
```

### Phase 2: Per-File Inspection and Layout Authority

Inspect individual artifacts to detect their exact runtime dialect, layout declarations, or refusal reasons:

```bash
# 1. OpenWrt embedded bytecode: correctly identified as lua5.1-lnum32 with 32-bit size_t and integral flag 4
luad inspect tests/fixtures/firmware_tree/dispatcher.lua

# 2. Stock desktop Lua 5.1 bytecode: 64-bit size_t, standard float representation
luad inspect tests/fixtures/firmware_tree/system_service.luac

# 3. Plain text source: rejected by name without crashing or misinterpreting as bytecode (exits with code 4)
luad inspect tests/fixtures/firmware_tree/network_setup.lua

# 4. Truncated header: fails with exact offset anchor (exits with code 1)
luad inspect tests/fixtures/firmware_tree/corrupted_module.luac
# error: Parsing failed at offset 10: Unexpected EOF: requested 1 bytes at offset 10, only 0 available

# 5. Unsupported endianness: refused honestly at offset 6 rather than silently misreading operands (exits with code 4)
luad inspect tests/fixtures/firmware_tree/mips_be_legacy.luac
# error: Parsing failed at offset 6: Chunk layout validation failed: Unsupported endianness 0: only Little-Endian (1) is currently supported
```

### Phase 3: Targeted Fact Extraction and Static Auditing

Extract sensitive constants, query global function accesses, and inspect raw instruction words and semantic register effects:

```bash
# 1. Audit string constants across valid chunks:
luad export tests/fixtures/firmware_tree/dispatcher.lua --format jsonl --facts constant | \
  jq -r 'select(.record_type == "constant" and .data.value.value.display?) | .data.value.value.display'

# 2. Locate global variable resolutions:
luad query tests/fixtures/firmware_tree/dispatcher.lua --where "mnemonic == 'GETGLOBAL'" --format json | \
  jq -c '.data.matches[] | {pc: .id, summary: .summary}'

# 3. Disassemble with exact 32-bit instruction words and register read/write effects:
luad disasm tests/fixtures/firmware_tree/dispatcher.lua --raw --effects

# 4. Audit call sites, unresolved targets, and argument origins:
luad callees tests/fixtures/firmware_tree/dispatcher.lua --format json | jq '.data.prototypes[].calls[]'
luad origins tests/fixtures/firmware_tree/dispatcher.lua --format json | jq '.data.prototypes[].calls[].argument_window'
```

### Phase 4: Optional Decompiler Handoff

`luad` reports the input facts needed to select another tool:

- `system_service.luac` declares profile `lua5.1` and layout
  `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0`.
- `dispatcher.lua` declares profile `lua5.1-lnum32` and layout
  `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4`. Selecting stock `lua5.1`
  explicitly for this input is rejected by luad.

These declarations describe serialized fields, not host pointers or CPU architecture.
They do not prove that a particular decompiler accepts the input or recovers correct
source. The required walkthrough tests only luad's facts and refusal behavior.

If you have a decompiler, try it separately with the stock fixture. For example, with
an executable wrapper of your choice that accepts one chunk path and writes source to
stdout:

```bash
DECOMPILER=/absolute/path/to/your/decompiler-wrapper
"$DECOMPILER" tests/fixtures/firmware_tree/system_service.luac > recovered.lua
```

No particular decompiler or version is required to build or test luad, and this recipe
does not install one. Record the actual tool version or revision, binary hash, input
hash, command, and output when reporting an interoperability result. A zero exit status
alone does not prove correct decompilation; validate recovered source against the
fixture's source and behavior before making that claim. No external decompiler
compatibility result is asserted by this walkthrough. For LNUM32, check the selected
tool's explicit profile support; luad's disassembly remains available independently.
