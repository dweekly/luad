# Composition Recipes for `luad` Machine Output

This document contains practical command-line recipes for downstream tools, security auditing workflows, and automated pipeline scripts consuming `luad` structured JSON and JSONL streams.

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
luad export firmware/*.luac --format jsonl | jq -r '
  select(.record_type == "constant" and
         (.data.value.value.display? != null)) |
  "[\(.context.input_identity.path)]" +
  "[\(.data.id | sub(":k:[0-9]+$"; ""))] " +
  "\(.data.id): \(.data.value.value.display)"'
```

For large or mixed corpora, cap counted facts independently for each input while
retaining every file's completion or failure record:

```bash
luad export firmware/*.lua --format jsonl --max-facts-per-file 10000 | jq -c '
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

## 3. Finding Globals and Call Sites

Find all `GETGLOBAL` / `SETGLOBAL` lookups and function invocation call sites (`CALL` / `TAILCALL`):

```bash
luad query firmware/main.luac --where "mnemonic == 'GETGLOBAL' or mnemonic == 'CALL'" --format json | \
  jq '.data.matches[] | {id, kind, summary}'
```

Or from a batch JSONL export:

```bash
luad export firmware/*.luac --format jsonl | jq -c '
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
luad export firmware/*.lua --format jsonl | jq -c '
  select(.record_type == "callee") |
  {file: .context.input_identity.path,
   profile: .context.interpretation.profile,
   call: .data.call_id,
   resolution: .data.resolution}'
```

Treat `global-label` and `module-label` as bytecode-derived lookup labels. Apply sink
classification and attacker-control policy in the consuming research layer.

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
`unknown` nodes retain the reason analysis stopped or refused to invent a merge.

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

---

## 7. Reconstructing a Multi-Hop Upvalue Binding Chain

Trace the capture of local variables and parent upvalues into nested closure upvalues across prototype boundaries:

```bash
luad export closures.luac --format jsonl | jq -c '
  select(.record_type == "xref" and .data.relation == "binds") |
  {source: .data.source, target: .data.target, relation: .data.relation}'
```

Output:
```json
{"source":"proto:0/0:local:1","target":"proto:0/0/0:upvalue:0","relation":"binds"}
{"source":"proto:0/0/0:upvalue:0","target":"proto:0/0/0/0:upvalue:0","relation":"binds"}
```

---

## 8. Indexing Batch Exports in an External Database (e.g. SQLite)

Stream fact records directly into an SQLite database for SQL-based graph queries:

```bash
# Initialize tables
sqlite3 luad_index.db "
  CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, sha256 TEXT, byte_length INT);
  CREATE TABLE IF NOT EXISTS instructions (proto TEXT, pc INT, mnemonic TEXT, role TEXT, raw_hex TEXT);
  CREATE TABLE IF NOT EXISTS xrefs (source TEXT, target TEXT, relation TEXT);
"

# Ingest JSONL stream
luad export firmware/*.luac --format jsonl | jq -r '
  if .record_type == "instruction" then
    "INSERT OR REPLACE INTO files VALUES (\x27" + .context.input_identity.path + "\x27, \x27" + .context.input_identity.sha256 + "\x27, " + (.context.input_identity.byte_length|tostring) + ");" +
    " INSERT INTO instructions VALUES (\x27" + (.data.id | sub(":pc:[0-9]+$"; "")) + "\x27, " + (.data.pc|tostring) + ", \x27" + .data.mnemonic + "\x27, \x27" + .data.role + "\x27, \x27" + .data.raw_hex + "\x27);"
  elif .record_type == "xref" then
    "INSERT INTO xrefs VALUES (\x27" + (.data.source|tostring) + "\x27, \x27" + (.data.target|tostring) + "\x27, \x27" + .data.relation + "\x27);"
  else empty end' | sqlite3 luad_index.db
```

---

## 9. Joining Prototype Content Across Firmware Trees

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

Equal `luad-prototype-v1` digests establish equal canonical content. A missing or changed
digest is a triage signal only; it does not by itself prove a behavioral change.
The scheme commits exact constant bytes and is intended for joins within the same Lua
5.1 profile. Equivalent source compiled for stock and LNUM32 number layouts is not
expected to produce equal digests.

---

## 10. Pagination with Context-Bound Cursors

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

## 11. Validating Live Output Against Schemas

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
```
