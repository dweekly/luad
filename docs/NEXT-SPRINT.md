# Verified export reference consumer

Fresh as of: 2026-10-22. Lane: product; experimental composition, no target promotion.

## Outcome

A consumer currently needs its own decoder-independent glue to distinguish a complete
mixed-corpus export from dropped records, stale joins or a successful broken pipe.
The public recipes display facts but do not supply that reusable check. The private
consumer's fixed-denominator measurement also needs this boundary. Deliver one small
Python 3.11+ reference consumer over existing JSONL, usable with a packaged luad, with
bounded capture and verification. This is a composition claim, not a new VM analysis,
whole-firmware clearance or stable SDK.

## Public boundary

`examples/export_reader/luad_export.py capture --luad BINARY --input-list FILE --out DIR`
creates a new durable bundle. Record the executable hash, version, exact argv and working
directory, generated export schema/hash, requested input inventory (path/hash/length or
explicit read failure), stream hash, exit status and stderr. Hash existing inputs before
and after capture and refuse changed inputs; generated source chunks remain separate
artifacts. Never execute Lua/chunks or use a shell. Retain unsuccessful attempts as such.
Allow explicit existing export fact selection, dialect, strictness, link convention and
per-file fact cap without silently changing them. Capture stdout/stderr, time and input
budgets are explicit. No overwrite of a preexisting bundle.

`verify BUNDLE` validates the pinned, local schema and every bounded JSONL record; it
requires schema major 2 and the known record kinds/closed variants. Refuse duplicate
JSON keys, bare NaN/infinity tokens, invalid encodings, unknown variants and remote
schema references. Match exact input path/hash/size and complete interpretation across
facts; local IDs are never global across artifacts. Require one file_start/file_end
pair for every expected input, one prologue/terminal export record, correct ordering,
no records after termination, and reconciled fact/diagnostic/instruction/status counts.
Unknown profiles/modes may not be silently interpreted as known derived coverage.

Return one deterministic bounded JSON coverage report only after verification finishes.
Separate valid stream completion from skipped/failed files, fact truncation, producer
failure and analysis precision. Preserve diagnostics, nonfinite class/raw fields and
unknown nodes unchanged; never flatten origins or infer reachability/security labels.
The internal factual adapter may retain selected record families under aggregate byte/
record bounds so the next caller workflow can reuse it. It must not publish joined
answers before final stream/manifest verification. Hashes detect mismatches, not hostile
rewriting of an entire self-consistent bundle; executable identity is not attestation.

## Scope and non-goals

Add examples/export_reader/ (reader, pinned Python requirements, focused tests and
indexed README); integrate those tests in existing Linux/macOS contributor CI. Update
README, CONTRIBUTING, machine reference, composition recipes, workflow provider notes,
CHANGELOG and this
checkpoint when their freshness triggers fire. A direct provider-wrapper preflight
repair may remove the rejected redundant effort flag without changing the pinned High
model; record the failure/repair, keep tools/workspace narrowly scoped. No Rust analysis,
export payload/schema changes, dialects, persistent index, source compiler bridge,
caller algorithm, private firmware policy or release promotion belongs in this batch.

## Executable evidence fixed before implementation

- `python -m unittest discover -s examples/export_reader/tests -v` with required
  CARGO_BIN_EXE_luad and official LUAD_LUAC51: generate public source fixtures and capture
  real full/selected/capped/mixed/read-failure streams. Exercise the committed OpenWrt
  authority fixture too; compare known literal/argument facts and exact byte provenance,
  not merely record counts. Compiler/fixture absence fails; no skips.
- Corrupt each authority independently: remove a whole expected file (adjust counters),
  drop/duplicate/reorder completion or fact records, alter context/hash/interpretation,
  invent a record/enum, duplicate local IDs across different artifacts, damage hashes,
  status/fact/diagnostic/instruction totals, numeric payload or schema. Positive twins
  must pass. Same local IDs in separate inputs must remain separate.
- Exercise unusual quoted/Unicode paths, raw string bytes, nonfinite/raw preservation,
  open/unknown origins, fact caps, malformed JSON/depth/line/record/total limits, producer
  early exit/timeout/oversized stderr/stdout, changed inputs and preexisting output.
  Negative controls must reach the actual reader/comparator; no self-declared evidence.
- Run the unchanged machine-contract gate for the producer interaction and one pinned
  Rust `bash scripts/check.sh`; run focused Python checks on Linux/macOS in final CI.
  Record compiler identities, test and skip counts and measured public capture/verify
  time/output bytes. No performance advantage is claimed by this batch.

Use one implementation session for code and ordinary tests, then steward review and
verification. A bounded tool-free independent review is required for malformed-input
resource boundaries and identity/completion assumptions. At most one substantive
correction. Stop at accepted, final-CI-green merged code and a neutral checkpoint;
select one-hop caller inspection/public corpus workflows separately.
