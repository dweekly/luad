# Verify a `luad` export before using its facts

This small reference consumer captures a corpus export and verifies its schema,
artifact context, expected file set and completion accounting. Use it when an omitted
file, interrupted pipe or stale identity would turn into a misleading empty answer.
It works with a packaged `luad`; it contains no bytecode decoder and executes no Lua.
Python 3.11+ on Linux/macOS is required. This example and its import API are experimental.

From a repository checkout, create an isolated environment and install the pinned,
wheel-hash-checked dependencies:

```console
python3 -m venv "$HOME/.local/share/luad/export-reader-venv"
"$HOME/.local/share/luad/export-reader-venv/bin/python" -m pip install --require-hashes -r examples/export_reader/requirements.txt
```

Capture a public mixed corpus into a new, durable directory:

```console
mkdir -p artifacts
printf '%s\n' tests/fixtures/firmware_tree/dispatcher.lua tests/fixtures/firmware_tree/system_service.luac tests/fixtures/firmware_tree/network_setup.lua > artifacts/reader-inputs.txt
"$HOME/.local/share/luad/export-reader-venv/bin/python" examples/export_reader/luad_export.py capture --luad /absolute/path/to/luad --input-list artifacts/reader-inputs.txt --out artifacts/reader-bundle
"$HOME/.local/share/luad/export-reader-venv/bin/python" examples/export_reader/luad_export.py verify artifacts/reader-bundle
```

The corpus has two readable chunks and one source file which bytecode export skips.
The report therefore has `stream_complete: true`, `all_files_succeeded: false` and
one skipped file. A valid capped export has `all_available_facts_emitted: false`.
`producer_succeeded` separately reports whether the captured process returned zero.
The consumer exits zero for a verified bundle, including an explicitly incomplete
analysis population; it exits one on refusal and writes no report to stdout. Inspect
these coverage fields when deciding whether the result meets your task's requirements.
`analysis_precision: "not-assessed"` is deliberate: accounting checks do not prove VM
semantics, runtime reachability, or absence of other callers.

Capture forwards explicit `--facts`, `--dialect`, `--strict`, `--link-convention` and
`--max-facts-per-file` settings. For example `--facts origin,call_relation` avoids a
full instruction export. Inspect `capture --help` and `verify --help` for bounds.
An existing bundle directory is refused. Failed attempts retain `capture_complete:
false` and a bounded reason in `capture.json`; they cannot be verified as successes.

The input list uses the producer's line-oriented path representation. Paths may
contain quotes, spaces within a name, and Unicode. Empty, duplicate, stdin, newline,
NUL, or leading/trailing-whitespace paths are refused instead of being normalized
into another file. Only regular files are supported; symlinks may name regular files.

## What the bundle proves

`capture.json` records the producer executable's SHA-256/length/path, exact argv and
working directory, input inventory, limits, exit status, elapsed export time, and hashes
of `schema.json`, `export.jsonl` and `stderr.txt`. The stream records the tool version.
`schema.stderr.txt` retains the separate schema command's bounded stderr. Offline
verification needs neither the original inputs nor the executable; it checks the
recorded inventory against the exported identities and hashes the bytes it consumes.

The reader uses the captured Draft 7 schema, its local definitions and known record
variants. Remote references and schema scope changes are refused. Unknown closed enum
variants, duplicate JSON keys, bare NaN/infinity tokens, invalid UTF-8 and out-of-range
JSON numbers refuse. Canonical `nan`/`inf`/`-inf` class strings, raw bytes and unknown
origin expressions remain unchanged. Cross-field scalar consistency is the producer's
responsibility; schema validity alone does not prove it.

One prologue, one file pair per expected input and a terminal `export_end` are required.
Record context must match that input's exact path, SHA-256, length and full interpretation.
Counters must reconcile with actual facts and diagnostics; truncation must agree with
the producer's declared available count. Resolved link targets must belong to the same
inventory with an identical artifact identity. A file-local stable ID can occur in
several artifacts; that does not join them. Repeated IDs within a fact family in one
file are refused, except relations with multiple edges such as xrefs and links.

The report marks `lua51_analysis_families` separately: callee, origin, parameter-field,
call-relation and prototype-identity exports are experimental on Lua 5.1 profiles;
other currently known PUC profiles do not produce those families through export. All available facts emitted means equality with the producer's
count, not an independently proven enumeration of every possible VM fact. Read the
[core analysis limits](../../docs/MACHINE-INTERFACE.md) before using the facts.

Structured disassembly/instruction export is unavailable on Lua 5.2, 5.3 and 5.5. A default export
reports these parsed inputs as failed with their identity and interpretation, zero facts
and an explicit diagnostic. The reader verifies that complete failure accounting; it
does not turn it into a successful file. Choose `--facts prototype,constant,upvalue`
for a structural inventory across all five currently read PUC versions. Unverified
human text listings remain available without `--effects`; this reader never parses them.

Keep the executable, input list and corpus immutable throughout capture. Before/after
hash checks detect observed changes; they do not create an atomic filesystem snapshot
or detect an adversary that changes a file and restores it between observations.
Hashes bind artifacts, not authorship: an attacker can rewrite a whole bundle and its
manifest consistently. This is not a signature, containment sandbox or attestation.
Choose a trusted `--luad` binary. Capture invokes that binary directly without a shell.

## Callers from a verified bundle

`callers` answers "who calls this prototype?" offline, from a verified bundle alone:

```console
"$HOME/.local/share/luad/export-reader-venv/bin/python" examples/export_reader/luad_export.py callers artifacts/reader-bundle --target /path/to/module.luac --proto 0/3
```

Capture the bundle with the `prototype`, `callee`, `origin` and `call_relation` families
(the default selection includes them for Lua 5.1), and add `--link-convention
luci-module-setglobal` to search other artifacts. A bundle without those families, a
capped bundle, a target outside the inventory or not a Lua 5.1 export, and a missing
prototype all refuse. The answer uses the same exactly-once call-site classes as `luad
callers`: each listed caller carries its bases and verbatim argument window, and each
analyzed file carries class counts that sum to its call sites. Every join uses the full
record context plus the file-local call id. Import `bundle_callers(Path(bundle), target,
proto)` for the same answer as a dictionary. The tests require it to equal `luad callers`
on fixture corpora and on the vendored LuCI subset. An empty list means no observed caller
in the bundle, not unreachable code.

## Bounds and integration

Defaults cap each JSONL line at 8 MiB, a stream at 1 GiB/two million records, nesting
at 96, inputs at 10,000 files/64 MiB each/4 GiB aggregate, retained facts at 64 MiB,
and producer stderr at 1 MiB. Each producer command has a 300-second deadline. Limit
options require positive integers and refuse values above sixteen times their defaults.
The report is capped separately at 16 MiB. Special files refuse before reading; producer
stdout/stderr are drained together and the process group is terminated on interruption
or exhaustion. Counts, bytes and nesting bound verification work; this example is not
an OS memory or CPU sandbox. JSON/schema parsing has Python/library overhead beyond
encoded sizes. A limit hit is a refusal, never a successful partial report.

For a small consumer, import `verify_bundle(Path(bundle), retain={"origin",
"call_relation"})`. It returns `(report, records)` only after complete verification.
Every retained record keeps its context; join on artifact identity **and** full
interpretation plus the local ID, never only a local ID or path. No origin flattening,
endpoint/sink policy, database or multi-hop substitution is included.

Focused verification, with required official Lua 5.1.5 and 5.2.4 compilers already installed:

```console
CARGO_BIN_EXE_luad="$PWD/target/debug/luad" LUAD_LUAC51="$HOME/.cache/luad/lua-tools/bin/luac5.1" LUAD_LUAC52="$HOME/.cache/luad/lua-tools/bin/luac5.2" "$HOME/.local/share/luad/export-reader-venv/bin/python" -m unittest discover -s examples/export_reader/tests -v
```

The tests generate stock Lua 5.1.5 inputs and a Lua 5.2.4 refusal control, consume the
pinned OpenWrt LNUM32 fixture,
and damage actual streams and bundles. They check omitted inputs even after counters
are rewritten consistently, exact raw/argument facts, identity and variant corruption,
limits, changed inputs, producer interruption and explicit coverage. Required tools and
fixtures fail when absent; no case skips. The existing core gates remain the authority
for bytecode interpretation and analysis semantics.
