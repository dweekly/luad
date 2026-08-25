# Active sprint: self-identifying JSONL facts

Lane: machine contract. Target: make every streamed fact independently attributable
without requiring hidden file-boundary state.

## Claim and researcher value

Every JSONL data record emitted by `inspect`, `disasm`, `cfg`, `xrefs`, `query`, `diff`,
and recursive `export` will carry the input identity and resolved interpretation needed
to join or audit that record in isolation. A consumer may interleave, filter, shard, or
persist fact lines without retaining the preceding metadata or `file_start` record.

This directly supports firmware-tree workflows where many chunks, profiles, and errors
share one stream and an AI agent or relational loader consumes individual records.

## Contract

A single reusable record context will contain:

- the input path, SHA-256, and byte length when an input artifact was read;
- the resolved base dialect, patch/oracle version, profile, validated layout, and
  selection mode when interpretation succeeded;
- an explicit absence of unavailable identity or interpretation fields on failed-input
  diagnostics rather than invented hashes or profiles.

Every `JsonlDataRecord<T>` will require this context. Export fact records—prototype,
instruction, constant, upvalue, xref, and diagnostic—will use the same generic shape as
single-file JSONL commands. Control records may retain their present framing fields,
but no fact may depend on them for attribution.

The schema major will advance because the new context is required. Canonical schemas,
examples, and recipes will show consumers how to select `.context.input_identity.path`,
`.context.input_identity.sha256`, and `.context.interpretation.profile` directly from
any fact line.

## Acceptance matrix

One table-driven machine-contract suite will exercise every JSONL-producing command and
every export fact variant. It will prove:

- schema validation and deterministic output;
- exact path/hash/length agreement with the source bytes;
- exact interpretation agreement with the corresponding metadata or `file_start`;
- mixed stock Lua 5.1 and LNUM32 export records retain distinct local contexts after
  arbitrary fact-line interleaving;
- deleting metadata and control records leaves every successful fact attributable;
- failed reads and parse failures produce honest diagnostic context;
- removing, swapping, or mutating a fact context is rejected by the comparator or schema.

The same matrix will add structured capability discovery for the `diagnostics` command
and `diagnostics` schema so an agent can find the catalog without reading prose. It will
not redesign the complete command catalog.

## Allowed production paths

- `crates/luad-core/src/envelope.rs`
- `crates/luad-core/src/capabilities.rs`
- JSONL construction in `crates/luad-cli/src/main.rs`
- text capability rendering only as needed for the same discovery fact
- canonical schemas, machine examples, recipes, tests, gate specs, and `CHANGELOG.md`

## Non-goals

This sprint does not add persistent session state, symbolic callees, value origins,
prototype content hashes, a dedicated constant-search command, support-tier promotion,
or a general plugin/command registry. It does not remove JSONL framing records or change
ordinary JSON document envelopes.

## Verification and stop condition

Acceptance requires the focused machine-contract matrix, adversarial context mutations,
the canonical machine-contract and batch-export gates, aggregate repository checks,
green pull-request CI, and a clean merged revision with local `main` equal to
`origin/main`.
