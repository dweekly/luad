# Active sprint: per-file export fact bounds

Status: acceptance contract. No downstream roadmap work begins before this sprint is
accepted or explicitly respecified.

## Claim

`luad export` lets a caller bound the number of ordinary fact records emitted for each
input while always preserving deterministic stream framing, diagnostics, and an
explicit per-file truncation result.

The public option is:

```console
luad export FILES... --format jsonl --max-facts-per-file N
```

Counted fact records are `prototype`, `instruction`, `constant`, `upvalue`, and `xref`.
The `export_start`, `file_start`, `diagnostic`, `file_end`, and `export_end` records are
stream-control records and are never suppressed by this bound.

## Researcher value

A human or agent can process a mixed firmware corpus without allowing one large chunk
to monopolize output or hide the status of later inputs. The stream remains usable by
`jq`, a database loader, or another agent even when a file is truncated or malformed.

## Starting evidence

- Accepted implementation revision:
  `232ec500b7fb4f25cdd4caf66a72bc4d96bc8756`.
- Existing foundation gate: `gate-batch-export` at
  `tests/gates/gate-batch-export.json`.
- Existing machine gate: `gate-machine-contract` at
  `tests/gates/gate-machine-contract.json`.
- All dialects and export remain experimental; this sprint does not promote a release
  target.

## Non-goals

- a global cross-file record or byte limit;
- continuation or resume tokens;
- recursive filesystem discovery;
- archive or firmware-image extraction;
- search, sink classification, call-graph inference, or decompilation;
- changes to query pagination;
- promotion of any dialect or profile.

## Public behavior

For each input:

- at most `N` counted fact records appear between its `file_start` and `file_end`;
- facts retain their existing deterministic order and are truncated only at a record
  boundary;
- `file_end` reports `is_truncated`, `emitted_fact_count`, and
  `available_fact_count`;
- `N = 0` emits no counted facts but still emits framing and diagnostics;
- a bound equal to or greater than `available_fact_count` reports
  `is_truncated: false`;
- truncation is a successful bounded result and does not by itself make the aggregate
  exit status nonzero;
- malformed, source, missing, and unsupported inputs retain their structured
  diagnostic, failed status, and aggregate failure behavior;
- omitted `--max-facts-per-file` preserves the unbounded-by-this-option behavior while
  existing parser and allocation limits remain active;
- invalid, negative, or non-integer values are usage errors with exit code 2 and no
  machine records on stdout.

Representative bounded invocation:

```console
$ luad export tests/fixtures/precompiled/lua51/closures.luac \
    --format jsonl --max-facts-per-file 3
```

The stream contains `export_start`, `file_start`, exactly three counted facts,
`file_end` with `is_truncated: true`, and `export_end`, in that order.

## Fixture matrix

| Fixture | SHA-256 | Purpose |
|---|---|---|
| `tests/fixtures/precompiled/lua51/closures.luac` | `62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e` | Recursive prototype, capture, instruction, constant, and xref records. |
| `tests/fixtures/precompiled/lua51_lnum32/hello.luac` | `8376be37ec3042d3b0a87aa39db7d7396fb54ae390abe346d885e1527d23e353` | Explicit vendor-profile identity under a bound. |
| `tests/fixtures/precompiled/lua54/hello.luac` | `a171c4c88ec40b1c871a57a888f66d7a93144e1d742f4071af286c9dc7b93575` | Small debug-bearing control input. |
| `tests/fixtures/precompiled/lua54/hello_stripped.luac` | `9806c9692fd2e55f737c0af5b9cfb96fd543383a2f4decc715c8c30a861ede0f` | Stripped control input. |
| Generated source, malformed bytes, and missing path | Generated and hashed by the acceptance test | Failure records remain visible at zero and nonzero bounds. |

## Independent authority

Acceptance uses a contract-derived stream state machine and reviewed record-type
goldens. It counts serialized public JSONL records rather than calling production
export helpers. Existing semantic gates remain responsible for the correctness of the
facts inside each record.

## Acceptance assertions

- The live CLI satisfies the record bound for every fixture and recursively emitted
  prototype tree.
- `file_end` counts equal the independently counted full stream and bounded prefix.
- Control and diagnostic records survive `N = 0`.
- Later files receive complete framing after an earlier file truncates or fails.
- Repeated invocations produce byte-identical output.
- The live export schema validates every bounded record and rejects missing or
  mistyped truncation fields.
- Text on stderr never contaminates JSONL stdout.

## Killer mutations

The acceptance comparator must reject otherwise-valid streams when a test changes
exactly one of these facts:

- emits `N + 1` counted facts;
- removes a `file_end` after truncation;
- changes `is_truncated` to false;
- changes either fact count by one;
- suppresses a diagnostic at `N = 0`;
- drops the next input after the preceding input reaches its bound;
- changes record ordering between repeated runs;
- removes a truncation field from the export schema.

Each mutation reaches the same comparator or schema validator used for the positive
case and records the expected rejection reason.

## Canonical gate

The independent acceptance author creates one unique gate:

```console
bash scripts/gates/gate-batch-export-bounds.sh ARTIFACT_DIR
```

Its specification is `tests/gates/gate-batch-export-bounds.json` and depends on
`gate-proof-harness`, `gate-machine-contract`, and `gate-batch-export`. It pins every
public fixture above and enumerates every positive and killer-mutation test exactly.

## Role boundaries

The acceptance-test author may change only the sprint acceptance tests, fixture
provenance, new gate specification, and new gate wrapper. The implementation agent may
then change production code, ordinary unit tests, command documentation, schemas, and
examples, but not the frozen acceptance material or shared gate runner.

## Handoff

Acceptance requires:

- the accepted base, frozen acceptance, and candidate implementation commits;
- exact Claude and Antigravity CLI versions and resolved model identities;
- the acceptance-red and implementation-green logs;
- a clean candidate revision;
- canonical gate artifacts with zero failed, ignored, skipped, filtered, or missing
  tests;
- fixture and schema hashes;
- `bash scripts/check.sh` success;
- confirmation that capability tiers remain unchanged.

## Stop condition

Do not begin validator-authority, exact Lua 5.1 release, or other roadmap work until
this sprint passes independent review from one clean revision.
