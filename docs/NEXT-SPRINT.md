# Sprint contract: Corpus-wide query --input-list (R-4)

Lane: product lane. Base: `fd00ecc`.

## Outcome and public claim

One exact query runs across an explicit artifact list with per-input identity and failures retained.

`query --input-list <file|-> --where <expression>` adopts export's batch input and outcome
semantics, preserving order, duplicates, identity, and one result or failure outcome for
every input:

- File lists and standard input (`-`) are accepted via a shared list parser.
- Multi-input streaming JSONL output uses explicit stream framing (`query_start`, `query_end`)
  and per-file framing (`file_start`, `file_end`) containing exact input identities,
  match counts, diagnostic counts, and truncation flags.
- Source files, malformed bytecode, unsupported dialects, and IO errors emit explicit
  skip or failure records with diagnostics. No failed file becomes an apparently clean
  zero-match result.
- Matches and diagnostics retain per-file context and identity.
- Predicate syntax errors fail closed immediately before processing artifacts.

## Allowed boundary

- `crates/luad-cli/src/args.rs`: make `file` optional in `QueryArgs` when `--input-list` is passed; add `input_list` and `strict`.
- `crates/luad-cli/src/main.rs`: extract shared `parse_input_list` helper; implement batch query execution and streaming JSONL records (`QueryStartRecord`, `QueryEndRecord`, `FileStartRecord`, `FileEndRecord`).
- `crates/luad-oracle/tests/test_batch_query.rs`: test file vs stdin input lists, mixed outcomes, duplicates, order preservation, limit truncation, zero matches, malformed predicates, and equivalence to filtering `export` on the firmware fixture tree.
- `docs/MACHINE-INTERFACE.md`, `docs/examples/RECIPES.md`, `README.md`, `CHANGELOG.md`, and this contract: truthful documentation.

## Evidence

Run these focused checks against the candidate:

```console
cargo test -p luad-oracle --test test_batch_query -- --nocapture
bash scripts/check.sh
```

- Assert exact JSONL framing records and stderr summaries.
- Test file lists, stdin lists, duplicates, and order.
- Test that missing files, source text, and invalid bytecode produce explicit failure/skip records, never false zero-match successes.
- Assert equivalence between `query --input-list` matches and filtered `export` instructions over `tests/fixtures/firmware_tree/`.
- Run `bash scripts/check.sh` once on a clean candidate.

## Non-goals and stop condition

No fact-family discovery (R-5), convention linking (R-2), caller substitution (R-3),
or query predicate language additions. Stop when `query --input-list` provides complete
streaming JSONL batch query execution with truthful failure records and all named checks pass.
