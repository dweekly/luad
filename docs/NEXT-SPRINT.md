# Bounded one-hop caller view

Fresh as of: 2026-10-23. Lane: bounded product outcome (roadmap C, caller inspection); no
target promotion, no new analysis.

## Outcome and decision

"Who calls this function, and with what arguments?" is the question firmware
investigations ask most. Today it needs a full `export --link-convention`, then a
three-way join: same-artifact `call_relation`, cross-artifact `cross_chunk_link`, and
per-site `origin` records keyed by artifact identity plus `call_id`. RECIPES has no recipe
for it across files, and the reference consumer has no join helper. Two oracle tests
(`test_cross_chunk_inverse_*`) already compute the answer with library calls, so the facts
exist and are accepted. This batch adds `luad callers`, a per-call-site, one-hop view that
reorganizes those accepted facts. It adds no resolution rule, origin rule, or link rule.

Evidence boundary, stated in the answer itself: a listed caller is a call site whose
callee an accepted analysis proved to be the target. An empty list means no observed
caller in the analyzed corpus. It does not mean the target is unreachable. Every other
call site is put in exactly one non-caller class, so the residue that could still reach
the target is visible and is never listed or counted as a caller. An answer weakened by a
limit or a dynamic index is marked `degraded`, so it cannot look like a clean negative.

## Interface

```
luad callers TARGET --proto PATH [CORPUS...] [--input-list FILE]
             [--link-convention luci-module-setglobal] [-f text|json|jsonl]
             [--max-callers N] [-d DIALECT] [--strict]
```

- **TARGET** is one file. It must parse as a known Lua 5.1 profile (`lua5.1`,
  `lua5.1-lnum32`, `lua5.1-stock32`) and pass `validate_for_analysis`; otherwise exit 4
  (unsupported) or 1 (invalid) with empty stdout. Exit 3 if it cannot be read.
- **`--proto`** takes `0/1` or `proto:0/1`. An absent or unparsable prototype is exit 2
  with empty stdout.
- **Corpus.** The corpus is TARGET plus the CORPUS files plus the input list, deduplicated
  by path and sorted. Stdin is refused. The existing input-list ceilings apply. The total
  corpus bytes are charged to one aggregate ceiling, checked before analysis (exit 5).
- **Without `--link-convention`**, only same-artifact callers are attempted and the corpus
  is the target alone; extra CORPUS files are exit 2. The answer states that
  cross-artifact attribution was not requested, so an empty list says nothing about other
  files.

## Per-site classification

The analyses run as follows:
- on the target file: callees, call relations, prototype identity, and origins for its
  listed callers;
- on every other corpus file (linking requested): callees and link resolution, plus
  origins when that file contains a listed caller.

A site's *sources* are its call relation (target file only) and its link record, if any;
its callee fact supplies the reasons. Each call site of each analyzed file gets exactly one
class, decided in this order:

1. `caller`: the resolved sources name the target and nothing else.
2. `conflicting`: the resolved sources name the target and something else.
3. `degraded`: a source or the callee carries a limit-class or index outcome. That means
   `analysis-limit`, `path-limit`, the expression/node/window limits, `limit_exceeded`, or
   a link downgraded by a dynamic or limited index.
4. `attributed_elsewhere`: resolved sources name only targets other than the target.
5. `unmapped_label`: the callee is a proven label or lookup (or the relation reports only
   the label), linking was requested, and the convention emitted no link record for it.
   This is documented as "label proven, not mapped by the requested convention", not as
   absence.
6. `unattributed`: everything else (unresolved callee or relation for a non-limit reason;
   link `absent`, `duplicate` or `unsupported`), counted by its first reason in that order.

Per file, the class counts sum to the file's call sites. This invariant is checked.

## Answer

The JSON form is a `MachineDocument<CallersAnswer>` with a new schema, `luad schema
callers`. JSONL emits one record per item: `metadata`, `target`, `caller`*,
`file_coverage`*, `summary`. Every record carries the existing input-identity and
interpretation context. Text is a human rendering of the same data.

**`target`**: input identity, interpretation, prototype id, and the existing
`prototype_identity` digest.

**`caller`**: one record per call site, unique by caller identity plus `call_id`, sorted by
(path, prototype, pc). Fields:
- caller identity and interpretation, prototype, pc, `call_id`, `call_kind`;
- `bases`, a non-empty list of
  `{source: call_relation|cross_chunk_link, basis, label_segments?, evidence}`;
- `argument_window`: that site's `CallArgumentWindow` from the existing origin analysis,
  verbatim. Unknown reasons and open windows are preserved; nothing is summarized.

**`file_coverage`**: one record per corpus input.
- `status` is one of `analyzed`, `failed`, `unsupported_profile` or `unreadable`, with
  that file's bounded diagnostics.
- For an analyzed file: total call sites, and the per-class counts above, with
  `degraded` and `unattributed` broken down by reason. The counts are computed over every
  site even when `--max-callers` truncates the list.

**`summary`**: caller count, callers omitted by truncation, files by status, link
convention or null, `is_truncated`, `coverage_complete` (every corpus file analyzed), and
`degraded` (any site classed degraded, or any index cutoff or dynamic provider), and
`dynamic_providers` naming the providers the index could not admit. A limited index also
emits its existing `ANA-LIMIT-001` diagnostic. There is no field claiming that the negative
is complete.

## Exit

- **0**: every corpus file analyzed, nothing truncated, and no limit-class outcome,
  including an empty caller list. A dynamic-index degradation keeps exit 0 but sets
  `degraded` and emits its diagnostic.
- **1**: any non-target corpus file failed or is unsupported. The full answer is still
  printed with its coverage records, mirroring export's framed mixed rule.
- **5**: `--max-callers` reached (answer printed with `is_truncated: true` and a limit
  diagnostic), any limit-class degraded site (answer printed, `degraded: true`), or the
  aggregate corpus ceiling reached (empty). Callers kept under truncation are the first N
  in sort order.
- **2, 3, 4**: the target or usage conditions above. Machine stdout stays free of
  commentary.

## Scope

- **Production:** the new command and its renderers in `luad-cli` (args, main or a new
  module, text render). A serializable answer type in `luad-analysis` built only from the
  existing `analyze_chunk_callees`, `analyze_chunk_call_relations`,
  `analyze_chunk_origins`, `analyze_chunk_prototype_identities`,
  `build_module_export_index` and `resolve_chunk_links`. Capabilities lists the command as
  experimental. Schema registration and snapshot.
- **Work:** link resolution over the corpus only when requested; call relations on the
  target file; origins only on files that contain a listed caller; callee analysis per
  file for unattributed coverage. The existing per-chunk budgets apply unchanged.
- **Docs:** MACHINE-INTERFACE section, a RECIPES "who calls X" entry, the README command
  table, CHANGELOG.
- **Out of scope:** multi-hop, unions across callers, the reference-consumer extension
  (next batch), non-5.1 analysis, persistence, performance work, and any change to the
  resolution, origin or link rules or to existing schemas.

## Executable acceptance fixed before production

- **Library equivalence.** On the existing cross-chunk fixtures (`mod_svc`,
  `caller_svc_a/b`, `mod_sys`, `mod_sys_dup`, `mod_dynamic`, `caller_missing`, `caller_sys`)
  and on a new required-official-5.1.5 debug/stripped same-artifact source, the command's
  callers must equal two library results:
  - `callers_of(analyze_corpus_links(...))`, matching the target by path *and* sha256,
    plus the same-artifact resolved `call_relation` for the target;
  - each `argument_window` equal to `analyze_chunk_origins` for that `call_id`.

  The same-artifact source has a local function called twice, a same-named decoy in
  another prototype, a call through a captured closure, and a call via a unique global
  store.
- **Classification oracle.** An independent test-side classifier over the library
  facts reproduces every per-file class count, and the counts sum to the call sites. A
  linked cross-file caller appears only as `caller`, never also as `unattributed`.
- **Boundary controls:**
  - a never-called target on a clean corpus gives an empty list with
    `coverage_complete: true`, `degraded: false` and exit 0;
  - the same target with `mod_dynamic` added gives `degraded: true`, names it in
    `dynamic_providers`, and differs from the never-called case;
  - a real limit outcome from official compiler output (a callee path one segment past
    the 32-segment bound, parsed only) gives a `degraded` site, exit 5, and the limited
    site is never listed, while the genuine caller is. A starved capture budget is pinned
    on the library classifier, because a real exhaustion took 74 s in a debug build;
  - a site where call relation and link disagree, in either direction, is classed
    `conflicting` and not listed (pinned on synthetic facts: no compiled shape reaching it
    was found under the current rules);
  - the target given under two spellings of one file is indexed once;
  - a duplicate definition (`mod_sys` plus `mod_sys_dup`) lists no caller for the
    duplicated name and counts it under `unattributed.duplicate`;
  - a dynamic index (`mod_dynamic`) gives downgraded statuses that are counted, not listed;
  - without `--link-convention`, cross-file callers are absent and the summary says so;
  - a Lua 5.4 file in the corpus gives `unsupported_profile` and exit 1, with the rest of
    the answer intact;
  - a garbage file gives `failed`;
  - a 5.2 target gives exit 4 with empty stdout, and a missing prototype gives exit 2;
  - `--max-callers 1` gives exit 5, `is_truncated`, and exactly one caller;
  - debug and stripped twins give identical callers apart from identity;
  - the OpenWrt LNUM32 authority fixture answers on the `lua5.1-lnum32` profile.
- **Comparator negative controls:** dropping a caller, injecting a fabricated caller,
  swapping two sites' argument windows, moving one site between classes, or altering the
  target sha256 is detected.
- **Schema and suites.** The schema snapshot validates every JSON/JSONL output. The
  existing machine-interface schema/golden tests pass. The unchanged M1 gate, one
  pinned-Rust `scripts/check.sh`, and final Linux/macOS CI pass. Required compiler absence
  fails, and skip counts are recorded.
- **Public replay.** On the 20 pinned LuaSocket/Penlight inputs, `callers` for each 5.1
  module's exported prototypes completes with coverage for every input (the 5.2–5.5
  inputs are `unsupported_profile`). This is composition evidence only.

Stop at accepted, final-CI-green merged code and a neutral checkpoint. The reference
consumer's caller context and the three executable workflows follow as separate batches.
