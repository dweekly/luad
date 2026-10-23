# Reference consumer caller context

Fresh as of: 2026-10-23. Lane: bounded reference-consumer outcome (roadmap C); no core
analysis, schema or convention change.

## Outcome and decision

`luad callers` answers "who calls X" by running the analyses. A consumer that keeps a
verified export bundle should get the same answer offline, from the retained records
alone, with the bundle's identity checks still binding every fact. The roadmap asks for
the reference consumer to gain caller context and to test identity-scoped caller joins,
partial origins and corpus omissions at that boundary. A second implementation over a
different interface (export records instead of in-process facts) is also the strongest
available cross-check of `luad callers`. The existing Rust oracle shares its structure
with production code, and this one does not.

Add `luad_export.py callers BUNDLE --target PATH --proto PROTO`. It answers only after
`verify_bundle` succeeds, and it uses the same six exactly-once classes and the same
precedence as the core contract, rebuilt from records:
- `callee` records list every call site of a file;
- `call_relation` records count for the target artifact only;
- `cross_chunk_link` records count when the bundle was captured with a convention;
- an `ANA-LIMIT-002` diagnostic marks a link cutoff;
- `origin` records supply each listed caller's argument window verbatim.

Every join uses the record context (path, SHA-256, byte length, interpretation) plus the
file-local call id, never the call id alone.

## Refusals and coverage

- **Refused, exit 1, no report:** an unverifiable bundle; a target path absent from the
  inventory or not a successfully exported Lua 5.1 artifact; a missing prototype; a
  bundle without the `callee`, `origin` and `call_relation` families; and any truncated
  file (a capped stream cannot classify every site).
- **Per-file coverage:** non-target inputs that failed, were skipped or use an
  unsupported profile appear in coverage with their status and are not analyzed.
- **Summary:** it states whether cross-artifact search happened, using the captured argv,
  and keeps the empty-list caveat.

## Scope

- **Code:** `examples/export_reader/luad_export.py` (a `callers` subcommand and an
  importable `bundle_callers` function), its tests, README, RECIPES and CHANGELOG.
- **Out of scope:** core changes, new conventions, multi-hop, persistence, and
  dispatch/sink policy.

## Executable acceptance fixed before implementation

- **Agreement:** on the Rust fixture shapes (svc with and without `mod_dynamic`, sys,
  duplicate, same-artifact) and on the vendored LuCI subset, `bundle_callers` over a
  captured, verified bundle must equal `luad callers -f json` on the same files for:
  - the caller set and basis sources;
  - each argument window;
  - the per-file class counts.

  Any disagreement fails the test and is investigated as a defect in one of the two.
- **Boundary controls:**
  - a bundle captured without the required families, a capped bundle, a target outside
    the inventory, a non-5.1 target, and a damaged bundle all refuse;
  - an omitted input is already refused by verification;
  - a Lua 5.2 corpus file appears in coverage and is not analyzed;
  - two artifacts that share a call id do not join;
  - a link to the target's path with a different SHA-256 is not a caller.
- **Negative controls:** removing one origin record or one callee record from an
  otherwise valid bundle (and re-hashing it) is detected as a refusal or a disagreement.
- **Suites:** Black and Ruff, the Python suite with the required compilers, one
  `scripts/check.sh`, and final CI.

Stop at accepted, final-CI-green merged code and a neutral checkpoint.
