# Active sprint: trustworthy mixed-tree export outcomes

Lane: patch. Target: make recursive export safe to compose over firmware trees that mix
supported bytecode, ordinary Lua source, unreadable paths, and unsupported formats.

## Claim and researcher value

An export run that emits at least one complete successful file result will exit
successfully by default, even when other per-input outcomes are skipped or failed. Every
non-success will be named in machine records and stderr, and the final summary will state
succeeded, skipped, and failed counts. A run that exports no input, cannot read its input
list, cannot complete its output stream, or is invoked with `--strict` and has any
non-success will exit nonzero.

This lets researchers use `luad export --input-list ...` under `set -e` and
`set -o pipefail` without treating expected plaintext files as a truncated corpus, while
still making incomplete coverage explicit and auditable.

## Contract

Default export classifies each requested input independently:

- `succeeded`: a complete per-file fact stream was emitted;
- `skipped`: bytes were read but are not a supported bytecode interpretation, with a
  typed diagnostic distinguishing plain Lua source from an unknown or malformed format;
- `failed`: the individual input could not be read. Per-input read failure does not abort
  processing of later inputs.

Every per-file diagnostic and `file_end` carries the exact input path. Parse helpers used
inside batch export will return errors to the batch coordinator without printing a
pathless duplicate. Human stderr emits one path-qualified line per skipped or failed
input and one deterministic terminal summary. JSONL stdout remains uncontaminated.

The terminal `export_end` record will report requested, succeeded, skipped, and failed
counts, with `requested == succeeded + skipped + failed`. Each occurrence in the input
list is processed and counted, including duplicate paths. Default exit status is zero
when at least one input succeeded. `--strict` makes any skipped or failed input nonzero
after the complete framed stream and summary are emitted. Zero successful inputs are
always nonzero. An unreadable list file is a command-level I/O error rather than a
per-input result.

`export_end` is the consumer-visible completeness marker. Its absence means that the
stream is incomplete, including when stdout closes early; a process must never emit a
terminal record before all per-input records have been written.

Plain Lua source detection remains bounded and deterministic. Inputs that resemble Lua
bytecode but do not match a supported interpretation retain a distinct diagnostic from
plain source. This sprint does not claim to distinguish every malformed stock chunk from
every vendor dialect.

## Acceptance matrix

One table-driven test matrix will cover:

- all-success, mixed bytecode/source, mixed bytecode/unknown-format, mixed
  bytecode/missing-path, all-source, all-unknown, and all-missing input lists;
- default and `--strict` exit status for each applicable row;
- exact `file_start`, diagnostic, `file_end`, and `export_end` counts and statuses;
- the terminal count-closure invariant and one exact successful-file fact inventory;
- path presence in every structured and stderr failure report;
- deterministic stdout and stderr across repeated runs;
- valid JSONL framing through the terminal record for every non-stream-I/O case;
- stdin and file-backed input lists, duplicate paths, and paths containing spaces.

Killer controls will flip a mixed-run exit code, erase a failed path, break the terminal
count invariant, remove the terminal summary, classify source as unknown, drop a fact
while retaining framing, and mark an all-skipped run successful. Each mutation must be
rejected against the table-derived expectation.

## Allowed production paths

- export argument parsing and coordination in `crates/luad-cli`
- export envelope fields and generated schemas/examples
- the existing batch-export test module and one focused gate
- indexed machine-interface, recipe, status, PRD, roadmap, and changelog documentation

## Non-goals

This sprint does not add directory discovery, globbing, source compilation, vendor
dialect recovery, content identity, query predicates, security classification, or
persistent state. It does not downgrade malformed recognized bytecode to success or hide
any per-file diagnostic. It does not make a successful process status mean that every
requested input was bytecode.

## Verification and stop condition

Acceptance requires the table and killer controls, canonical batch-export and
machine-interface checks, aggregate repository checks, green pull-request CI, and a clean
merged revision with local `main` equal to `origin/main`. The sprint stops rather than
guessing whether an unsupported byte sequence is a vendor dialect.
