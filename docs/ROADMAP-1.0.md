# The road to a 1.0

Status: qualification obligations for a future stable release, subordinate to
[ROADMAP.md](../ROADMAP.md) for product selection and ordering.

Fresh as of: 2026-10-22.

Adopt this program after outside users establish that the public workflows are useful
and a compatibility promise would help them. An experimental announcement need not
wait for 1.0. This document supplies qualification obligations, not a second product
backlog. [NEXT-SPRINT.md](NEXT-SPRINT.md) must name the exact active claim, paths,
commands, assertions, and stop condition before implementation or qualification.

## Stable release boundary

Preserve the canonical [frozen version-1 boundary](RELEASING.md#frozen-version-1-boundary):

| Qualification order | Compiler/profile | Exact serialized layout |
|---|---|---|
| First | OpenWrt-derived Lua 5.1.5, `lua5.1-lnum32` | `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4` |
| Second | Stock PUC Lua 5.1.5, `lua5.1` | `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0` |

Qualify these independently. No adjacent width, byte order, compiler release, dialect,
or derived analysis inherits support. Changing the future target set or order requires
a separate planning decision and corresponding release-policy and requirements edits.
Package platforms remain Linux x86-64 and macOS ARM64 until their own build/transfer
contracts expand them.

Keep extraction, decompilation, source reconstruction, target execution, security policy,
whole-program feasibility, and persistent research state outside the stable core.
Existing CFG, xref, query, diff, caller, origin, call-relation, and content-identity
surfaces remain experimental unless a dedicated contract qualifies an exact subset.
Structural checks cannot certify safe execution, and comparison cannot certify
behavioral equivalence.

## Qualification sequence

### Public workflows and outside trial

Reference the accepted roadmap evidence for mixed-tree inventory, byte-backed
investigation, caller inspection, and comparison/handoff. Re-run only the interactions
invalidated by the stable candidate. A workflow relying on an experimental derived
fact must identify that boundary and cannot establish a stable analysis claim.

Retain uncoached outside-user results before interface freeze: actual commands,
installation work, correct answers, custom glue, incomplete coverage, and mistakes.
Correct blocking findings and repeat the affected portions. Internal agents and a
successful self-run cannot substitute for outside participants or establish adoption.

### Minimal machine-contract qualification

Enumerate stable commands and export fact families explicitly. Start with the portions
of `inspect`, `disasm`, `validate`, `export`, `capabilities`, `diagnostics`, and `schema`
that the accepted workflows need. Do not stabilize unrelated experimental records
because they share an envelope or schema number.

Qualify identity, validated layout, raw values, byte offsets, stdout/stderr separation,
exit codes, deterministic ordering, selective export, completion, and explicit limits.
Exercise the reference consumer against live schemas and actual output, including
failed inputs, duplicate local IDs across artifacts, unknown variants, and truncation.
A clean exit without terminal stream records cannot establish completion.

Freeze schema-major compatibility, open/closed vocabularies, additive-field policy,
CLI behavior, and any adopted content-ID schemes for 1.x. Keep the numeric compatibility
slots defined in the release procedure: command envelopes and other major-1 families
at major 1, capabilities and streaming export at major 2, and exit meanings 0 through 6.
A schema version alone must never imply qualified semantics.

### Public authority and hostile-input qualification

Require every exposed parser to honor or explicitly refuse declared widths, byte
order, and numeric modes. Preserve the deepest observed failure offset and distinguish
proved header/body contradictions from uncertain causes. Out-of-profile refusal is
sufficient; qualification must not require implementing an unrelated layout.

Authenticate the stock Lua archive and exact OpenWrt revision, ordered patches, numeric
configuration, build recipe, compiler binaries, fixture sources, commands, and hashes.
Correct provenance for every retained fixture. Use applicable official Lua tests,
realistic redistributable modules, stripped/debug pairs, and minimized counterexamples;
private firmware may supplement usefulness evidence but cannot define a format.

Reuse accepted listing comparisons, independent decoders for the facts they expose,
semantic suites, and mutation controls. A listing is not authority for runtime effects
it does not describe. A comparator must reject meaningful corruption; shared production
logic or shared implementation lineage does not establish independent authority.
Do not duplicate prerequisite semantic suites in a downstream release gate.

Audit aggregate allocation, traversal, recursion, diagnostic, and output bounds on all
exposed paths. Seed maintained fuzz targets and retain a bounded smoke run plus an
extended campaign for the exact candidate. Set falsifiable runtime/peak-memory budgets
for small malformed inputs, large instruction vectors, deep prototypes, long strings,
and a representative mixed corpus. Convert failures to public minimized regressions.
Stop for a known false advertised answer, panic, unbounded path, or unexplained timeout.

### Exact target qualification

Merge a target-qualification contract before implementation. Qualify LNUM32 first with
a fresh candidate identity, exact authority/layout, accepted public-read, validator,
diagnostic, retrieval, scalar, machine, export-bound, and hostile-input prerequisites.
Preserve physical closure descriptors and `SETLIST` data words separately from executable
instructions. Prove stock/LNUM profile rejection symmetrically and retain precise
malformed-input offsets.

Pre-register the firmware replay's input inventory and expected behavior, including
open argument/result windows and unaffected callee registers. Record consumer and core
revisions; distinguish corrected stale answers from information loss and source-coverage
changes. Keep private results outside public evidence except sanitized summaries.
This replay supplements the format claim and cannot promote derived analysis.

Qualify stock Lua 5.1.5 separately for its exact declared widths, numeric representation,
constants, stripped/debug prototypes, captures, operands, jumps, and refusal boundaries.
Require clean prerequisites, platform attestations, controls, and zero required skips
for each promotion manifest. Stop at the exact authorized target set.

### Candidate transfer and publication

Verify the accepted workflows and reference consumer from packaged artifacts in a
fresh session on both package platforms. Repeat invalidated trial interactions after
interface changes. Align capabilities, stable/experimental boundaries, schemas, security
policy, release notes, checksums, and evidence with one clean revision.

Reuse the existing packaging, source SBOM, attestations, release bundle, and publication
machinery. Consume accepted bytes without rebuilding; retain accepted evidence in durable
release/PR storage rather than expiring local directories. Require fresh downloads and
walkthroughs before declaring publication complete. Follow the release rollback policy
for partial publication, and issue a new version for corrected published bytes.

## Outside validation

After release, seek independent use across firmware families and Lua tooling tasks.
Review terminology, format claims, build instructions, and surprising output with the
community. Measure recurring questions answered and repeated work removed separately
from trial success and adoption. Return next product decisions to the root roadmap;
this qualification program does not automatically schedule new profiles, analyses,
platforms, or integrations.
