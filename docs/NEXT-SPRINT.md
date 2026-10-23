# Honest structured disassembly and export availability

Fresh as of: 2026-10-22. Lane: bounded product family; no target promotion.

## Outcome and decision

Default/instruction export panics for nested Lua 5.2/5.3/5.5 chunks. The same generic
CLI disassembly projection emits opcode_num zero for nonzero encoded opcodes and
silently omits children. Required official-compiler public controls reproduce the
family; Lua 5.1/5.4 positives and explicit structural exports complete. Source authority
is the declared PUC opcode layout (official 5.2.4/5.3.6/5.5.1 lopcodes.h), the existing
5.1/5.4 public disassemblers and the repository's analysis-availability boundary.

Remove the synthesized fallback from structured public disassembly/explanation. This
batch does not implement three new backends. Preserve existing text listings without
--effects on all five PUC versions: the unchanged scalar-authority suite proves useful
constant rendering there. Mark 5.2/5.3/5.5 text explicitly unverified and do not project
it into machine records. Their JSON/JSONL disassembly, instruction effects and all
explanation formats must refuse with exit 4, no stdout and actionable diagnostics.
Structured disassembly remains available on experimental known Lua 5.1 profiles and
Lua 5.4. Raw words/child structure remain in inspect and structural export. Capabilities
must distinguish unverified text from structured disassembly.

## Export contract

Use one explicit allowlist for fact availability: prototype/constant/upvalue on all
currently read PUC profiles; instruction/xref on known Lua 5.1 profiles and Lua 5.4;
callee/origin/call_relation/prototype_identity only on known Lua 5.1 profiles. No unknown
profile silently defaults to any group. Existing opt-in cross-chunk link unsupported
records remain explicit and unchanged.

An explicit --facts selection containing an unavailable family fails that input as a
whole before publishing any of its facts. Default export includes instruction facts,
so 5.2/5.3/5.5 also fail explicitly. Default 5.4 retains its existing available families;
it does not acquire Lua 5.1-only analysis. Do not silently switch a requested selection
to another selection. A per-file failure has its exact identity/interpretation, one
bounded diagnostic with byte evidence, file_end status failed and zero fact counts;
export_end accounts for every input. Preserve existing mixed/strict exit rules and
fact-cap behavior; a zero fact cap must not hide an unsupported request. Selected
prototype,constant,upvalue export remains usable on all five read PUC versions.

## Scope

Production: CLI main.rs shared disassembly, explain and export routing; CI only to
supply the required Lua5.2 compiler to the new reader interaction control; core
capabilities.rs; analysis lib.rs only to correct obsolete availability guidance. Tests:
an ordinary test_export_availability.rs and/or shared oracle helper, existing canonical
machine entrypoints, common/machine_floats.rs, the raw-inspection boundary in
test_analysis_eligibility.rs, and reference-consumer tests. Update
README, machine/recipe/reference-reader docs, current capability example, CHANGELOG,
ROADMAP/checkpoint and the site's target wording where required for honesty. No dialect
parser/lifter, semantic algorithm, schema/envelope, archived gate/candidate or support
status changes. No source compiler bridge, new analysis, persistence or blanket limits.
The pinned implementation provider is unavailable; steward implements directly without
substitution. Use one code/ordinary-test session and one bounded review if compatibility
or availability authority remains a material risk.

## Executable acceptance fixed before production

- Required official Lua 5.1.5/5.2.4/5.3.6/5.4.8/5.5.1 compile nested/decoy and stripped/
  debug public twins; no source/chunk execution. Test actual disasm/explain formats (preserve unverified plain text, refuse
  unavailable structured/effects/explanation views),
  default and all nine explicit family selections, zero/nonzero fact caps and mixed/
  strict batches. Assert exact availability decisions, stdout/refusal behavior, record
  context, diagnostic byte evidence, status/count completion and preserved child facts.
- Retain the previous binary's failing public counterexamples before production edits.
  A structural comparator must reject a deliberately omitted child despite rewritten
  stream counters; availability controls must reject synthetic zero-opcode success.
- Extend existing machine gate entrypoints rather than changing frozen GateSpec lists.
  Float controls continue inspect/constant export and typed raw/class checks on all
  five versions. On unavailable disassembly assert refusal instead of skipping; retain
  schema/typed checks on every available path.
- Retain the unchanged all-version scalar text-rendering assertions. Run focused
  availability/reference-consumer checks, unchanged machine-contract gate,
  one pinned-Rust scripts/check.sh and final Linux/macOS CI. Required compiler/fixture
  absence fails. Record exact compiler identities and every skip count.
- Replay the pinned LuaSocket/Penlight inputs: structural selection completes all20;
  default reports correct full facts or explicit per-profile failures and terminal
  coverage, without panic or fabricated instruction fields. No semantic qualification
  or performance superiority follows from that composition replay.

Stop at accepted, final-CI-green merged code and a neutral checkpoint. Resume caller
inspection/public workflow work after this false-answer family closes.
