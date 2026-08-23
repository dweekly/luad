# Coding-agent plan: trustworthy embedded Lua 5.1 and machine contracts

Status: authoritative forward implementation plan.

Process transition: this is the final broad multi-package sprint. Follow the
[evidence-gated development workflow](DEVELOPMENT-WORKFLOW.md) while bringing it to
one honest clean conclusion. After acceptance, replace this document with a high-level
roadmap and one scoped `NEXT-SPRINT.md`; do not carry this broad format forward.

Read with:

- [Product requirements](../PRD.md)
- [Architecture](../ARCHITECTURE.md)
- [Machine interface](MACHINE-INTERFACE.md)
- [Embedded-firmware requirements](EMBEDDED-FIRMWARE-REQUIREMENTS.md)
- [Release procedure](RELEASING.md)

This plan keeps `luad` a deterministic, stateless fact tool. Humans and external
agents own hypotheses, naming, security judgments, project history, and planning.

## 1. Outcome

The next release line must make the workflows demonstrated on embedded OpenWrt
firmware reliable through the public CLI and machine boundary:

- select stock Lua 5.1 and the exact supported LNUM profile without ambiguity;
- report the selected base dialect, profile, layout, and selection evidence;
- expose typed Lua 5.1 disassembly in text, JSON, and JSONL;
- resolve constants and closure captures without manual index reconstruction;
- reject malformed queries and nonexistent targets instead of returning plausible
  empty or over-broad results;
- produce schema-valid, versioned machine documents;
- process firmware-scale input sets through deterministic batch export;
- preserve the accepted Lua 5.4.8 proof boundary.

No support claim follows from parser presence or an internal library test. A claim
is eligible only after its named public-boundary gate passes from one clean source
revision.

## 2. Non-goals

Do not add any of the following in this plan:

- a decompiler or pseudo-code structurer;
- vulnerability or dangerous-sink classification;
- attacker-control judgments;
- general backward slicing or register provenance;
- a call-graph inference engine;
- recursive firmware-tree diffing;
- persistent projects, annotations, sessions, or overlays;
- a GUI or TUI;
- another dialect family;
- runtime execution of untrusted Lua.

If exact exported facts let an external tool implement one of these workflows,
document the composition pattern instead of adding intelligence to `luad`.

## 3. Starting constraints

1. Treat the LNUM implementation on `fix/lua51-lnum-reachable-from-cli` as a
   candidate, not an accepted profile boundary.
2. Preserve the existing exact Lua 5.4.8 oracle, public-disassembly comparator,
   lossless model, CFG review, and gate harness.
3. Keep every unproved dialect/profile or command surface experimental.
4. Do not depend on the private 252-file firmware corpus for public proof.
   Minimized redistributable fixtures are mandatory; private-corpus results are
   supplemental.
5. Do not commit sensitive firmware keys or credentials. Replace exact findings in
   documentation with a prefix plus SHA-256 unless disclosure is explicitly cleared.
6. Runtime effects remain `Reviewed` or `Unverified`; this plan does not promote
   them to `Fact`.
7. Existing uncommitted work belongs to its author. Do not overwrite or absorb it
   into an unrelated work package.

## 4. Required order

```text
T0 evidence and claim hygiene
  -> L1 exact Lua 5.1 profile selection and identity
       -> checkpoint L1
       -> L2 public Lua 5.1 disassembly and capture facts
            -> checkpoint L2

T0 -> Q1 fail-closed query, xref, and cursor contracts
T0 -> V1 validator operand authority and clean-input null hypothesis

L1 + L2 + Q1 + V1
  -> M1 versioned machine contract
       -> checkpoint M1
       -> W1 deterministic batch export
            -> checkpoint W1

accepted Lua 5.4 gates + V1 + M1
  -> REL54 exact Lua 5.4.8 release evidence

L1 + L2 + Q1 + V1 + M1 + W1 + maintained Lua 5.1 layout evidence
  -> REL51 exact embedded Lua 5.1 release evidence
```

Stop at every checkpoint. Do not begin a downstream package while a required
upstream gate is red.

## 5. Proof discipline

Every work package follows the same sequence:

1. State the exact public claim and what remains experimental.
2. Add the positive public-boundary test and at least one adversarial mutation.
3. Record the red result before implementation.
4. Implement through one owning fact layer; renderers and validators do not
   independently decode raw words.
5. Run the focused test, the package gate, and `bash scripts/check.sh`.
6. Commit the smallest coherent change.
7. Run the gate from a clean revision and preserve its verified artifacts.
8. Report passed, failed, ignored, and missing-test counts plus remaining limits.

A gate must prove both directions:

- invalid or inconsistent input produces the required diagnostic or rejection;
- maintained valid compiler-produced input produces no unjustified diagnostic.

Avoid a command × format × fixture Cartesian test matrix. Schema and envelope tests
cover shape; representative CLI goldens cover serialization; dialect-specific gates
cover semantic content.

## 6. T0 — evidence and public-claim hygiene

### Work

- Keep `EMBEDDED-FIRMWARE-REQUIREMENTS.md` limited to present product constraints;
  this plan remains the only implementation authority.
- Keep one forward plan: this file.
- Keep firmware key material, credentials, and other extracted secrets outside public
  documentation; use bounded placeholders or hashes where an example is necessary.
- Keep README and machine-interface Lua 5.4 claims identical to the evidence required
  by the target-specific release boundary.
- Describe the existing Lua 5.1 closure and constant gates as internal evidence
  until L2 proves their public forms.
- Mark Lua 5.5 disassembly as unverified in-band: text receives one deterministic
  stderr warning; machine output receives a structured evidence tier.
- Replace “content-identical to `luac`” with “normalized typed agreement” where
  `luad` intentionally carries additional facts.

### Acceptance

- Documentation names exactly one forward implementation plan.
- README, `capabilities`, machine-interface documentation, and release evidence do
  not contradict one another.
- No public document contains the complete field-discovered cryptographic key.
- No unsupported dialect/profile is promoted by implication.

## 7. L1 — exact Lua 5.1 profile selection and identity

### Design

Introduce one resolved interpretation record below the CLI:

```text
ResolvedInterpretation
  base_dialect
  patch_or_oracle_version
  profile
  profile_version_or_hash
  validated_layout
  parse_mode
  selection_mode: detected | explicit
  detection_evidence
```

Detection returns this record or a bounded set of candidates. The CLI must not
re-read header bytes to choose a profile. An unambiguous LNUM marker may select the
profile automatically, but the choice and evidence must appear in output. Explicit
override remains available and mismatch diagnostics remain active.

### Required behavior

- `lua5.1` means the stock profile only.
- The supported OpenWrt/eLua profile has a precise name such as
  `lua5.1-lnum32`; do not use an open-ended `lnum` family claim.
- Stock parsing rejects the LNUM marker at the header offset with a profile-specific
  diagnostic and suggested override.
- Explicit LNUM selection rejects a stock header rather than accepting stock values
  as alternate meanings of the profile field.
- Header byte 11 is represented according to the selected profile. For LNUM32 it is
  `sizeof(lua_Integer)`, not an integral-number boolean.
- `Header.lua_integer_size`, `ChunkLayout`, and machine output preserve the declared
  value.
- LNUM tag 9 becomes an exact typed integer with its signed value, raw bytes, vendor
  tag, and stable constant ID. Do not convert it to `f64`.
- `inspect`, `validate`, `disasm`, and errors report the same resolved profile.
- CLI help lists the exact override and explains automatic versus explicit selection.

### Public fixtures and killer probes

Commit a minimized redistributable LNUM32 fixture and a stock 32-bit `size_t`
fixture. At minimum prove:

- automatic CLI detection parses and validates the LNUM32 fixture;
- `--dialect lua5.1-lnum32` parses the same fixture;
- `--dialect lua5.1` rejects it at byte 11;
- the LNUM override rejects the stock fixture;
- changing byte 11 from 4 to a non-profile value fails before prototype parsing;
- removing the profile from JSON makes schema or comparison validation fail;
- changing tag 9 from integer to float makes the typed comparison fail;
- truncation at every byte remains bounded.

Run the private firmware corpus through the CLI, not a library API, and record only
content-addressed aggregate results: expected bytecode/source counts, detected
profile/layout distribution, parse/validation counts, diagnostic counts, tool
revision, and corpus hash.

### Canonical gate

Strengthen `gate-profile-lua51-lnum` so its spec includes the public fixtures,
exact profile identity, CLI tests, cross-profile failures, and corpus-report schema.

### Checkpoint L1

Provide exact text and JSON `inspect` records for stock and LNUM32, both override
mismatch diagnostics, typed tag-9 output, gate artifacts, and the supplemental
252-file aggregate report.

## 8. Q1 — fail-closed query, xref, and cursor contracts

### Work

- Parse query expressions into a documented AST with complete token consumption.
- Validate field/operator/value combinations before evaluation.
- Make `contains` apply its supplied needle exactly; never degrade to a broader
  predicate.
- Resolve query and xref target IDs against the selected chunk before execution.
- Return exit 2 for malformed grammar, unknown fields/operators, invalid operand
  types, and nonexistent targets.
- Define cursor semantics once. Integer cursors in `0..=total` are valid; values
  above `total` and cursors from another response are usage errors. An exact end
  cursor may return a successful empty page.
- Emit invocation diagnostics on stderr without corrupting JSON stdout.

### Killer probes

- A known key prefix matches at least one constant.
- A guaranteed-absent needle returns zero matches.
- Mutating only the needle changes the result set.
- `constant contains` without a value fails.
- Unknown field, unknown operator, trailing tokens, and unbalanced parentheses fail.
- A nonexistent constant, prototype, instruction, or upvalue target fails.
- A cursor one past the known total fails; the exact end cursor succeeds empty.

Implement one table-driven CLI conformance test over command, malformed-input kind,
and expected exit code. Every future selector-oriented command adds rows to this
table.

### Canonical gate

Create one script/spec pair:

```console
bash scripts/gates/gate-cli-selection-contract.sh
```

### Checkpoint Q1

Provide the expression grammar, exit-code table, positive present/absent examples,
and red/green output for every silent-success defect.

## 9. V1 — validator operand authority and clean-input null hypothesis

### Design

Create one dialect-owned opcode/operand specification used by decoding,
disassembly, validation, and analysis. It identifies which encoded fields are
semantically exposed and their types. Raw `a`, `b`, and `c` fields must not be a
public shortcut for consumers.

Do not make the validator depend on text rendering. Both consume the same typed
instruction facts below presentation.

### Work

- Remove blanket Lua 5.4 register validation over `raw.a`.
- Validate only operands classified as registers for that opcode.
- Apply the same authority to jump, companion, and extra-argument instructions.
- Audit other dialect validators for the same generic-field pattern.
- Assign every emitted diagnostic through a typed registry containing code,
  severity, category, explanation, and suggested action.
- Generate the diagnostic catalog from that registry and reject undocumented codes.

### Proof

- Every maintained valid compiler-produced fixture produces zero validation
  diagnostics unless the gate spec names and justifies an exception.
- Include positive and negative large `sJ` values that alias large raw `A` bits.
- Mutate a real register operand out of range and require the exact diagnostic.
- Mutate a non-register field to the same raw bits and require no register diagnostic.
- Run both stripped and debug fixtures.

### Canonical gate

Create:

```console
bash scripts/gates/gate-validation-null-hypothesis.sh
```

### Checkpoint V1

Provide the clean-fixture diagnostic matrix, the `JMP` false-positive reproducer,
the real-register negative control, diagnostic-catalog coverage, and gate artifacts.

## 10. L2 — public Lua 5.1 disassembly and capture facts

### Design boundary

Lua 5.1 must use the same reusable `DisassembledPrototype` family proven for Lua
5.4. The public JSON form is not the raw chunk model. Each physical word records:

- physical PC, raw word, source span, opcode, and semantic role;
- exact encoded fields and typed interpreted operands;
- stable constant, prototype, register, and upvalue references;
- exact typed resolved values plus bounded escaped previews;
- closure-binding companion relationships;
- source line, confidence, provenance, and structured diagnostics.

The text renderer, JSON, JSONL, `explain`, xrefs, and query consume this record or
shared facts below it. They do not independently decode opcode modes.

### Required behavior

- `LOADK`, `GETGLOBAL`, `SETGLOBAL`, `SELF`, and every RK operand retain the
  encoded index and expose the resolved constant.
- `MOVE` renders only its defined Lua 5.1 operands.
- `CLOSURE Bx` resolves to the child’s full stable prototype path.
- The `nups` words following `CLOSURE` remain physical records with role
  `closure_binding`, render as `upvalue[i] <- parent Rn` or
  `upvalue[i] <- parent upvalue[n]`, and never appear as executable moves.
- Closure bindings produce no standalone register writes or CFG nodes.
- Forward and inverse `Binds` xrefs expose parent source to child upvalue without
  positional reconstruction by the caller.
- `explain` includes the same resolved constants and prototype IDs as disassembly.
- Unknown opcodes and invalid references emit structured diagnostics.

### Proof

For every instruction in all maintained stock Lua 5.1 fixtures, recursively require
agreement among:

1. exact `luac 5.1` listing facts;
2. an independent Lua 5.1 reference decoder;
3. the production record exposed through live CLI JSON.

LNUM-specific facts use minimized fixtures and the independently specified profile;
do not claim an official stock oracle for vendor-only tag 9.

Add full text goldens for `hello`, `closures`, and a constant-heavy fixture. Killer
probes remove a resolved constant, change a child prototype path, restore a fake third
`MOVE` operand, turn a binding into an executable write, and remove a `Binds` xref.

### Canonical gate

Create:

```console
bash scripts/gates/gate-public-disasm-lua51.sh
```

Keep the existing closure and resolved-operand gates as internal prerequisites until
this public gate supersedes their claims. Capability and release evidence must depend
on the public gate.

### Checkpoint L2

Provide exact public records for the AES-key load pattern using a redacted value,
the complete three-hop capture chain, representative closure bindings, recursive
fixture comparison totals, every killer-probe rejection, and gate artifacts.

## 11. M1 — versioned machine contract

### Design

Introduce one generic machine envelope rather than bespoke metadata fields:

```text
MachineDocument<T>
  schema_version
  tool_version
  input_identity
  interpretation: ResolvedInterpretation
  analysis_configuration
  data: T
  diagnostics
```

Define response types for collections. `xrefs` schema describes the complete xref
response, not one array element. Do not expose bare arrays as top-level JSON
documents.

JSONL begins with one metadata record, emits typed data records, and ends with a
summary record when completion/truncation state cannot be known in the prologue.
Every record carries a discriminator.

### Work

- Apply the envelope to `inspect`, `disasm`, `validate`, `cfg`, `xrefs`, `query`,
  `diff`, and later `export`.
- Include selected profile/layout and automatic-versus-explicit selection.
- Pin schema major 1 before the first release using it.
- Reject unsupported schema majors with exit 2.
- For cross-dialect diff, report alignment as `incompatible` or `uncertain`; do not
  present instruction correspondence as exact.
- Commit one representative generated example per command/format under
  `docs/examples/`.
- Make documentation examples executable conformance fixtures.

### Proof

- Every advertised schema validates representative live CLI output.
- JSON and every JSONL record parse without stderr/prose contamination.
- Removing or mutating schema version, tool version, input identity, profile, or
  analysis configuration fails comparison.
- An xref element schema cannot be substituted for the response schema.
- Repeated output is byte-deterministic.
- Hostile strings remain escaped and bounded in text and exact in typed machine data.

### Canonical gate

Create:

```console
bash scripts/gates/gate-machine-contract.sh
```

### Checkpoint M1

Provide all schema hashes, representative envelope and JSONL records, schema-validation
results, cross-dialect diff behavior, mutation failures, and gate artifacts.

Do not generate a committed `STATUS.md` containing the commit that contains it.
Publish verified status with release artifacts and expose current evidence through
`luad capabilities --evidence`.

## 12. W1 — deterministic firmware-scale batch export

### Product boundary

Add one composable primitive rather than several intelligent commands:

```console
luad export [FILES...] --format jsonl
luad export --input-list FILE --format jsonl
luad export --input-list - --format jsonl
```

The export contains exact facts already owned by the model: artifact identity,
interpretation, layouts, prototypes, instructions, constants, strings, upvalues,
closure bindings, xrefs, diagnostics, and explicit truncation state. It does not
classify sinks, infer vulnerabilities, name variables, or persist interpretations.

### Required behavior

- Input order and output order are deterministic.
- Each input produces a start record, bounded fact records, and a completion or
  failure record.
- One bad file does not corrupt adjacent records.
- Aggregate exit is nonzero when any input fails; per-input structured status remains
  available.
- Limits apply per input and globally where required.
- Duplicate paths and duplicate content have documented deterministic behavior.
- Plain Lua source and unsupported files produce explicit per-input statuses.
- Profile identity and tool/schema versions appear without a second invocation.

Document shell and `jq` recipes for:

- corpus-wide constant/string search with prototype context;
- finding globals and call sites;
- reconstructing a multi-hop upvalue binding chain;
- indexing exports in an external database;
- comparing exports from two firmware trees externally.

Do not add `search`, `diff-tree`, `provenance`, or sink-classification commands in
this package. Consider a small `strings` view only after export recipes are tested by
real users and show a repeated ergonomic problem.

### Proof

- Batch the maintained fixture corpus in one invocation.
- Include mixed stock, LNUM32, stripped, malformed, source, and unsupported inputs.
- Run the same batch repeatedly and require one output hash.
- Mutate input order and verify the documented ordering rule.
- Enforce output byte limits with explicit continuation/truncation records.
- Demonstrate constant search and capture-chain reconstruction using only exported
  facts and standard external tools.

### Canonical gate

Create:

```console
bash scripts/gates/gate-batch-export.sh
```

### Checkpoint W1

Provide the record schema, deterministic hashes, mixed-input outcome table, bounded
failure examples, documented composition recipes, and gate artifacts.

## 13. Release evidence

Split promotion by exact target. Lua 5.4.8 must not wait on unrelated Lua 5.1 work,
and Lua 5.1 must not inherit Lua 5.4 evidence.

### REL54

`gate-release-lua54-8` closes over the accepted Lua 5.4 oracle, public disassembly,
analysis, losslessness, V1, and M1 gates from one clean revision. Its manifest names
Lua 5.4.8 and only the exact verified command surfaces. Lua 5.1 evidence may be listed
as supplemental but is not a prerequisite for the Lua 5.4 claim.

### REL51

Create an exact embedded Lua 5.1 release gate after L1–W1. Its manifest separately
lists:

- stock Lua 5.1 layouts actually proven;
- the exact LNUM32 profile identifier and profile hash;
- public disassembly, closure, constant, query/xref, machine-contract, and batch
  surfaces proven for each profile;
- supplemental private-corpus identity and aggregate results;
- experimental or unsupported features.

The release manifest schema must contain explicit target profile and layout fields;
do not overload `target_patch_version` with a profile name.

### Release killer probes

- Missing any required public gate rejects promotion.
- An internal-only closure or operand result cannot substitute for L2.
- Cross-revision, dirty, mutated, or stale results reject promotion.
- Lua 5.4 evidence cannot promote Lua 5.1 and vice versa.
- Removing profile/layout identity rejects the Lua 5.1 manifest.
- Unverified query, xref, analysis, or dialect surfaces remain experimental.

## 14. Documentation deliverables

Before each release candidate:

- README states only current evidence-backed claims and links to release artifacts.
- `MACHINE-INTERFACE.md` documents the live envelope and JSONL record sequence.
- README summarizes user-visible tracks and links to this plan; no separate roadmap
  duplicates the implementation sequence.
- The diagnostic catalog contains every emitted code and suggested next action.
- `docs/examples/` is regenerated and verified by M1.
- Embedded-firmware requirements remain current and contain no sensitive corpus values.
- Closed execution plans and absorbed audit narratives are removed rather than kept
  as competing authorities.

## 15. Required checkpoint handoff

Every checkpoint reports:

- exact clean source revision;
- public claim being accepted and limits remaining;
- gate ID, spec path, spec SHA-256, and exact argv;
- enumerated positive and adversarial tests;
- red-before and green-after output;
- compiler, fixture, profile, and corpus-report identities;
- passed, failed, ignored, and missing-test counts;
- result and manifest paths plus hashes;
- exact capability fields changed, or `none`;
- next permitted work package.

“All tests pass” is not a checkpoint handoff.

## 16. Completion criteria

This plan is complete only when:

- the exact LNUM32 profile is reachable and truthfully identified through the CLI;
- malformed and semantically invalid queries/xrefs fail closed;
- valid maintained inputs produce no unjustified validation diagnostics;
- Lua 5.1 public text and machine disassembly satisfy L2;
- closure bindings and constants are directly consumable without manual decoding;
- every advertised machine document validates against its response schema;
- deterministic batch export supports the demonstrated firmware workflow;
- release manifests promote only exact independently proven targets;
- unsupported intelligence and dialect surfaces remain explicitly outside `luad`.
