# Coding-agent plan v3: make the proof boundary real

Status: canonical implementation plan after the audit of clean commit `c5201a8` on 2026-08-22.

This plan supersedes earlier gate-completion claims. It preserves useful implementation work, but treats every proof and product gate below as red until the stated adversarial probes pass through the real public boundary.

Read with:

- [Correctness review](REVIEW-2026-08-22.md)
- [Plan review](PLAN-REVIEW-2026-08-22.md)
- [TP-Link Lua 5.1 field report](FIELD-REPORT-TP-LINK-LUA51.md)
- [Machine interface](MACHINE-INTERFACE.md)

## 1. Outcome

Deliver a reliable, composable CLI for Lua reverse engineering. The first defensible release slice is:

- exact, evidence-backed parsing and disassembly for official Lua 5.4.8;
- explicit, evidence-backed Lua 5.1 layout and vendor profiles needed by embedded firmware;
- correct Lua 5.1 closure-capture facts and constant-bearing operands;
- deterministic text and structured output suitable for humans and AI agents;
- no project database, session manager, hypothesis engine, or autonomous analysis inside `luad`.

Lua 5.2, 5.3, and 5.5 remain implemented but experimental. Runtime semantic-effect verification remains a separate project.

## 2. Audit verdict at `c5201a8`

### Useful work to retain

- safer Lua 5.4 opcode conversion and corrected bitfield definitions;
- existing official compiler fixtures and differential-test scaffolding;
- Lua 5.1 `size_t` threading;
- explicit stock-versus-LNUM parser entry points;
- stock rejection of constant tag 9;
- preliminary closure-descriptor recognition;
- typed constant operands in the Lua 5.1 semantic lifter;
- constant-index diagnostics;
- all current safety, malformed-input, determinism, formatting, and lint checks.

### Claims that are not established

- the gate runner does not reject dirty or stale promotion artifacts;
- gate scripts do not use the gate runner or emit result artifacts;
- evidence JSON is not derived from validated gate results;
- the Lua 5.4 oracle still compares operand strings and tolerant floats;
- the immediate-dominator algorithm remains incorrect;
- Lua 5.4 binary round-trip copies captured prototype bytes instead of serializing the model;
- the byte ledger is only a length sum;
- Lua 5.4.8 promotion is hardcoded;
- Lua 5.1 layout support is incomplete and LNUM integers are represented as floats;
- closure descriptors remain semantic instruction rows and lack capture xrefs;
- resolved constants do not reach public disassembly or structured output;
- the private 252-file corpus and public minimized field reproducers have not run through a reproducible gate.

Consequently, C0 and P1-P5 are red. L1-L4 are red, although each contains reusable partial work.

## 3. Rules the coding agent must follow

1. Do not mark a gate complete because a script exits zero. Completion means its acceptance probes distinguish the intended implementation from the shortcuts identified in this plan.
2. Write each adversarial probe first and record its failing output before changing implementation.
3. Tests must call the production verifier, parser, serializer, analyzer, or CLI boundary. Constructing an expected error value in a test is not rejection.
4. A test that searches source text for a function name is never gate evidence.
5. A test that asserts a committed JSON value is `true` is never gate evidence.
6. A proof command must execute at least one explicitly enumerated test. Zero tests, missing fixture sources, missing compilers, and skipped required cases are fatal.
7. Gate results are generated into a caller-supplied temporary directory. Tests must not overwrite committed evidence.
8. Promotion evidence requires a clean worktree, exact source commit, exact compiler binary hash, exact fixture hashes, and validated prerequisite artifacts.
9. A release manifest is assembled from gate results. Capability code must not copy required gate IDs into a completed list.
10. Do not broaden a result from an exact release or profile to a major/minor family.
11. Do not call model agreement independent evidence when both sides use the same decoder, lifter, raw byte cache, or opcode table.
12. Do not label static effects `Fact` until the separate instrumented-runtime project passes. Omit or label them reviewed/unverified.
13. Keep physical bytecode records distinct from executable semantic instructions.
14. Preserve exact encoded values and raw representations. Do not substitute `nil`, coerce vendor integers to floats, or compare floats approximately at a proof boundary.
15. Make the smallest commit that closes one gate. Stop for review after every checkpoint named below.

## 4. Gate artifact contract

Implement a versioned `GateSpec`, `GateResult`, and `ReleaseManifest`.

`GateSpec` must declare:

- gate ID and schema version;
- argv arrays for commands, never a whitespace-split shell string;
- exact test names expected to execute;
- required compiler identities: path policy, exact version, and SHA-256;
- required fixture paths and SHA-256 values;
- required profile/layout identifiers;
- prerequisite gate IDs;
- exact capability fields the gate is allowed to change.

`GateResult` must record:

- canonicalized spec hash;
- source commit and dirty state;
- complete command argv and exit status;
- enumerated tests, passed/failed/ignored counts, and missing expected tests;
- compiler paths, exact version output, and binary hashes;
- fixture and profile hashes;
- platform and architecture;
- start/end timestamps;
- stdout/stderr artifact hashes;
- success derived by the runner, never accepted from input JSON.

`ReleaseManifest` must contain the SHA-256 of every prerequisite result. Its verifier must validate schema, spec hash, source revision, clean state, compiler identity, fixture identity, test enumeration, and prerequisite closure.

Tamper resistance here means that changing a result after assembly invalidates the manifest, and regenerating a manifest requires rerunning the release assembler against valid results. It is not a claim of protection against an attacker who can rewrite the repository and verifier.

Every gate script must:

1. accept or create a temporary result directory;
2. invoke the production gate runner with a committed spec;
3. execute the declared commands;
4. emit a `GateResult`;
5. verify that result before returning success.

## 5. Required order and checkpoints

```text
R0 containment
  -> R1 proof harness
       -> R2 Lua 5.4.8 oracle
       -> R3 CFG and dominators
       -> R4 Lua 5.4.8 model serializer and byte ledger
            -> R5 Lua 5.4.8 promotion

R1 proof harness
  -> F1 Lua 5.1 layouts and profiles
       -> F2 closure bindings
       -> F3 resolved public operands
            -> F4 field evidence
```

Stop for human review after R1, R4, R5, F1, and F3. Do not proceed past a checkpoint merely because tests are green.

## 6. R0 — restore truthful containment

### Work

- Return Lua 5.4.8 to `experimental` until R1-R5 are valid.
- Clear all unvalidated `completed_gates`.
- Mark `tests/evidence/LUA-5.4.8-PROOF.json` non-promoting or remove it.
- Remove claims of verified binary losslessness, dominators, and full P1-P5 proof.
- Make README, machine-interface documentation, and `luad capabilities` agree.
- Keep historical evidence only when clearly labeled self-reported/non-promoting.
- Remove `runtime_semantics_passed: true` from generated evidence unless E1 exists.
- Delete the source-text named-test presence gate.

### Red-first probes

- A temporary supported dialect with no validated release manifest must be rejected.
- A README status differing from the canonical manifest must fail the consistency test.
- No committed evidence file may promote a dialect by its own `status` or boolean fields.

### Acceptance

```console
cargo test -p luad-core capabilities::tests
cargo test -p luad-oracle --test test_cli_e2e capabilities
```

`luad capabilities --evidence --format json` reports no supported stock dialect. Commit R0 separately.

## 7. R1 — build an executable proof harness

### Work

- Replace the current whitespace-split command runner with the artifact contract in section 4.
- Add validation APIs that accept explicit expected revision, cleanliness, compiler hash, fixture hashes, and prerequisite results.
- Add `LUAD_ORACLE_BIN_DIR`; proof specs must not fall back to a generic `luac` on `PATH`.
- Verify exact compiler versions and hashes even when binaries already exist.
- Complete fixture provenance with source archive URL/hash, compiler binary hash, target layout, generator revision, and generation command.
- Make absent fixture sources fatal.
- Make every proof script emit and verify a result artifact.
- Make evidence assembly consume only verified results.

### Required adversarial probes

- `echo success` exits zero but executes zero tests: reject.
- A nonexistent or non-matching test filter: reject.
- One ignored required test: reject.
- A result from another Git commit: production verifier rejects it.
- A dirty result: production promotion verifier rejects it.
- Correct compiler version text but wrong binary SHA-256: reject.
- Correct compiler but wrong patch version: reject.
- Missing compiler: reject before tests run.
- Mutated fixture byte: reject before the gate claim is evaluated.
- Mutated result after manifest assembly: manifest verification fails.
- Changed `success: false` to `true`: verification still fails.

### Gate

```console
bash scripts/gates/gate-proof-harness.sh
```

### Acceptance

The script produces a fresh result in a temporary directory, records a nonzero enumerated test set and zero ignored required tests, and every probe above fails through production code at the intended boundary.

### Checkpoint R1

Hand off the spec, result, manifest, one clean result, and outputs from every adversarial probe. Do not start R2-R5 until reviewed.

## 8. R2 — make the Lua 5.4.8 oracle exact

### Work

- Replace `operands_raw: String` comparison with typed expected operand fields.
- Define the required operand fields from independently transcribed official Lua 5.4.8 opcode modes.
- Compare all fields, including `k`, signed immediates, Ax/extra words, constant indices, and resolved jump destinations.
- Parse constants into exact index, tag, canonical listing token, and decoded value.
- Compare integer/float/string tags exactly.
- Compare the canonical `luac` float token exactly. Prove raw IEEE-754 bits separately through R4.
- Track consumption of every parsed oracle field and reject unused fields.
- Treat unknown actual opcodes, unknown expected mnemonics, missing operands, and extra operands as structured mismatches.

### Required probes

- unknown actual opcode;
- missing and extra operand;
- each relevant operand field mutated independently;
- constant value unchanged but tag changed;
- float listing token changed by one character;
- positive zero changed to negative zero;
- an added oracle field left unconsumed;
- the old bit-15 decoder against every maintained fixture.

### Gate

```console
bash scripts/gates/gate-facts-lua54-8.sh
```

### Acceptance

All maintained Lua 5.4.8 fixtures match the exact compiler with no ignored fields. The result artifact identifies the exact compiler and fixture hashes. The claim remains limited to Lua 5.4.8.

## 9. R3 — correct CFG, dominators, and preconditions

### Work

- Fix immediate-dominator selection: the selected strict dominator must itself be dominated by every other strict dominator.
- Expose a graph-level test boundary independent of Lua decoding.
- Assert complete dominator sets and exact immediate dominators.
- Cover linear, diamond, loop, nested branch, multiple exit, unreachable, and a documented irreducible case.
- Validate registers, constant indices, upvalue indices, register ranges, jump targets, and companion/physical-role invariants before analysis.
- Ensure non-executable physical records cannot become CFG nodes or jump targets.

### Killer probes

- Linear `0 -> 1 -> 2 -> 3` must have idoms `[none, 0, 1, 2]`; the algorithm present at `c5201a8` must fail this test.
- A nested diamond must assert the entire expected dominator tree.
- Mutate one register, constant, upvalue, range, jump, and companion target beyond bounds; each must refuse analysis with a stable diagnostic.

### Gate

```console
bash scripts/gates/gate-analysis-cfg.sh
```

### Acceptance

Exact graph assertions pass independently of bytecode fixtures. Presence of an idom, reachability, or “idom is a valid block” is insufficient.

## 10. R4 — serialize the Lua 5.4.8 model and account for bytes

### Work

- Implement a field-by-field binary writer for the lossless model.
- Remove the prototype-level shortcut that copies `proto.source.raw_hex`.
- Preserve numeric raw bits, exact strings, debug data, instruction/companion words, layout data, diagnosed trailing bytes, and explicitly preserved unknown bytes.
- Implement a byte ledger as non-overlapping classified intervals: recognized field, padding, preserved uninterpreted data, or diagnosed trailing data.
- Validate complete coverage from byte zero to EOF.

### Killer probes

- Clear every aggregate prototype/header raw span after parsing; serialization must remain byte-identical.
- Mutate one modeled instruction or constant; serialized bytes must change at the expected field and reparse to the mutation.
- A writer that returns any aggregate captured raw span must fail a dedicated test.
- Inject an internal one-byte ledger gap: reject.
- Inject an overlap: reject.
- Duplicate coverage with the same total summed length: reject.
- Exercise debug, stripped, nested prototype, embedded NUL, NaN payload, infinity, and signed-zero fixtures.

### Gate

```console
bash scripts/gates/gate-lossless-lua54-8.sh
```

### Acceptance

`parse -> model serialize` is byte-identical without aggregate raw-span shortcuts, `parse -> serialize -> parse` is structurally identical, and every input byte belongs to exactly one ledger interval.

### Checkpoint R4

Hand off a test demonstrating that clearing aggregate raw spans still passes and another demonstrating that mutating a modeled field changes output.

## 11. R5 — promote only validated Lua 5.4.8 scope

### Work

- Run R1-R4 into one temporary result directory on a clean source commit.
- Assemble a release manifest from their validated result hashes.
- Derive capability support and README status from that validated manifest.
- Keep runtime effects explicitly unverified.
- Do not promote any other Lua 5.4 patch or dialect.

### Probes

- Remove any prerequisite result: promotion fails.
- Substitute a passing result from another commit: promotion fails.
- Change one result after assembly: promotion fails.
- Set supported status in a standalone JSON file: runtime capabilities remain experimental.
- Include an effect claim without E1: reject that feature claim without blocking parse/disassembly promotion.

### Gate

```console
bash scripts/gates/gate-release-lua54-8.sh
```

### Acceptance

Only exact Lua 5.4.8 parsing/disassembly claims become supported, and only because the release verifier accepts fresh R1-R4 artifacts.

### Checkpoint R5

Provide the clean commit, compiler identity, fixture hashes, all result hashes, release-manifest hash, exact promoted fields, and remaining unverified features.

## 12. F1 — complete Lua 5.1 layouts and exact profiles

### Work

- Use one immutable `ChunkLayout` for byte order, `sizeof(int)`, `sizeof(size_t)`, instruction width, Lua-number width, integrality, and resolved profile.
- Route every layout-dependent read through layout-aware primitives. No dialect field may choose `read_i32_le`, `read_u64_le`, or equivalent ad hoc.
- Either implement each advertised layout combination or reject it at the exact header byte with a precise diagnostic.
- Replace `Stock32` with layout discovery; 32-bit `size_t` is a layout property, not a semantic profile.
- Define LNUM by a pinned patch source/archive hash and profile ID. Record integer width, signedness, tag semantics, compiler hash, and runtime hash.
- Store tag-9 integers as exact integers or an explicit vendor-integer variant with raw bytes.
- Add CLI profile selection and include resolved profile/layout in text diagnostics and structured output.
- Preserve deepest error byte offset and enclosing prototype/field context separately.

### Required independent fixtures

- official Lua 5.1.5 with 32-bit and 64-bit `size_t`;
- debug and stripped forms;
- each supported byte order and Lua-number representation;
- integer-VM form if advertised;
- a fixture built by the pinned LNUM toolchain;
- stock/LNUM cross-profile negatives;
- representation and resource-boundary strings/counts.

Header-byte mutation alone does not count as a 32-bit fixture. Hand-assembled bytes do not count as the LNUM oracle.

### Killer probes

- Run a real 32-bit fixture through the full parser, not only header parsing.
- Feed the same field bytes under opposite byte order and prove the decoded value changes correctly.
- Parse tag 9 under stock: fail at the tag offset.
- Parse the pinned LNUM fixture under its exact profile: preserve the integer and raw bytes.
- Parse the LNUM fixture with a different vendor profile: fail.
- Change `integral_flag` without changing number bytes: the parser must follow or reject the declared representation, never silently read a float.

### Gates

```console
bash scripts/gates/gate-layout-lua51-stock.sh
bash scripts/gates/gate-profile-lua51-lnum.sh
```

### Checkpoint F1

Provide compiler/runtime hashes, profile specification, fixture provenance, layout matrix, and cross-profile failure output.

## 13. F2 — model closure bindings as facts, not instructions

### Work

- Preserve every physical word and PC with an explicit role: executable, closure binding, companion, or preserved unknown.
- Parse each `CLOSURE` group into ordered `CaptureBinding` facts containing closure PC, descriptor PC, child prototype, child upvalue slot, and source kind.
- Distinguish parent-register capture from parent-upvalue capture.
- Produce semantic instructions only for executable words. Consumers needing physical PCs must use a PC map rather than vector indexing.
- Exclude descriptors from standalone reads/writes, explanations, CFG nodes, query instruction results, and executable disassembly rows.
- Render descriptors only as annotations such as `upvalue[0] <- parent R1`.
- Add capture-specific forward and inverse xref relations.
- Validate child prototype index, descriptor count/opcode, source register/upvalue range, truncation, overlapping groups, and jumps into descriptors.

### Killer probes

- The existing closures fixture must no longer print descriptor rows as `MOVE` or `GETUPVAL`.
- A descriptor contributes zero standalone effects and no CFG node.
- Querying a child upvalue returns its parent capture source; querying the source returns the child target.
- Traverse a register -> child upvalue -> grandchild upvalue chain mechanically.
- Every malformed group class returns a stable diagnostic at the descriptor or closure PC.

### Gate

```console
bash scripts/gates/gate-closures-lua51.sh
```

### Acceptance

The TP-Link-style constant-to-nested-function capture chain is traversable without reconstructing descriptor words by hand.

## 14. F3 — expose resolved constants through public output

### Work

- Use typed semantic operands as the shared source for disassembly, explanation, xrefs, JSON, and JSONL.
- Preserve encoded index, stable constant ID, typed exact value, tag/profile, and raw representation.
- Cover `LOADK`, globals, every RK-capable opcode, tables, comparisons, arithmetic, and profile-specific numeric constants.
- Render a bounded, escaped text preview while keeping the encoded index.
- Emit structured exact values in JSON/JSONL.
- Replace the lifter's missing-constant-to-`nil` fallback with an explicit invalid operand/diagnostic.

### Killer probes

- `LOADK 1 1` for the hello fixture must include the resolved string preview on the same row.
- A global operand must show both its encoded constant index and name.
- Control characters, invalid UTF-8, quotes, backslashes, and long keys must be safely escaped and bounded.
- JSON must expose a typed constant object; parsing human text must never be required.
- The same semantic operand must agree across disassembly, explanation, and xrefs.
- An invalid constant index must never appear as `nil`.

### Gate

```console
bash scripts/gates/gate-resolved-constants-lua51.sh
```

Rename/remove `gate-operands-lua51.sh`; the canonical command above must match capabilities and documentation.

### Checkpoint F3

Provide exact text and JSON output for the key, global, RK, hostile-string, and invalid-index cases.

## 15. F4 — make field evidence reproducible

### Work

- Add redistributable minimized fixtures for the 32-bit `size_t`, LNUM tag, closure-binding, error-offset, and resolved-constant defect classes.
- Run the private 252-file corpus externally under the exact profile from F1.
- Record aggregate corpus hashes, source commit, binary/profile hashes, layout distribution, parse/validation counts, diagnostics, and resource use.
- Keep the private corpus supplemental; public minimized fixtures are the regression gate.
- Do not describe parse/validation counts as semantic correctness.

### Gate

```console
bash scripts/gates/gate-field-reproducers-lua51.sh
```

Remove or rename `gate-corpus-lua51.sh`; ten ordinary stock fixtures parsed under an LNUM mode are not field-corpus evidence.

### Acceptance

Every disclosed field defect has a redistributable reproducer, and the corpus owner can independently reproduce the aggregate report.

## 16. Deferred E1 — runtime semantic effects

Do not place E1 on the first parser/disassembler promotion path.

When undertaken, pin an official Lua runtime, instrument its VM execution loop, force fast and metamethod paths, log actual register/stack/upvalue accesses, and compare those observations with static declarations. Deleting one declared access must make the gate fail. Until then, effects are reviewed/unverified rather than facts.

## 17. Required handoff at every checkpoint

Report:

- exact clean source commit;
- gate ID and committed spec hash;
- exact command argv;
- enumerated positive tests and adversarial probes;
- failing output before implementation and passing output after it;
- compiler/runtime paths, versions, and hashes;
- fixture/profile/layout paths and hashes;
- passed, failed, ignored, and missing-test counts;
- result artifact path and SHA-256;
- exact capability fields changed, or `none`;
- remaining red gates and limitations.

“All tests pass” is not a handoff. Do not close multiple checkpoints in one summary.

## 18. Definition of the first release candidate

The first release candidate is eligible only when:

- R0-R5 have separately reviewed artifacts;
- exact Lua 5.4.8 parsing/disassembly support is derived from its release manifest;
- F1-F3 have separately reviewed artifacts for every advertised Lua 5.1 layout/profile;
- F4 contains public minimized field reproducers and a reproducible private-corpus report;
- public text and machine output expose exact scope, profile, layout, confidence, and limitations;
- unsupported dialects and features remain explicitly experimental;
- the full repository health suite, fuzz targets, and all gate scripts pass on the release commit.

Passing `scripts/check.sh` is necessary repository health evidence. It is not, by itself, proof that any gate above is complete.
