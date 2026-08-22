# Coding-agent plan v2: prove the facts, then ship the workflow

Status: canonical remediation plan.

Audit baseline: clean worktree at commit `0622b7b` on 2026-08-22.

This plan supersedes the earlier gate ordering and all completion claims made by commit messages through the audit baseline. Git history preserves the prior plan. Do not infer completion from a commit subject, a test function name, a copied gate ID, or a green aggregate test run.

Primary references:

- [Correctness review](REVIEW-2026-08-22.md)
- [Tactical coding-agent feedback](CODING-AGENT-FEEDBACK-2026-08-22.md)
- [Plan review](PLAN-REVIEW-2026-08-22.md)
- [TP-Link Lua 5.1 field report](FIELD-REPORT-TP-LINK-LUA51.md)
- [Architecture and invariants](../ARCHITECTURE.md)
- [Product requirements](../PRD.md)
- [Roadmap](../ROADMAP.md)

## 1. Objective

Produce one trustworthy stock-Lua proof vehicle and one useful embedded-Lua product slice before expanding scope:

```text
proof vehicle: Lua 5.4.8
product slice: embedded Lua 5.1 plus explicit LNUM/vendor profiles
```

`luad` owns deterministic, bounded facts. It does not own researcher hypotheses, naming, persistence, planning, or agent intelligence.

The immediate goal is not to add commands. It is to make the existing factual surface honest and independently falsifiable, then implement the three facts the firmware workflow needs most:

1. header-driven Lua 5.1 layout and explicit profile selection;
2. correct closure/upvalue capture relations;
3. resolved constant-bearing operands in text and machine output.

Lua 5.2, Lua 5.3, Lua 5.5, LuaJIT, composable overlays, `get`, `export`, and other feature work remain outside the critical path until the unlock conditions in this plan pass.

## 2. Audited state at `0622b7b`

### Keep

- Memory-safe bounded readers and hostile-input tests.
- Exact official compiler installation with archive checksum verification on a fresh CI runner.
- Fatal compiler requirements in differential-oracle tests.
- Structured `OracleMismatch` values.
- Operand comparison and its mutation controls.
- Lua 5.4 bitfield, signed-immediate, mode, safe-opcode-conversion, and golden-word fixes.
- Raw instruction words, stable IDs, typed operands, provenance types, and deterministic rendering foundations.
- The Lua 5.1 `size_t == 4` compatibility fix as an urgent field fix.
- Honest warnings in README and `docs/MACHINE-INTERFACE.md`.

### Do not treat as complete

- Capability promotion for Lua 5.1 through Lua 5.5.
- Gate IDs copied into both `required_gates` and `completed_gates`.
- Evidence JSON whose success fields are assigned unconditionally.
- A test that searches source text for function names.
- Immediate-dominator correctness.
- Lossless chunk serialization or complete byte accounting.
- Runtime verification of semantic effects.
- General Lua 5.1 layout support.
- An explicit LNUM profile or LNUM oracle.
- Lua 5.1 closure-binding semantics or capture xrefs.
- Inline resolved constants in disassembly.
- Patch-range support beyond the exact compiler releases executed by a gate.

## 3. Operating rules

1. Preserve unrelated worktree changes and inspect `git status --short` before every task.
2. One gate or one narrowly related negative-control batch per change.
3. Add the falsifying test before changing the implementation. The PR or branch history must show the test failing for the intended reason and passing after the fix.
4. Keep acceptance criteria as prose and map every criterion to an exact executable command and assertion. A test name is not evidence by itself.
5. A gate script or CI job must fail if its compiler, fixture, profile, instrumented runtime, or evidence input is absent. No proof path may skip or silently use a bundled fallback.
6. Evidence is derived from command results. Do not write unconditional `true`, counts, versions, gate IDs, or `supported` status into an evidence generator.
7. A negative control must prove the comparator or gate rejects a meaningful corruption. Testing that a function exists, a JSON field says `true`, or an implementation agrees with itself is insufficient.
8. Preserve raw representation separately from interpreted meaning: encoded operands, integer values, float bits, physical instruction words, and hostile string bytes.
9. Never derive artifact layout from the analyzer host. Validate the chunk header and use one immutable layout value for every width- and endian-dependent read.
10. Vendor behavior is selected through an explicit profile with provenance. Stock mode must reject vendor-only constructs.
11. Physical instruction words are not necessarily executable semantic instructions. Companion and closure-binding words retain identity without acquiring false standalone effects.
12. Do not advertise a patch range unless every advertised patch has evidence. Prefer one exact supported release to an unproved range.
13. Do not promote semantic-effect claims until an independent runtime oracle exists. Source citations and self-tests are reviewed evidence, not runtime evidence.
14. `bash scripts/check.sh` is an aggregate development check, not a proof gate.
15. Do not begin another dialect or composability milestone while a critical-path gate is red.

## 4. Gate protocol

Every gate added or repaired under this plan must define all of the following in the same change set:

- **Scope:** exact dialect, profile, version, platform/layout, and fact types.
- **Prerequisites:** compilers, runtimes, fixtures, patches, and their hashes.
- **Positive tests:** exact expected facts.
- **Negative controls:** deliberate corruption that must fail.
- **Command:** one non-interactive command suitable for CI.
- **Artifact:** structured result with source revision and inputs.
- **Claim effect:** exactly which capability field can change after the gate passes.

The gate artifact records at minimum:

- gate ID and schema version;
- source commit and dirty-state flag;
- exact command and exit status;
- test count and skipped-test count;
- compiler/runtime path, exact version, and binary SHA-256;
- upstream archive/patch SHA-256 where applicable;
- fixture source and output SHA-256 values;
- target OS, architecture, endianness, and relevant serialized layout;
- comparator/instrumentation revision;
- start/end timestamps and deterministic result summary.

A committed evidence file is not trusted because it is committed. Its integrity test must recompute or independently validate every claim it uses for promotion. Evidence produced from a dirty worktree cannot promote a release capability.

## 5. Critical paths

### 5.1 Proof spine

```text
C0 contain claims
  → P1 executable gate/evidence harness
  → P2 sound Lua 5.4.8 differential facts
  → P3 correct CFG and validation preconditions
  → P4 real byte losslessness
  → P5 evidence-backed Lua 5.4.8 promotion
```

### 5.2 Embedded Lua 5.1 product spine

```text
C0 contain claims
  → L1 ChunkLayout and explicit stock/LNUM profiles
  → L2 closure-binding and capture facts
  → L3 resolved constants in text and JSON
  → L4 field-corpus regression evidence
```

P1 is shared by both paths. P2 can proceed in parallel with L1 only after C0 and P1 are green. L2 and L3 may proceed in parallel after the L1 data model is stable. No support promotion occurs until the relevant full path is green.

### 5.3 Separate project

Runtime semantic-effect verification is project E1. It is not on the initial promotion path because effect claims can be downgraded or omitted. Do not call lifter self-tests runtime evidence.

## 6. C0 — contain unsupported claims

### Work

- Mark Lua 5.1 through Lua 5.5 `experimental`.
- Clear `completed_gates` that are not backed by this plan's executable artifacts.
- Remove `lossless`, verified-CFG, runtime-effects, layout-profile, and patch-range claims that have not passed their new gates.
- Report exact tested releases separately from support tier.
- Keep README, machine-interface documentation, and capability output consistent.
- Retain evidence files only as historical run reports clearly marked non-promoting, or remove them from the runtime capability source.

### Required tests

- `capabilities::tests::no_supported_dialect_without_verified_artifact`
- `capabilities::tests::completed_gate_requires_validated_result`
- `test_capabilities_readme_status_consistency`
- `test_capabilities_do_not_claim_version_ranges_from_one_patch`

### Negative controls

- Copy a required gate ID into `completed_gates` without an artifact: the test fails.
- Mark a dialect supported with a stale, dirty, or mismatched artifact: the test fails.
- Change README status independently of the manifest: the test fails.

### Gate command

```console
cargo test -p luad-core capabilities::tests
cargo test -p luad-oracle --test test_cli_e2e capabilities
```

### Acceptance

`luad capabilities --evidence --format json` reports no supported stock dialect at the audit baseline, and its claims agree with README and `docs/MACHINE-INTERFACE.md`.

## 7. P1 — executable gate and evidence harness

### Work

- Replace the source-text function-name scan with explicit gate commands executed by CI.
- Define a small versioned gate-result schema.
- Make each gate command write results to a temporary output path supplied by the caller.
- Have the evidence assembler consume those results; it must not infer success from a test name or set success independently.
- Verify exact compiler versions and hashes even when binaries already exist.
- Add `LUAD_ORACLE_BIN_DIR` and remove ambiguous generic `luac` fallback from proof commands.
- Complete fixture provenance with compiler archive hash, compiler binary hash, target layout, generator revision, and generation command.
- Make required fixture-source absence fatal rather than skipping an optional loop body.

### Required tests

- `test_gate_runner_rejects_missing_command`
- `test_gate_runner_rejects_nonzero_command`
- `test_gate_runner_rejects_skipped_test`
- `test_gate_runner_rejects_stale_source_revision`
- `test_gate_runner_rejects_dirty_promotion_evidence`
- `test_gate_runner_rejects_wrong_compiler_binary`
- `test_evidence_tamper_is_detected`
- `test_fixture_manifest_records_complete_provenance`

### Negative controls

- Remove one compiler.
- Substitute the right major/minor but wrong patch release.
- Modify one fixture byte.
- Change one evidence result from false to true.
- Point a gate at a nonexistent or zero-test filter.

### Gate command

```console
bash scripts/gates/gate-proof-harness.sh
```

The script does not exist at the audit baseline. Create it with the tests, commit the red tests first, then implement the harness.

### Acceptance

Each negative control fails at the named prerequisite or claim boundary. A clean run emits a result derived from executed commands and records zero skipped tests.

## 8. P2 — sound Lua 5.4.8 instruction and constant oracle

### Work

- Retain the corrected Lua 5.4 raw decoder and golden words.
- Parse expected operands into typed fields rather than treating the complete operand list as a whitespace string.
- Compare every operand required by the opcode mode, including `k`, signed immediates, RK/constant indices, Ax/extra words, and jump destinations.
- Treat an unknown actual opcode or missing expected field as a mismatch.
- Parse `luac` constants into index, tag, and value fields.
- Compare integer/float/string tags exactly.
- Compare the canonical `luac` float token exactly; separately prove raw IEEE-754 preservation with binary round-trip fixtures. Do not use a broad numeric tolerance.
- Add field-consumption accounting so a parsed oracle field cannot remain silently unused.
- Limit the claim to Lua 5.4.8 until other patches run the same gate.

### Required tests

- existing mnemonic, operand, constant, metadata, count, and old-bitfield negative controls;
- `test_negative_control_unknown_opcode`
- `test_negative_control_operand_count`
- `test_negative_control_constant_tag`
- `test_negative_control_float_listing_token`
- `test_negative_control_signed_zero`
- `test_negative_control_unused_oracle_field`
- `test_lua54_8_all_fixture_operands_and_constants`

### Gate command

```console
bash scripts/gates/gate-facts-lua54-8.sh
```

### Acceptance

The exact Lua 5.4.8 compiler and all maintained positive fixtures match with zero ignored fields. Every negative control emits the expected structured mismatch.

## 9. P3 — correct CFG, dominators, and analysis preconditions

### Work

- Correct immediate-dominator selection. For node `n`, choose the strict dominator dominated by every other strict dominator.
- Test the graph algorithm on hand-authored graphs independent of Lua decoding.
- Assert complete dominator sets and exact immediate dominators, not merely presence or reachability.
- Cover linear, diamond, loop, nested branch, multiple-exit, irreducible where supported, and unreachable topologies.
- Audit CFG construction for companion words and non-executable physical records.
- Reject or mark unavailable analysis when registers, constants, upvalues, stack ranges, jump targets, or companion invariants are invalid.

### Required tests

- `test_idom_linear_exact`
- `test_idom_diamond_exact`
- `test_idom_loop_exact`
- `test_idom_nested_exact`
- `test_idom_multiple_exits_exact`
- `test_idom_unreachable_exact`
- `test_cfg_negative_control_old_entry_for_all_algorithm`
- validator-precondition mutation tests for registers, constants, upvalues, ranges, and jumps.

### Gate command

```console
bash scripts/gates/gate-analysis-cfg.sh
```

### Acceptance

The old algorithm fails the linear and nested negative controls. Exact expected dominator trees and analysis refusal behavior pass.

## 10. P4 — real losslessness and byte accounting

### Work

- Rename the existing JSON round-trip test to describe model-serialization behavior; it is not a chunk-losslessness gate.
- Implement a Lua 5.4.8 binary writer beginning with the lossless parsed model.
- Preserve raw numeric bits, string bytes, debug data, companion words, unknown preserved data, and layout fields.
- Implement a non-overlapping byte ledger classifying recognized fields, padding, preserved uninterpreted bytes, and diagnosed trailing bytes.
- Prove `parse → binary serialize` byte identity and `parse → serialize → parse` structural identity.

### Required tests

- `test_lua54_8_binary_roundtrip_debug`
- `test_lua54_8_binary_roundtrip_stripped`
- `test_lua54_8_binary_roundtrip_numeric_extremes`
- `test_lua54_8_binary_roundtrip_embedded_nul`
- `test_byte_ledger_complete_no_gaps`
- `test_byte_ledger_negative_gap`
- `test_byte_ledger_negative_overlap`

### Gate command

```console
bash scripts/gates/gate-lossless-lua54-8.sh
```

### Acceptance

Every maintained Lua 5.4.8 fixture is byte-identical after serialization, and the ledger accounts for every byte exactly once. Cursor end position and JSON serde do not count as this proof.

## 11. P5 — promote only the proven Lua 5.4.8 scope

### Work

- Assemble promotion evidence only from passing P1–P4 artifacts.
- Do not require or claim runtime semantic-effect evidence unless E1 has passed.
- Generate capability status and README support status from the same validated result.
- Report unsupported or reviewed-only features separately from dialect parse/disassembly support.
- Bind release evidence to source commit, clean tree, exact Lua 5.4.8 compiler, fixtures, schemas, and platform.

### Required tests

- `test_lua54_8_promotion_requires_p1_through_p4`
- `test_lua54_8_promotion_rejects_stale_artifact`
- `test_lua54_8_promotion_does_not_imply_effect_evidence`
- `test_runtime_capabilities_match_validated_manifest`

### Gate command

```console
bash scripts/gates/gate-release-lua54-8.sh
```

### Acceptance

At most Lua 5.4.8 changes to `supported`. No other patch or dialect is promoted transitively, and effect facts remain explicitly unverified unless E1 passes.

## 12. L1 — Lua 5.1 ChunkLayout and explicit profiles

### Work

- Create one validated immutable `ChunkLayout` containing endianness, `sizeof(int)`, `sizeof(size_t)`, instruction width, Lua-number width, integrality, and resolved profile.
- Use a layout-aware reader layer for every layout-dependent field. Keep primitive `SafeReader` methods available internally for genuinely fixed fields; dialect code should not choose widths ad hoc.
- Reject unsupported widths and combinations at the exact header field.
- Implement separate `stock` and `lnum:<profile-id>` interpretations.
- Stock Lua 5.1 must reject tag 9. LNUM support requires an exact patch definition and a built patched compiler/runtime oracle.
- Preserve an LNUM integer as an integer or explicit vendor numeric variant, never as a fabricated float.
- Include profile/layout in diagnostics, machine output, capability scope, and interpretation identity.
- Preserve the deepest parse-error byte offset separately from structural context.

### Fixtures

- independently generated stock Lua 5.1.5 with 32-bit and 64-bit `size_t`;
- debug and stripped forms;
- supported endian and Lua-number layouts;
- explicit LNUM fixture generated by the pinned patched toolchain;
- strings and counts near representation and resource boundaries;
- stock/LNUM cross-profile negative controls.

### Required tests

- `test_lua51_stock_32_layout`
- `test_lua51_stock_64_layout`
- `test_lua51_layout_rejects_unsupported_width`
- `test_lua51_layout_honors_endianness`
- `test_lua51_layout_honors_number_representation`
- `test_lua51_stock_rejects_lnum_tag`
- `test_lua51_lnum_profile_integer_exact`
- `test_lua51_lnum_oracle`
- `test_lua51_error_preserves_exact_offset_and_context`

### Gate commands

```console
bash scripts/gates/gate-layout-lua51-stock.sh
bash scripts/gates/gate-profile-lua51-lnum.sh
```

### Acceptance

Equivalent supported layouts normalize to the same facts, wrong-profile parsing fails at the vendor tag, and no result depends on the analyzer host representation.

## 13. L2 — Lua 5.1 closure-binding and capture facts

### Work

- Preserve every physical word and PC.
- Add an explicit physical-word role such as executable, closure-binding, companion, or preserved unknown.
- For each Lua 5.1 `CLOSURE`, consume the following `nups` descriptor words as ordered bindings.
- Represent parent register capture and parent-upvalue capture distinctly.
- Attach child prototype and child upvalue slot.
- Exclude descriptor words from standalone effects, explanations, CFG nodes, and control-flow entry.
- Validate descriptor count, opcode form, operand range, truncation, and illegal jumps into a group.
- Add forward and inverse capture relations to the generalized xref model.
- Keep a future `upvalues` command as a renderer over these facts, not a second analysis.

### Required tests

- `test_lua51_closure_register_capture`
- `test_lua51_closure_parent_upvalue_capture`
- `test_lua51_closure_multiple_bindings_ordered`
- `test_lua51_closure_descriptor_has_no_standalone_effects`
- `test_lua51_closure_descriptor_not_cfg_node`
- `test_lua51_closure_capture_xrefs_both_directions`
- `test_lua51_closure_multihop_capture_chain`
- malformed count, opcode, range, truncation, and jump negative controls.

### Gate command

```console
bash scripts/gates/gate-closures-lua51.sh
```

### Acceptance

The firmware-style register-to-child-upvalue chain is mechanically traversable, and no descriptor is rendered as an executable copy or false register write.

## 14. L3 — resolved constant-bearing operands

### Work

- Resolve constants through typed dialect operand metadata, not renderer-specific mnemonic lists.
- Preserve encoded index, stable constant ID, typed value, and raw representation.
- Cover `LOADK`, globals, RK operands, table operations, comparisons, arithmetic, and profile-specific numeric constants.
- Text disassembly prints a bounded, safely escaped inline preview.
- JSON/JSONL emits a structured exact value; it never requires parsing the text preview.
- Disassembly, explanation, xrefs, and future export use the same semantic record.
- Missing or invalid constant indices produce explicit diagnostics rather than `nil` substitution.

### Required tests

- `test_lua51_disasm_loadk_resolves_string_inline`
- `test_lua51_disasm_globals_resolve_inline`
- `test_lua51_disasm_rk_resolves_inline`
- `test_lua51_json_constant_operand_is_typed`
- `test_constant_preview_is_bounded_and_escaped`
- `test_invalid_constant_index_is_diagnostic`
- `test_constant_resolution_consistent_across_views`

### Gate command

```console
bash scripts/gates/gate-resolved-constants-lua51.sh
```

### Acceptance

A hardcoded key can be identified from the instruction record without manually joining the constant table, in both text and JSON.

## 15. L4 — field-corpus regression evidence

### Work

- Re-run the private 252-file corpus under an explicit recorded profile.
- Record aggregate artifact hashes, exact tool commit, profile hash, layout distribution, parse/validation counts, diagnostics, and resource usage.
- Minimize and publish a redistributable fixture for every distinct defect class.
- Do not translate `252/252 parse and validate` into semantic correctness.
- Keep batch processing external unless measurement demonstrates that process startup is a material bottleneck.

### Gate command

Project-specific private command plus:

```console
bash scripts/gates/gate-field-reproducers-lua51.sh
```

### Acceptance

All disclosed aggregate results are reproducible by the corpus owner, and every support-relevant defect has a public minimized regression fixture.

## 16. E1 — independent semantic-effect evidence

This is a separate project. Until it passes, effects are labeled reviewed or unverified rather than `Fact`.

### Work

- Pin an exact official Lua source archive and maintain a test-only `lvm.c` instrumentation patch.
- Log prototype, PC, raw instruction, register/stack reads and writes, upvalue accesses, top transitions, calls, metamethod paths, and closure behavior.
- Define comparison rules for exact, conditional, top-dependent, range, and metamethod-capable effects.
- Force both fast and fallback paths.
- Compare observed accesses with static declarations; deleting one declared read/write must fail.

### Gate command

```console
bash scripts/gates/gate-effects-lua54-8.sh
```

### Acceptance

Every effect claim reports executable coverage and observed comparison results. Merely finding an opcode, lifting an instruction, or citing `lvm.c` does not pass.

## 17. Deferred dialects and features

Lua 5.2, Lua 5.3, and Lua 5.5 remain implemented but experimental. Do not delete their code. Do not promote them by copying the Lua 5.4 gate list. Each needs its own exact-version oracle, independent golden vectors, validator audit, CFG preconditions, binary losslessness gate, and evidence result.

Before choosing the next ecosystem, gather broader usage evidence. The TP-Link report justifies prioritizing embedded Lua 5.1; it does not by itself prove that Lua 5.2 should be abandoned or that LuaJIT must be next.

Composable research work remains deferred until P1–P5 and L1–L3 pass for their exact scopes. When it resumes:

1. specify the shared object/export record union;
2. implement exact `get` retrieval using that union;
3. implement deterministic streaming `export`;
4. add read-only overlays with hostile-string handling;
5. add traversal only after a measured workflow demonstrates the need.

No project database, session manager, hypothesis engine, or autonomous agent logic belongs in `luad`.

## 18. Required handoff after every gate

Report:

- exact source commit and whether the tree was clean;
- gate ID and command;
- positive tests and negative controls executed;
- exact compiler/runtime paths, versions, and hashes;
- fixture/profile/layout scope;
- test count and skipped count;
- failing output before the fix and passing output after it;
- generated artifact path and hash;
- exact capability claim changed, or `none`;
- remaining red gates and known limitations.

Do not write “all tests pass” as the handoff. Do not close multiple unrelated gates in one summary. Do not proceed automatically to a deferred milestone.

## 19. Definition of production-grade for the first release candidate

The first release candidate is eligible only when:

- C0 and P1 are green;
- Lua 5.4.8 has passing P2–P5 artifacts;
- Lua 5.1 stock/LNUM advertised scopes have passing L1–L3 artifacts;
- the TP-Link defect classes have redistributable regression fixtures;
- every advertised capability derives from validated evidence;
- unsupported effects are downgraded or E1 passes;
- no required proof test skips;
- `bash scripts/check.sh` passes;
- README, machine interface, capabilities, changelog, and release notes agree;
- fuzzing and resource-limit evidence meet the release policy.

Until then, `luad` remains a promising experimental research tool with useful implemented surface, not a production-grade source of security conclusions.
