# `luad`: Product Requirements Document

**Status:** Living product requirements

**Fresh as of:** 2026-08-27

**Product roadmap:** [ROADMAP.md](ROADMAP.md)

**Active sprint:** [docs/NEXT-SPRINT.md](docs/NEXT-SPRINT.md)
**Primary deliverable:** Self-documenting command-line interface with a versioned machine-readable output contract  
**Primary users:** Lua security researchers and AI coding/reverse-engineering agents

## 1. Overview

### 1.1 The need

Lua bytecode is common in embedded applications, games, appliances, security products, developer tools, and server software. A reverse engineer encountering a compiled Lua chunk typically needs to answer questions such as:

- What Lua implementation, bytecode version, platform, and numeric representation produced this chunk?
- Is the chunk structurally valid, truncated, modified, obfuscated, or intentionally hostile?
- What functions, constants, strings, globals, upvalues, and nested prototypes does it contain?
- What does each instruction do in this specific Lua version?
- Which instructions read or write a given register, constant, upvalue, global, or table field?
- Where can control flow go, and which blocks are reachable?
- Which high-level structures are facts, which are derived facts, and which are heuristic reconstructions?
- How does this chunk differ from another build, another Lua version, or a decompiler's recompiled output?
- Can the results be consumed reliably by scripts and AI agents without scraping terminal text?

Today, answering these questions usually requires a collection of version-specific Lua binaries, old decompilers, one-off parsers, hand comparison with Lua VM source, and substantial expert knowledge. The workflow is fragile: tools frequently conflate disassembly with decompilation, load untrusted chunks into the target runtime, support only one version or host architecture, lose raw representation details, or produce output that cannot be queried programmatically.

Lua's bytecode is an internal implementation format rather than a stable cross-version interchange format. Lua's own documentation states that the virtual machine is likely to change between versions and that precompiled programs from one version will not load in another. Lua 5.1 encoded host details such as endianness, word sizes, and numeric representation in its header. Later releases changed both the serialized chunk layout and instruction encoding. LuaJIT, OpenResty LuaJIT, and Luau use distinct formats and instruction sets rather than merely adding a few opcodes.

Parsing, disassembly, and decompilation of that bytecode are commodities: rizin, unluac, and unluac-rs already read it, including embedded 32-bit layouts. Verification is not. No tool proves its output against the producing compiler with negative controls, none reports a header that contradicts its body, and no public corpus of malformed chunks or licensed bytecode exists. The product opportunity is the Lua bytecode verifier and fact source: honest refusal that names the lying field, an authority discipline behind every claim, public corpora that make the claim testable, and a machine contract that decompilers, devirtualizers, and reverse-engineering platforms consume rather than compete with.

### 1.2 Who needs it

#### Lua security researchers

Security researchers need to inspect unknown and potentially malicious chunks without executing them. Their priorities are:

- Safe parsing of arbitrary bytes.
- Exact raw-to-semantic provenance.
- Fast identification of version, platform, and non-standard format characteristics.
- Search, cross-references, control-flow analysis, and suspicious-pattern detection.
- Useful behavior on stripped, damaged, modified, and obfuscated chunks.
- Deterministic artifacts that can be included in reports and regression suites.
- Clear boundaries between decoded facts and heuristic interpretation.
- Integration with shell pipelines, notebooks, malware-analysis automation, and existing reverse-engineering systems.

#### AI agents

AI agents need many of the same facts, but have additional interface requirements:

- Stable JSON schemas rather than prose-oriented output.
- Stable identifiers for chunks, prototypes, instructions, blocks, constants, and diagnostics.
- Explicit relationships instead of relationships inferred from column formatting.
- Bounded output, pagination, filtering, and summary modes to control context size.
- Discoverable commands, schemas, examples, and error recovery through the CLI itself.
- Deterministic ordering and formatting.
- Provenance and confidence metadata so inferred pseudocode is not mistaken for ground truth.
- Non-interactive operation with meaningful exit codes and no prompts.
- The ability to request a narrow fact, such as all writes to an upvalue, without receiving an entire disassembly.

### 1.3 Options available today

The existing ecosystem contains valuable components but no complete solution.

| Tool or project | Strength | Principal limitation for this product's users |
| --- | --- | --- |
| Official [`luac -l -l`](https://www.lua.org/source/5.5/luac.c.html) | Authoritative stock-Lua listing for its exact version and build | Runtime-coupled, version-specific, text-only, and loads the chunk through the C runtime; not an independent hostile-input parser |
| Official [LuaJIT `jit.bc`](https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/jit/bc.lua) | Authoritative LuaJIT instruction listing with constants, upvalues, and branch targets | Requires a compatible LuaJIT runtime and is not a standalone structural analyzer |
| [OpenResty LuaJIT](https://github.com/openresty/luajit2) bytecode listing | Adds source-line and constant-table improvements useful to OpenResty users | Specific to that runtime family; not a general cross-version format reader |
| [ChunkSpy](https://github.com/viruscamp/luadec/blob/master/ChunkSpy/ChunkSpy51.lua) | Excellent historical binary-inspection model: offsets, raw bytes, profiles, rewriting, and source merging | Primarily Lua 5.0/5.1 and no longer covers modern formats |
| [LuaDec](https://github.com/viruscamp/luadec) | Widely known Lua 5.1 decompiler with disassembly and recompilation comparison | Experimental for 5.2/5.3 and no support for modern Lua; decompiler-oriented architecture |
| [unluac](https://sourceforge.net/projects/unluac/) (Java) and the [Jeong-Min-Cho fork](https://github.com/Jeong-Min-Cho/unluac) | Established stock-Lua decompiler lineage; honours declared header widths end to end, so it reads embedded 32-bit layouts correctly; the fork adds `--opmap` and `--typemap` for modified VMs | Decompiler-first; malformed input surfaces as a Java exception without an offset; no oracle or negative controls; source reconstruction depends on debug information |
| [unluac-rs](https://github.com/x3zvawq/unluac-rs) | MIT, actively maintained Rust decompiler for Lua 5.1-5.5, LuaJIT, and Luau with CFG/dominator analysis, CLI, library, and Wasm; honours declared widths and names the offset and tag on malformed input | Decompiler-first; widens 4-byte floats to double before printing; no differential oracle, negative controls, or machine contract; the closest neighbour and a candidate independent second decoder |
| [luac-parser-rs](https://github.com/metaworm/luac-parser-rs) | Memory-safe parser foundation for Lua 5.1-5.4, LuaJIT, and Luau; custom parsers compile to WASM and are hot-loaded by a hosted decompiler | No license file; no Lua 5.5; requires nightly Rust; accepts embedded headers and then fails inside the body |
| [LuaDecompiler](https://github.com/Coldzer0/LuaDecompiler) (Free Pascal) | Disassembler and decompiler claiming Lua 5.1 through 5.5 with custom opcode tables | AGPL-licensed, lightly proven, and based on a less commonly embedded stack |
| [LuaJIT Decompiler v2](https://github.com/marsinator358/luajit-decompiler-v2) | Strong dedicated LuaJIT source-recovery candidate with stripped-bytecode support | Windows-oriented, decompiler-first, and still lists big-endian support as unfinished |
| [rizin](https://github.com/rizinorg/rizin) | Native `luac` architecture with per-version ISA tables for Lua 5.0 through 5.5 and LuaJIT, a loader, and rizin's CFG, xref, and graph machinery | Refuses non-stock headers by name and then falls back to disassembling the bytes as native code; no oracle discipline, no machine-readable fact contract, interactive-session oriented; the platform `luad` should feed, not fight |
| [Luau official tooling](https://github.com/luau-lang/luau/blob/master/CLI/src/Compile.cpp) | Rich official dump for the Luau ecosystem | Luau is a separate, rapidly evolving bytecode system and cannot stand in for stock Lua |

The [prior-art and corpus survey](docs/PRIOR-ART-AND-CORPORA.md) keeps a reproduced
matrix of these tools against the same non-stock chunks; it is the public acceptance
picture for every vendor profile.

### 1.4 Why current options are deficient

The problem is not that existing tools are uniformly poor. The problem is that their strengths do not compose into a dependable product contract.

Common deficiencies include:

1. **Runtime dependence.** The most authoritative tools use the runtime's own loader. That is inconvenient for cross-version work and inappropriate as the primary parser for an unknown hostile file.
2. **Version fragmentation.** “Lua 5.x support” often means strong support for 5.1 and progressively weaker support afterward. Lua 5.5 is new enough that many otherwise modern tools do not support it.
3. **Dialect conflation.** Stock Lua, LuaJIT, OpenResty LuaJIT, Luau, xLua, Playdate Lua, and vendor-modified VMs are sometimes treated as minor variants even when their formats or semantics require separate front ends.
4. **Decompiler-first design.** Tools optimize for reconstructed source while making raw format details, validation results, and inference provenance secondary.
5. **Unsafe or under-defended parsing.** C-runtime loaders and older parsers were generally not designed as memory- and resource-bounded forensic parsers for arbitrary bytes.
6. **Weak machine interfaces.** Human-readable listings are frequently the only stable output. Scripts and agents must scrape columns and comments.
7. **Missing semantic relationships.** Raw `A B C` operands are printed without typed operands, register ranges, implicit effects, companion instructions, control-flow edges, or references.
8. **Insufficient evidence.** A README claim of version support rarely identifies opcode coverage, malformed-input behavior, differential oracle results, platform fixtures, or fuzzing outcomes.
9. **Poor distinction between facts and guesses.** Decompiled loops, expressions, and variable names are commonly rendered without exposing their source evidence or confidence.
10. **Little support for investigation.** Cross-references, focused queries, comparison, annotations, and “why does this value flow here?” are uncommon.

### 1.5 What must be true of a high-quality disassembler

`luad` will be considered high quality only if all of the following are demonstrably true:

- It parses supported chunks independently and never needs to execute them.
- It preserves all representable input information, including unknown or currently uninterpreted fields.
- It decodes every supported opcode using version-specific semantics, not mnemonic-name similarity.
- It reports exact byte offsets, prototype paths, PCs, raw instruction words, typed operands, implicit effects, and targets.
- It handles both debug and stripped chunks.
- It rejects or diagnoses malformed structures without panicking, reading out of bounds, or making unbounded allocations.
- It distinguishes parse validity, structural validity, VM validity, and heuristic-analysis confidence.
- It produces deterministic human-readable and machine-readable output.
- It can answer focused cross-reference and data-flow questions without requiring consumers to reimplement the analyzer.
- It treats a firmware tree as a first-class batch workflow and makes every streamed
  fact independently joinable to its input and interpretation.
- It exposes symbolic call paths, value origins, and partial call relations only when
  their evidence is auditable, with explicit unresolved and cutoff states.
- Its correctness is continuously compared against official tools and official VM behavior.
- Every supported opcode and format feature is covered by a focused fixture.
- Fuzzing and adversarial regression tests demonstrate parser robustness.
- Version-support claims are generated from machine-readable coverage evidence.

### 1.6 Proposed product and delivery strategy

The primary product should be a self-documenting CLI rather than a GUI or TUI. The CLI is the common denominator for both human researchers and AI agents; it is composable, automatable, testable, remotely usable, and capable of producing durable artifacts. A stable JSON interface is as important as the human text interface.

Development proceeds through customer-visible, public-boundary vertical slices rather
than broad parser presence. The first promotion path qualifies the exact
OpenWrt-derived Lua 5.1 LNUM32 target and the firmware-tree machine contract. Version
1.0 then closes the same public contract independently for the exact stock PUC Lua
5.1.5 64-bit layout and the final PUC Lua 5.4.9 release. No target inherits support
from a nearby version, profile, or layout.

Dynamic tracing, assembly, SSA, decompilation, persistent research state, and security
judgment remain separate layers over the factual substrate. The roadmap defines the
dependency-ordered release train; the active sprint defines the sole executable
checkpoint.

## 2. Product definition

### 2.1 Product vision

`luad` is an explainable Lua bytecode laboratory for safely inspecting, validating, navigating, comparing, and understanding compiled Lua code.

It should feel like a purpose-built combination of:

- `objdump` for reliable structural and instruction listings;
- `javap -v` for integrated metadata;
- a small portion of Ghidra/Binary Ninja for references, CFG, and layered representations;
- WABT for validation and eventual lossless text/binary round trips; and
- a self-describing data service exposed through a CLI rather than a network daemon.

### 2.2 Product form

The initial supported interface is a native command-line program named `luad`.

The implementation should have clean library boundaries, but a stable public language-library API is not required for version 1. The versioned JSON contract is the initial programmatic interface. This prevents premature commitment to in-process APIs while still supporting automation and AI agents.

No GUI or TUI is planned for version 1. The CLI must not make a future UI impossible: the normalized model, analysis APIs, stable identifiers, and JSON schemas should be independently reusable.

### 2.3 Product principles

1. **Facts before reconstruction.** Exact parsing and instruction semantics take priority over decompiled source.
2. **Never hide evidence.** Every derived result must link to the bytes and instructions that support it.
3. **Inference must be labeled.** Facts, derived facts, heuristics, and guesses are distinct data classes.
4. **Untrusted input stays data.** Static commands never execute or load the analyzed chunk through a Lua runtime.
5. **One implementation claim equals one proof artifact.** Version support is backed by fixtures, coverage, oracle comparison, and fuzzing.
6. **Human and machine interfaces are peers.** Text output and JSON are both designed products.
7. **Determinism is a feature.** Equivalent invocation and input produce byte-for-byte identical output unless explicitly requesting runtime or timing data.
8. **Dialects are explicit.** Separate VM families use separate front ends; ambiguity is reported rather than guessed away.
9. **Useful partial results beat opaque failure.** Permissive forensic recovery is available, but never silently treated as a valid parse.
10. **The CLI teaches its own use.** Help, schemas, examples, diagnostics, and suggested next actions are available locally.
11. **Facts and judgment are different products.** Deterministic VM relationships belong
    in `luad`; sink, taint, authentication, and exploitability policy belong outside.
12. **Unresolved is a useful answer.** Derived analysis reports ambiguity, unsupported
    boundaries, cycles, and resource cutoffs explicitly instead of returning a broad
    plausible classification.

### 2.4 Terminology

- **Chunk:** A serialized compiled Lua unit, including its root prototype and nested prototypes.
- **Prototype / proto:** The compiled representation of one Lua function body.
- **Instruction:** One VM operation as encoded in a prototype's code vector.
- **Raw decode:** Literal extraction of opcode and operand bit fields.
- **Semantic decode:** Version-specific interpretation of operands and VM effects.
- **Validation:** Checks that parsed structures and instructions obey the selected format and VM invariants.
- **Analysis:** Derived information such as blocks, CFG, references, use/definition sets, or liveness.
- **Disassembly:** A faithful representation of chunk contents and instructions.
- **Decompilation:** Heuristic reconstruction of higher-level source constructs.
- **Dialect:** A bytecode family or modification requiring format, opcode, or semantic differences from a stock Lua release.
- **Strict mode:** Reject input at the first condition that violates the selected specification.
- **Permissive mode:** Preserve valid regions and emit explicit recovery diagnostics where possible.
- **Symbolic callee path:** An evidence-linked sequence of literal lookups, aliases,
  captures, or module-loader labels established by bytecode; it does not assert the
  identity of the runtime object stored at that path.
- **Value-expression origin:** A bounded derived graph linking a register value to the
  instructions, constants, parameters, captures, and calls that may produce it.
- **Provable call relation:** A caller-to-prototype edge established unambiguously by
  bytecode construction, storage, and invocation facts.
- **Interpretation identity:** The input, dialect, profile, layout, parse mode, and
  analysis configuration under which a fact has meaning.

## 3. Goals and non-goals

### 3.1 Version 1 goals

- Qualify OpenWrt-derived Lua 5.1.5 profile `lua5.1-lnum32` with
  `int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4` through a public,
  reproducible compiler authority.
- Qualify EdgeTX Lua 5.3.6 profile `lua5.3-edgetx32` through the `edgetx-luac` host
  compiler at a pinned EdgeTX revision, with 4-byte `int`, a 4-byte `size_t` header
  slot, 4-byte instructions, 4-byte `lua_Integer`, 4-byte `lua_Number`, and `LUAC_NUM`
  serialized as a single-precision float.
- Qualify stock PUC Lua 5.1.5 profile `lua5.1` independently with
  `int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0`.
- Qualify stock PUC Lua 5.4.9 profile `lua5.4` independently at format 0, with 4-byte
  instructions, 8-byte `lua_Integer`, 8-byte `lua_Number`, and the pinned official
  compiler's standard little-endian representation.
- Preserve parsing surfaces for all other dialects, releases, profiles, and layouts as
  experimental without promoting them through the version-1 claim.
- Detect and report the exact dialect, profile, layout, and selection evidence.
- Produce faithful text and versioned JSON representations.
- Decode all instructions and semantically type all operands.
- Show nested prototypes, constants, upvalues, debug metadata, offsets, and raw instruction words.
- Validate structural and important VM invariants.
- Construct basic blocks and control-flow graphs.
- Provide instruction-level use/definition effects and common cross-references.
- Produce self-identifying, deterministic JSONL over firmware-scale mixed file sets.
- Freeze only the command and fact families admitted by the public automation-contract
  milestone. Existing symbolic-callee, bounded value-origin, provable-call-relation,
  and prototype-identity surfaces remain available as experimental research unless
  that milestone qualifies an exact stable subset.
- Explain instructions in context.
- Compare two chunks structurally and semantically.
- Support stripped chunks without treating absent debug data as an error.
- Remain safe and bounded on arbitrary input.
- Provide deterministic output, shell-friendly exit behavior, generated shell completions, local schemas, and extensive `--help` examples.

### 3.2 Post-version-1 goals

- Independent qualification of additional stock Lua releases, Lua 5.1 layouts, and
  vendor profiles with a public compiler authority.
- Configurable vendor chunk profiles and opcode mappings.
- Richer data flow, liveness, reaching definitions, backward slicing, and SSA.
- A canonical editable assembly representation and assembler.
- Controlled instrumented execution and trace comparison.
- Record/replay or reverse stepping in a constrained interpreter.
- Optional decompilation built on proven analysis layers.
- Export adapters for larger reverse-engineering ecosystems.

### 3.3 Explicit non-goals for version 1

- Reconstructing source identical to the original input.
- Guaranteeing compilable decompiler output.
- Executing analyzed chunks.
- Defeating arbitrary virtualization, encryption, packing, or opcode randomization automatically.
- Reading LuaJIT or Luau bytecode; both are separate bytecode systems outside the product.
- Competing with decompilers or reverse-engineering platforms on breadth of dialect parsing.
- Providing a GUI, TUI, IDE extension, or hosted web service.
- Editing chunks in place.
- Debugging native code generated by LuaJIT.
- Inferring author intent from bytecode without clearly marked uncertainty.
- Acting as a malware sandbox.
- Classifying dangerous sinks, taint, sanitization, attacker control, authentication,
  exploitability, or behavioral safety.
- Building a complete runtime call graph across dynamic Lua dispatch, native code, IPC,
  framework routing, or a firmware filesystem.
- Persisting researcher names, annotations, hypotheses, project state, or agent memory.

## 4. Users and primary workflows

### 4.1 Security researcher workflow

1. Supply an explicit firmware file set or a bounded discovered tree.
2. Classify each input as supported bytecode, source, malformed, ambiguous, or
   unsupported and retain an outcome for every file.
3. Determine the exact VM family, profile, layout, and interpretation evidence.
4. Validate chunks without executing them and enumerate constants, prototypes,
   captures, symbolic call paths, and unresolved calls.
5. Follow selected call arguments through bounded value-expression origins.
6. Navigate from a finding to instructions, blocks, captures, and provable callers.
7. Join prototype content identities across firmware versions.
8. Apply investigation-specific sink, trust, reachability, and exploitability policy in
   a thin external layer.
9. Preserve machine output, diagnostics, tool identity, schemas, and commands sufficient
   to reproduce the analysis.

### 4.2 AI-agent workflow

1. Run `luad capabilities --format json` to discover supported dialects, commands, schemas, and limits.
2. Export a bounded, self-identifying JSONL stream for the selected firmware inputs.
3. Query only relevant prototypes, instructions, callees, value origins, references, or
   diagnostics.
4. Follow stable structural IDs within an artifact and content IDs across builds.
5. Treat unresolved reasons and analysis cutoffs as required branches in its reasoning.
6. Apply its research policy outside `luad` and export a deterministic evidence bundle
   that another agent or human can reproduce.

### 4.3 Lua VM learner workflow

1. Compile a small source example with a selected official compiler.
2. View source lines, raw instruction fields, semantic instructions, register effects, and control flow together in text or JSON.
3. Compile the same source for another Lua version and compare the results.
4. Use `explain` to understand version-specific behavior and implicit effects.
5. Modify the source and observe the bytecode delta.

### 4.4 Tool author workflow

1. Invoke `luad` as a subprocess using JSON Lines or a single JSON document.
2. Pin the schema version and verify capability support.
3. Cache results using input hash, selected dialect/profile, tool version, and analysis configuration.
4. Query stable IDs and relationships without parsing human-oriented output.
5. Receive structured diagnostics and documented exit codes.

## 5. Functional requirements

Requirement identifiers are stable references for design, implementation, tests, and release evidence.

### 5.1 Input discovery and identification

- **FR-INPUT-001:** Accept a regular file, standard input, or an explicit byte range within a file.
- **FR-INPUT-002:** Compute and report input length and SHA-256 without altering input.
- **FR-INPUT-003:** Detect intact stock-Lua signatures and version bytes.
- **FR-INPUT-004:** Detect LuaJIT and Luau signatures once those dialects are supported.
- **FR-INPUT-005:** Report all plausible formats with confidence and evidence when identification is ambiguous.
- **FR-INPUT-006:** Permit an explicit dialect/version override without suppressing mismatch diagnostics.
- **FR-INPUT-007:** Support an explicit base offset for chunks extracted from containers.
- **FR-INPUT-008:** Never infer validity solely from filename or extension.
- **FR-INPUT-009:** Accept an explicit input list and bounded recursive discovery while
  emitting one structured per-file outcome for source, supported bytecode, malformed,
  ambiguous, and unsupported inputs.
- **FR-INPUT-010:** Qualify every batch-input diagnostic with its exact input path and
  distinguish readable unsupported inputs from unreadable inputs.
- **FR-INPUT-011:** Treat a mixed batch with at least one complete successful export as
  process success by default while reporting skipped inputs; provide a strict mode and
  fail when no input succeeds or fatal I/O prevents a complete stream.

### 5.2 Lossless chunk parsing

- **FR-PARSE-001:** Preserve the original input bytes or a content-addressed reference to them for the duration of analysis.
- **FR-PARSE-002:** Represent every parsed field with absolute byte offset, encoded length, raw representation, and decoded value.
- **FR-PARSE-003:** Parse headers according to the selected version rather than a shared superset structure.
- **FR-PARSE-004:** Parse all nested prototypes recursively while enforcing configured depth and count limits.
- **FR-PARSE-005:** Preserve the exact bit patterns of integer and floating constants, including signed zero, NaN payloads, infinities, and values not round-trippable through a default decimal formatter.
- **FR-PARSE-006:** Preserve string bytes independently of text decoding; text is a derived view with declared encoding and escape policy.
- **FR-PARSE-007:** Parse debug data independently from code validity and handle legitimately stripped chunks.
- **FR-PARSE-008:** Retain unknown tags or fields in permissive mode when a bounded recovery is possible.
- **FR-PARSE-009:** Report trailing bytes rather than silently ignoring them.
- **FR-PARSE-010:** Assign deterministic stable IDs based on structural paths, such as `proto:0/2/1`, and local indices, such as `proto:0/2/1:pc:37`.
- **FR-PARSE-011:** Derive a validated chunk-layout object from every header field that controls representation, including endianness, `sizeof(int)`, `sizeof(size_t)`, instruction width, number width, and integral-number flags where the dialect declares them.
- **FR-PARSE-012:** Use the declared chunk layout for every width- or endian-dependent read; never substitute the analyzer host's native representation or a fixed convenience width.
- **FR-PARSE-013:** Represent stock, LNUM, and other vendor constant/layout behavior through an explicit resolved profile with provenance; accepting one vendor tag must not silently broaden the stock dialect.
- **FR-PARSE-014:** Preserve the deepest offending byte offset when adding prototype and field context to a diagnostic.
- **FR-PARSE-015:** Include the selected layout/profile and parse mode in the interpretation identity used to scope persistent artifact references.
- **FR-PARSE-016:** Attach the input and interpretation identity to every exported fact
  directly or through a stable reference that remains valid in interleaved streams.

### 5.3 Instruction decoding

- **FR-DIS-001:** Decode raw instruction fields using the selected version's exact bit layout.
- **FR-DIS-002:** Resolve opcode numbers to version-specific opcode identities.
- **FR-DIS-003:** Type each operand as register, constant, upvalue, prototype, immediate, count, flag, jump, or other version-specific kind.
- **FR-DIS-004:** Preserve both encoded and interpreted signed values.
- **FR-DIS-005:** Resolve relative branches to stable target IDs and absolute prototype PCs.
- **FR-DIS-006:** Identify logical multiword or companion-instruction groups without deleting either physical instruction.
- **FR-DIS-007:** Represent instructions that conditionally skip the following instruction with explicit control-flow outcomes.
- **FR-DIS-008:** Describe fixed and variable register ranges read or written by calls, returns, varargs, concatenation, set-list operations, and loops.
- **FR-DIS-009:** Represent top-dependent or multireturn behavior explicitly.
- **FR-DIS-010:** Represent closure and upvalue-capture relationships, including the ordered mapping from parent register/upvalue at the closure site to each child upvalue slot.
- **FR-DIS-011:** Represent potential metamethod or runtime fallback behavior separately from the fast-path effect.
- **FR-DIS-012:** Display raw instruction words in selectable hexadecimal, unsigned, and bit-field forms.
- **FR-DIS-013:** Resolve every dialect-defined constant-bearing operand to its stable constant ID and typed value while preserving the encoded index; text output includes a bounded escaped preview and machine output includes a structured exact value.
- **FR-DIS-014:** Classify every physical instruction word by semantic role, distinguishing executable instructions from companion words, closure-binding descriptors, and preserved unknown words.
- **FR-DIS-015:** For Lua 5.1 `CLOSURE`, preserve the following `nups` binding words and physical PCs while excluding them from standalone execution effects and CFG instruction nodes.

### 5.4 Validation

- **FR-VAL-001:** Separate diagnostics into parse, structure, instruction, control-flow, debug-metadata, and analysis categories.
- **FR-VAL-002:** Assign each diagnostic a stable code, severity, location, message, supporting evidence, and suggested next action when applicable.
- **FR-VAL-003:** Check all indices and ranges against their referenced tables and stack bounds.
- **FR-VAL-004:** Check branch targets and skip edges against valid logical instruction boundaries.
- **FR-VAL-005:** Check version-specific companion and paired-instruction invariants.
- **FR-VAL-006:** Check prototype, upvalue, local-scope, and debug-line consistency.
- **FR-VAL-007:** Check known VM assumptions for variable-result and loop instruction sequences.
- **FR-VAL-008:** Distinguish unsupported constructs from invalid constructs.
- **FR-VAL-009:** In permissive mode, associate every recovered artifact with the diagnostic that made recovery necessary.
- **FR-VAL-010:** Produce a summarized validation verdict that cannot be confused with “safe to execute.”
- **FR-VAL-011:** Validate closure-binding descriptor count, allowed opcode form, operand ranges, child-upvalue targets, truncation, and prohibition on control-flow entry into descriptor groups.
- **FR-VAL-012:** Report a primary byte location and a separate structural context path; wrapping an error must never replace the primary location with an enclosing offset.

The verdict vocabulary is:

- `valid-for-parser`: conforms to the implemented format checks.
- `valid-for-analysis`: all invariants required by enabled analyses hold.
- `invalid`: violates a known requirement.
- `incomplete`: parsing or analysis could not finish because of truncation, limits, or unsupported features.
- `ambiguous`: more than one format interpretation remains plausible.

No verdict is named `safe`, because structural validation does not establish behavioral safety.

### 5.5 Structural analysis

- **FR-AN-001:** Partition every prototype into basic blocks.
- **FR-AN-002:** Emit typed CFG edges, including fallthrough, conditional true/false, skip, jump, loop, and exceptional/unknown where applicable.
- **FR-AN-003:** Mark reachable and unreachable instructions and blocks.
- **FR-AN-004:** Provide predecessor and successor queries.
- **FR-AN-005:** Generate use/definition sets for registers, upvalues, constants, and prototype references.
- **FR-AN-006:** Build cross-references for constants, strings, upvalues, prototypes, globals when statically identifiable, and jump targets.
- **FR-AN-007:** Identify direct closure creation and statically resolvable calls without pretending dynamic calls are resolved.
- **FR-AN-008:** Compute immediate dominators only after CFG correctness gates pass.
- **FR-AN-009:** Label natural-loop candidates and other structured regions as derived facts, with supporting edges.
- **FR-AN-010:** Support backward slicing as a post-version-1 analysis without changing the lossless core IR.
- **FR-AN-011:** Build forward and inverse capture cross-references between a parent register/upvalue at a specific closure PC and the corresponding child upvalue slot.
- **FR-AN-012:** Resolve an evidence-linked symbolic callee path for `CALL` and
  `TAILCALL` when literal lookups, deterministic aliases, or closure bindings establish
  one; otherwise emit a typed unresolved reason. Callee-register resolution is
  independent of fixed or open argument and result cardinality, and a top-dependent
  write invalidates only the register range it can affect.
- **FR-AN-013:** Preserve whether a module-labeled symbolic path originates in a literal
  loader call without asserting the runtime identity of the returned object.
- **FR-AN-014:** Build a bounded, cycle-safe value-expression origin graph for selected
  registers and call arguments, resolving aliased source operands at the writing
  instruction and exposing every traversal cutoff. Lua 5.1 origin semantics preserve
  both concatenation and the LuCI string-format idiom compiled through `MOD`, while
  distinguishing a computed value from an analysis cutoff.
- **FR-AN-015:** Emit a caller-to-prototype relation only when the target is unique under
  validated construction, reaching-definition, storage, and invocation facts.
- **FR-AN-016:** Compute a versioned prototype content identity from a documented
  normalization while preserving artifact-local structural identity.
- **FR-AN-017:** Preserve bounded, evidence-linked alternatives when multiple
  individually resolved definitions reach a selected value; identify the predecessor
  or defining instruction for each option and do not present their union as one
  path-specific fact.
- **FR-AN-018:** Represent bounded constant-key table construction as a table-literal
  value origin whose fields retain their individual origins and instruction evidence.

### 5.6 Explanation and provenance

- **FR-EXP-001:** Explain an instruction using version-specific semantics and its resolved contextual operands.
- **FR-EXP-002:** Include reads, writes, control-flow outcomes, implicit effects, possible runtime fallbacks, and validation concerns.
- **FR-EXP-003:** Link every explanation to raw bytes, decoded fields, official source references used to implement the semantics, and relevant tests.
- **FR-EXP-004:** Mark every statement as `fact`, `derived`, or `heuristic`.
- **FR-EXP-005:** Never use recovered debug names when they are absent; generated names must be explicitly marked synthetic.
- **FR-EXP-006:** Expose the tool's uncertainty rather than choosing an arbitrary interpretation.
- **FR-EXP-007:** Show resolved constants and closure captures in instruction explanations without requiring the researcher to manually join constant or child-prototype tables.
- **FR-EXP-008:** Reserve `fact` for claims guaranteed by the selected format and
  validated bytes; algorithmic call and value relationships are `derived` and identify
  their preconditions, evidence, ambiguity, and cutoffs.
- **FR-EXP-009:** Every prototype reference in a summary or explanation retains the
  owning prototype path and agrees with the corresponding typed operand, xref, and
  exported fact.

### 5.7 Search, query, and comparison

- **FR-QUERY-001:** Filter by prototype, PC range, opcode, operand kind/value, string, constant, diagnostic code, and analysis relationship.
- **FR-QUERY-002:** Return references to stable IDs instead of duplicating full records by default.
- **FR-QUERY-003:** Support bounded result counts, cursors, and explicit truncation metadata.
- **FR-QUERY-004:** Provide a documented expression grammar for queries; do not evaluate arbitrary host-language code.
- **FR-QUERY-005:** Permit bounded forward and inverse queries over closure-capture relations, preserving the closure site required to identify a parent register value.
- **FR-QUERY-006:** Query symbolic callee components, resolution basis, unresolved
  reason, value-origin node kind, call relation, interpretation identity, and prototype
  content identity without prose parsing.
- **FR-QUERY-007:** Reject unknown fields, unsupported operators, malformed selectors,
  and any predicate whose supplied operand is not applied.
- **FR-QUERY-008:** Apply one bounded structured query to an explicit input list while
  preserving per-file identity, outcomes, diagnostics, ordering, and cursor context.
- **FR-QUERY-009:** Let recursive export select fact-record families while preserving
  the control, identity, diagnostic, truncation, and terminal records required to
  interpret the selected stream.
- **FR-DIFF-001:** Compare chunk headers, prototype trees, constants, instructions, debug data, validation results, and CFGs.
- **FR-DIFF-002:** Support raw-index comparison and normalized semantic comparison.
- **FR-DIFF-003:** Report when alignment is uncertain, especially after instruction insertions or prototype reordering.
- **FR-DIFF-004:** Produce stable JSON diff objects suitable for automation.
- **FR-DIFF-005:** Support cross-firmware joins and comparisons over versioned prototype
  content identities without treating a hash match as source-level identity.
## 6. CLI requirements and command surface

### 6.1 Why a CLI is the correct primary deliverable

A CLI serves both target audiences with one interface:

- Researchers can compose it with `jq`, diff tools, graph renderers, shell scripts, CI, and forensic pipelines.
- AI agents can discover capabilities, constrain output, consume JSON, and retry deterministically.
- Every invocation can be copied into a report and reproduced.
- Golden tests can cover the entire user-facing contract.
- Remote and headless environments require no display stack.
- The implementation can later power a GUI without making the GUI the analysis engine.

A TUI would add interaction state, terminal rendering complexity, accessibility concerns, and a second interface to test before the underlying analysis is proven. A GUI would introduce still more surface area and encourage premature optimization for visual workflows. Neither is justified for version 1.

### 6.2 Command hierarchy

The intended top-level interface is:

```text
luad inspect       Identify and summarize a chunk
luad disasm        Produce a faithful instruction and metadata listing
luad validate      Validate format and VM invariants
luad cfg           List or export control-flow graphs
luad callees       Resolve symbolic labels for every call instruction
luad callgraph     Resolve bytecode-local caller-to-prototype relations
luad origins       Trace bounded value-expression origins for call arguments
luad xrefs         Query references to and from an artifact
luad explain       Explain a field, prototype, instruction, block, or diagnostic
luad query         Run a bounded structured query
luad diff          Compare two chunks
luad capabilities  Describe commands, dialects, features, limits, and schemas
luad schema        Print a selected JSON Schema
luad completions   Generate shell completions
luad help          Show conceptual and task-oriented help
luad version       Print tool and schema versions
```

Commands not yet implemented must not appear as silently nonfunctional placeholders.
`capabilities` reports the actual build's commands, schemas, diagnostic catalog, and
features.

### 6.3 Common invocation examples

```sh
# Fast human-readable identification
luad inspect sample.luac

# Bounded machine-readable summary
luad inspect sample.luac --format json --summary

# Full listing with raw words, resolved constants, and register effects
luad disasm sample.luac --raw --effects --debug-info

# Restrict output to one nested function
luad disasm sample.luac --proto 'proto:0/2/1'

# Strict validation suitable for CI
luad validate sample.luac --strict --format json

# Export a prototype CFG
luad cfg sample.luac --proto 'proto:0/2' --format dot

# Enumerate resolved and unresolved symbolic callees
luad callees sample.luac --format jsonl

# Enumerate exact caller-to-prototype relations and explicit stop reasons
luad callgraph sample.luac --format jsonl

# Trace eager, bounded call-argument expressions without applying sink policy
luad origins sample.luac --format jsonl

# Find all uses of a constant or writes to an upvalue
luad xrefs sample.luac --to 'proto:0:k:7'
luad query sample.luac --where 'effect.write.upvalue == 2' --limit 100

# Explain an instruction in context
luad explain sample.luac 'proto:0/2:pc:37'

# Compare semantic instructions while ignoring debug metadata
luad diff old.luac new.luac --semantic --ignore debug

# Discover the exact JSON schema without network access
luad schema disassembly --version 1
```

### 6.4 Self-documentation

- **CLI-HELP-001:** Every command and option has concise `--help` text.
- **CLI-HELP-002:** `luad help concepts` explains chunks, prototypes, registers, constants, upvalues, stripped debug data, and fact/inference levels.
- **CLI-HELP-003:** `luad help workflows` provides copyable examples for identification, triage, validation, navigation, comparison, and AI-agent use.
- **CLI-HELP-004:** Unknown commands and invalid options suggest the nearest valid forms without executing them.
- **CLI-HELP-005:** Diagnostics may include a `help_topic` resolvable by `luad help <topic>`.
- **CLI-HELP-006:** All help and schemas ship in the binary or installation package and work offline.
- **CLI-HELP-007:** Examples are executed as documentation tests in CI.

### 6.5 Output formats

Required version-1 formats are:

- `text`: stable enough for humans, not promised as a machine interface.
- `json`: one complete versioned document.
- `jsonl`: streaming records for large chunks and agent/tool pipelines.
- `dot`: graph output for CFG commands.

Potential later formats include SARIF for diagnostics and a canonical assembly syntax.

Rules:

- Data goes to standard output.
- Diagnostics about the invocation go to standard error.
- JSON modes never mix prose, progress bars, ANSI escapes, or logging into standard output.
- Human color defaults to `auto`; machine formats never contain color.
- All collections have deterministic ordering.
- Every machine document includes `schema_version`, `tool_version`, input identity, selected dialect/profile, and analysis configuration.
- Large byte arrays are represented through offsets, lengths, hashes, and explicitly requested encoded content rather than repeated by default.

### 6.6 Exit codes

The initial stable exit-code contract is:

| Code | Meaning |
| ---: | --- |
| 0 | Command completed and requested validity condition passed |
| 1 | Command completed but validation found invalid input |
| 2 | CLI usage error |
| 3 | Input/output error |
| 4 | Unsupported or ambiguous format without sufficient override |
| 5 | Configured safety or resource limit reached |
| 6 | Internal error; this is always a product defect |

Commands may provide more detailed structured statuses in JSON, but must not change these meanings incompatibly within a major CLI version.

### 6.7 Configuration

- Explicit CLI arguments override configuration files.
- The tool does not depend on environment variables for correctness-critical settings.
- A command can print its fully resolved configuration.
- Config files are versioned and validated.
- Project-local configuration is opt-in; analysis of a file must not execute config code.
- Safety limits have conservative defaults and cannot be disabled accidentally by a generic `--force` flag.

## 7. Machine-readable contract

### 7.1 Stable identity

Stable IDs are deterministic within a specific input and selected parse interpretation:

```text
chunk
proto:0
proto:0/2
proto:0/2:pc:37
proto:0/2:block:5
proto:0/2:k:7
proto:0/2:upvalue:1
diagnostic:L54-JUMP-003:proto:0/2:pc:37
```

IDs based on content hashes may also be emitted for cross-build matching, but must not replace structural IDs until collision and normalization behavior is specified.

Every stream record also carries an input reference and interpretation reference. A
consumer may join a record correctly without relying on record order or retaining the
most recent file envelope. Content identities use an explicit normalization version and
never replace structural IDs used for navigation.

### 7.2 Provenance record

Every parsed or derived artifact exposes:

```json
{
  "id": "proto:0/2:pc:37",
  "kind": "instruction",
  "confidence": "fact",
  "source": {
    "byte_offset": 428,
    "byte_length": 4,
    "raw_hex": "c1000080"
  },
  "derived_from": [],
  "diagnostic_ids": []
}
```

Derived objects list the stable IDs from which they were computed. Heuristic objects additionally report an algorithm identifier and confidence rationale.
Derived call paths, value origins, and call relations also report analysis preconditions,
typed unresolved or cutoff reasons, and the exact evidence edges included in the result.

### 7.3 Schema evolution

- JSON documents declare a positive integer major schema version.
- Fields may be added compatibly within a major version only when consumers are instructed to ignore unknown fields.
- Field removal, meaning changes, or type changes require a new major schema.
- Schemas are printable through `luad schema` and published with releases.
- Golden compatibility fixtures cover all supported schema majors.
- The CLI permits `--schema-version N` when the current binary can produce that version.

### 7.4 Bounded agent interaction

Every potentially large command supports:

- `--summary` for compact output.
- `--limit` with a safe default in agent-oriented modes.
- `--cursor` for continuation.
- `--select` to choose fields.
- `--proto` and `--pc` scoping.
- `--max-bytes` as a hard serialized-output ceiling.

Truncation is never silent. Responses include returned count, known total when inexpensive, truncation reason, and continuation cursor.

## 8. Internal architecture

### 8.1 Pipeline

```text
Input bytes
  └─> Detector
       └─> Dialect/version-specific chunk decoder
            └─> Lossless chunk model
                 ├─> Structural and VM validator
                 ├─> Semantic instruction lifter
                 │    └─> Normalized semantic IR
                 │         ├─> Basic blocks and CFG
                 │         ├─> Cross-references and effects
                 │         ├─> Symbolic call paths and value origins
                 │         └─> Provable call relations and content identity
                 └─> Renderers
                      ├─> Text
                      ├─> JSON / JSONL
                      └─> DOT
```

### 8.2 Layer boundaries

#### Detector

The detector is bounded and side-effect free. It reads only the minimum bytes needed to produce candidate format interpretations. It does not instantiate a runtime, recursively parse prototypes, or claim validity.

#### Chunk decoder

Each meaningful format generation has a dedicated decoder or explicitly versioned parameterization. Shared helpers may implement safe byte reading, but a generic “Lua 5.x struct” is prohibited.

For architecture-dependent formats such as Lua 5.1, the decoder constructs one immutable chunk-layout value from validated header declarations and uses it throughout recursive parsing. The layout is part of the selected interpretation, not transient header trivia.

#### Lossless model

The lossless model mirrors serialized facts without prematurely normalizing away representation differences. It retains offsets, encoded forms, and unknown values.

#### Semantic lifter

The lifter maps version-specific physical instructions into a normalized semantic vocabulary while preserving a link to every physical instruction. Normalization must not manufacture source constructs.

Physical words are not assumed to be independently executable. Companion words and Lua 5.1 closure-binding descriptors retain raw identity and provenance but attach their meaning to the owning logical instruction. Descriptor words do not acquire ordinary execution effects merely because their bit pattern names an opcode.

#### Validator

The validator is layered so researchers can see whether a failure is a malformed file, an illegal instruction reference, a CFG issue, or simply an unsupported analysis assumption.

#### Analyzers

Analyzers consume validated semantic IR and declare their preconditions. If preconditions fail, they emit `incomplete` results with reasons rather than producing plausible-looking graphs.

Value analysis snapshots source operands at each physical write, computes reaching
definitions only within declared bounds, and preserves ambiguity rather than selecting
one definition. Symbolic paths describe bytecode lookup structure, not runtime object
identity. Security policy cannot enter this layer through names such as `sink`, `taint`,
`safe`, or `sanitized`.

#### Renderers

Renderers do not perform semantic analysis. Text and JSON must consume the same model to prevent discrepancies between human and machine output.

### 8.3 Dialect model

A dialect module contains:

- Header recognition and confidence evidence.
- Validated serialized-layout rules for every header-declared width, endian, and numeric representation.
- Serialized chunk decoder.
- Instruction layouts and opcode table.
- Operand typing rules.
- Semantic instruction effects.
- Validation rules.
- Official source/oracle version metadata.
- Coverage manifest and fixture references.

Stock releases are immutable named targets such as `lua5.4` and `lua5.5`. Patch releases that share a VM remain recorded as oracle/compiler versions even when they share one dialect implementation.

LuaJIT is not implemented as `lua5.1 + extensions`; it receives its own chunk model and semantics module. Luau follows the same rule if supported later.

### 8.4 Vendor-profile extensibility

Not all vendor modifications can be expressed safely as an opcode name table. Extension levels should be explicit:

1. Header/signature override.
2. Constant-tag mapping.
3. Opcode-number mapping where field layouts and semantics are unchanged.
4. Declarative field-layout/profile changes from a constrained schema.
5. Compiled dialect plugin for genuinely different formats or semantics.

Profiles are data, never executable scripts. A profile identifies its base dialect, declares exactly what it changes, and receives a content hash included in every output document.

LNUM and similar constant-tag/numeric extensions are explicit profiles unless they materially change execution semantics enough to require a compiled dialect. Encountering a vendor tag may provide detection evidence, but it never silently changes the meaning of the stock base dialect.

### 8.5 Implementation constraints

- Prefer a memory-safe implementation language and parsing style.
- All arithmetic involving offsets, lengths, counts, and allocations is checked.
- Parsing uses explicit cursors or slices; no unchecked pointer arithmetic.
- Recursive data has configurable and tested depth limits.
- No production parser path contains `unwrap`, assertion-based input validation, or equivalent process-aborting behavior.
- The CLI catches internal failures at the process boundary and distinguishes defects from invalid input.
- The static binary does not link or embed Lua solely to parse chunks.
- Third-party code licenses must permit the intended distribution model; oracle tools may remain test-only dependencies.

## 9. Security and robustness requirements

### 9.1 Threat model

Inputs may be:

- Random or truncated bytes.
- Crafted to cause integer overflow or extreme allocation.
- Deeply nested.
- Internally inconsistent.
- Encoded with misleading version or size fields.
- Designed to exploit assumptions in a real Lua VM.
- Obfuscated with invalid control flow that a permissive runtime or modified VM accepts.
- Large enough to cause denial of service.
- Stored in a path with adversarial characters.

The attacker may know the exact `luad` version and default limits.

### 9.2 Required defenses

- Enforce maximum input size, prototype count, nesting depth, instruction count, constant count, string length, aggregate decoded bytes, diagnostic count, analysis time, and output size.
- Fail closed in strict mode.
- Avoid quadratic algorithms on attacker-controlled counts; where unavoidable, gate them behind limits and document complexity.
- Do not automatically open referenced source paths embedded in chunks.
- Escape terminal control characters and bidi controls in human output.
- Treat strings as bytes by default and make decoding explicit.
- Never write output files unless a path is explicitly requested.
- Refuse to overwrite existing files unless an explicit overwrite option names that behavior.
- Do not load project configuration from the analyzed file's directory unless explicitly enabled.
- Do not access the network.
- Do not invoke external compilers.

### 9.3 Fuzzing requirements

- Coverage-guided fuzz targets exist for detection, every chunk decoder, instruction decoding, validation, text rendering, and JSON rendering.
- Seed corpora contain valid minimal and maximal-feature chunks for every supported version.
- Mutation dictionaries include signatures, tags, varint boundaries, opcode values, and count encodings.
- Every discovered crash, timeout, excessive allocation, or inconsistent verdict becomes a minimized permanent regression fixture.
- CI runs a bounded smoke-fuzz stage; longer fuzzing runs execute continuously or on a schedule.
- Releases publish the duration and configuration of the most recent extended fuzz campaign.

## 10. Correctness and proof strategy

### 10.1 Sources of truth

For each stock Lua version, the authoritative implementation references are:

- `lundump.c` and `ldump.c` for chunk reading/writing.
- `lopcodes.h` and `lopcodes.c` for instruction layouts and opcode metadata.
- `luac.c` for the official listing interpretation.
- `lvm.c` for execution semantics and implicit instruction relationships.
- The corresponding official reference manual for language and compatibility behavior.

The implementation records the exact upstream release and source commit/archive hash used for each semantics table.

### 10.2 Differential oracle testing

For generated valid chunks:

1. Compile a source fixture with an exact official `luac` binary.
2. Run the official `luac -l -l` listing.
3. Run `luad` on the produced chunk.
4. Convert both outputs into a test-only canonical comparison form.
5. Compare prototype metadata, instruction count, opcode identity, operands, constants, lines, locals, and upvalues where the oracle exposes them.
6. Record intentional representation differences in explicit versioned adapters, not blanket ignored fields.
7. Run negative controls that perturb one mnemonic, operand, constant, layout width, and debug fact and prove the comparator reports each mismatch.

The official loader is an oracle used only on trusted generated fixtures. It is not used to validate unknown test corpus files.

### 10.3 Focused semantic fixtures

Every opcode has at least one minimal source fixture or hand-assembled trusted fixture demonstrating:

- Normal operands.
- Boundary operand values where constructible.
- Control-flow successors.
- Registers and other artifacts read and written.
- Companion-instruction behavior.
- Debug and stripped variants.
- Applicable numeric, metamethod, vararg, multireturn, closure, loop, and close behavior.
- For Lua 5.1 closures, each binding-descriptor form and a multi-hop parent-to-child upvalue chain.

Coverage is tracked by semantic behavior, not merely by encountering an opcode number.

### 10.4 Round-trip proof

Before an assembler exists, losslessness is tested by serializing the internal parsed-field record—not a runnable chunk—and confirming that every input byte is accounted for exactly once as:

- a recognized field,
- alignment/padding,
- uninterpreted but preserved data, or
- diagnosed trailing data.

Once an assembler/serializer exists, valid chunks must pass byte-exact decode/encode round trips where the format permits. Any canonicalizing mode is separate and never substitutes for the lossless round trip.

### 10.5 Metamorphic testing

Examples include:

- Stripping debug information changes only expected debug structures and related header fields.
- Renaming source files or locals does not change semantic instruction analysis.
- Reordering independent nested source definitions changes expected prototype references without corrupting unrelated prototypes.
- Encoding a chunk with an alternate supported endian or numeric configuration preserves normalized constants and semantics.
- Parsing equivalent 32-bit and 64-bit `size_t` fixtures uses the header-declared layout and never the analyzer host width.
- Reinterpreting an LNUM/profile fixture as stock Lua 5.1 fails with a profile-specific diagnostic rather than desynchronizing later fields.
- Text and JSON renderers report identical underlying facts.
- Strict and permissive modes agree on valid input.

### 10.6 Determinism testing

Golden tests run identical commands repeatedly and across supported hosts. Unless a field is explicitly declared host-specific, outputs must be byte-for-byte identical. Maps, graph nodes, diagnostics, and inferred artifacts use deterministic ordering.

### 10.7 Coverage manifest

Each release includes a generated manifest containing:

- Supported dialects and official oracle versions.
- Header and chunk feature coverage.
- Opcode semantic coverage percentage and uncovered behaviors.
- Fixture counts by category.
- Differential-test results.
- Supported host platforms.
- Fuzz targets and most recent campaign summary.
- Known incomplete analyses and accepted limitations.

The CLI exposes this through `luad capabilities --evidence`.

## 11. Performance and operational requirements

- **PERF-001:** Default inspection of a 10 MiB valid chunk completes in under one second on a documented reference machine, excluding process startup variance, unless configured limits reject it earlier.
- **PERF-002:** Full parse and disassembly use memory proportional to input plus decoded model size, with no accidental quadratic copying of strings or byte buffers.
- **PERF-003:** JSONL can begin emitting top-level metadata before every analysis is complete when command semantics permit streaming.
- **PERF-004:** CFG and cross-reference analysis complete in linear or near-linear time for normal compiler-produced input.
- **PERF-005:** Query operations over an already constructed model do not reparse the chunk.
- **PERF-006:** Cancellation or process interruption does not leave partial output files presented as complete.
- **PERF-007:** Benchmarks include small startup-sensitive chunks, large instruction vectors, deep prototypes, many constants, and long strings.
- **PERF-008:** A documented firmware-scale mixed corpus benchmark covers batch parsing,
  validation, fact export, symbolic call resolution, and bounded value-origin analysis;
  each stage publishes throughput and peak-memory results independently.

Exact thresholds must be calibrated on the release-candidate fixture matrix and a documented reference machine. Correctness and bounded behavior take priority over optimizing headline throughput.

## 12. Delivery strategy

The [product roadmap](ROADMAP.md) defines capability order and broad exit outcomes.
The [active sprint](docs/NEXT-SPRINT.md) defines the one eligible implementation
claim, including gate commands, killer probes, and checkpoint handoff.

Delivery uses the least expensive evidence lane that can falsify the claim. Product
batches implement one coherent researcher outcome and ordinary tests in one pull
request, using existing authorities and gates wherever possible. Independent review
and separated acceptance are risk-triggered. Target promotion uses complete
authority, provenance, prerequisite, and release evidence.

Customer assignments occur at roadmap boundaries rather than after every patch. Their
repeated workarounds prioritize deterministic facts; their security conclusions remain
outside the acceptance oracle. Downstream gates reference accepted prerequisite results
instead of reproducing their internal semantic suites.

## 13. Release criteria

### 13.1 First release candidate

The first promotable release candidate qualifies the exact LNUM32 profile without
implying stock Lua 5.1 support. It requires:

- a public, reproducible OpenWrt-derived Lua 5.1.5 LNUM32 compiler authority;
- an exact release manifest for the advertised embedded Lua 5.1 profile and layout;
- reviewed CFG/precondition and lossless-model checkpoints;
- deterministic, self-identifying public text and machine output over firmware-scale
  mixed inputs;
- existing derived-analysis surfaces may assist the customer trial, but remain
  experimental and cannot satisfy or expand the target-promotion claim;
- capability status derived from one verified release manifest;
- no required skipped probe;
- bounded malformed-input behavior and maintained fuzz coverage;
- all unproved dialects and runtime semantic effects labeled experimental;
- a successful uncoached customer investigation using a thin external judgment layer.

### 13.2 Version 1.0

Version 1.0 promotes the exact LNUM32, stock Lua 5.1.5 64-bit, and stock Lua 5.4.9
targets in the canonical [release boundary](docs/RELEASING.md#frozen-version-1-boundary).
It additionally requires:

- enveloped command JSON and the other major-1 JSON families at schema major 1,
  capabilities JSON and streaming JSONL/export at schema major 2, and stable CLI exit
  codes 0 through 6 with the meanings in the machine-interface contract;
- reproducible packages for every advertised platform;
- a published evidence bundle and software bill of materials;
- a completed security review and extended fuzz campaign;
- documentation for researcher, learner, and AI-agent workflows;
- no open P0 correctness or security defect;
- an explicit compatibility policy for exact dialect releases and profiles.

Version 1.0 does not require Lua 5.2, 5.3, 5.5, LuaJIT, Luau, another Lua 5.1 layout,
or another vendor profile. Breadth must not delay or dilute exact evidence for the
support scope actually advertised.

## 14. Success metrics

### 14.1 Correctness metrics

- 100% opcode identity and operand-layout coverage for every advertised version.
- 100% focused semantic fixture coverage for every advertised opcode.
- Zero unexplained differential mismatches against official oracles on the maintained valid corpus.
- 100% byte accounting for valid supported chunks.
- Zero known panic, memory-safety, or unbounded-allocation defects in the maintained malformed corpus.

### 14.2 Usability metrics

- A new user can identify, validate, and obtain a scoped disassembly using only `luad --help` and local help topics.
- Common triage output fits within a documented bounded summary without requiring a full listing.
- Every human-facing finding has a corresponding machine-readable representation.
- The reference corpus workflows require no consumer-side instruction decoder or
  stateful file-envelope adapter.
- Symbolic callee, value-origin, and provable-caller questions can be answered by one
  command or one command plus a stable-ID follow-up.
- Open argument forwarding never erases a callee proved in an unaffected register;
  argument openness and callee identity remain independently consumable facts.

### 14.3 Agent metrics

- A reference agent completes the standard workflow with zero human-text scraping.
- All large responses can be bounded and resumed.
- Stable-ID follow-up queries resolve unambiguously.
- Interleaved firmware-tree facts join to their input and interpretation without
  stream-position state.
- Unresolved relationships and resource cutoffs become explicit branches rather than
  confident negative answers.
- Equivalent invocations produce identical JSON across repeated runs and supported hosts, excluding declared environment metadata.

### 14.4 Adoption signals

Adoption is secondary to correctness, but useful signals include:

- External regression fixtures contributed with reproducible provenance.
- Private firmware corpora may contribute content-addressed aggregate results and minimized redistributable reproducers; private sample counts never substitute for a public proof fixture or profile definition.
- Use in security reports or automated analysis pipelines.
- Third-party consumers pinning and validating the JSON schema.
- Vendor profiles maintained outside the core repository.
- Differential bugs found in other Lua tools or VM documentation through `luad` evidence.

## 15. Risks and mitigations

| Risk | Consequence | Mitigation |
| --- | --- | --- |
| Scope expands into a universal decompiler | Core correctness remains unfinished | Enforce version-1 non-goals and require proof gates before advanced analysis |
| Similar opcode names hide version-specific semantics | Plausible but incorrect output | Derive semantics from exact official VM sources and require focused fixtures |
| Official listing is treated as a complete oracle | Missing implicit effects and loader bugs go unnoticed | Combine `luac` differential tests with `lvm.c` review, semantic fixtures, and metamorphic tests |
| Supporting all versions at once creates shallow coverage | README claims outpace reliability | Deliver one vertical slice and advertise versions only after independent gates pass |
| Permissive parsing looks authoritative | Researchers rely on recovered garbage | Propagate diagnostics and validity state into every recovered artifact |
| JSON schema mirrors unstable implementation details | Automation breaks frequently | Design a normalized external schema and test compatibility independently |
| AI-oriented summaries omit critical uncertainty | Agents overstate findings | Include confidence, provenance, truncation, and unresolved relationships in all modes |
| Vendor customization becomes arbitrary code execution | Static analyzer gains a plugin attack surface | Constrained data profiles first; compiled plugins are explicit, trusted, and separately distributed |
| Dynamic execution compromises host safety | Malicious chunk affects analyst system | Keep execution out of v1; later use an isolated instrumented runtime with explicit trust boundaries |
| Numeric/string rendering is lossy | Round trips and comparisons become incorrect | Preserve raw bytes/bits and make text formatting a derived view |
| CFG on invalid bytecode is misleading | Higher-level analysis appears credible | Analyzers declare validation preconditions and return incomplete results when unmet |
| CLI becomes a collection of inconsistent commands | Human and agent discoverability degrades | Shared selectors, output rules, IDs, diagnostics, and generated command documentation |
| Every consumer rebuilds register provenance differently | Silent aliasing, cutoff, and constant-expression errors recur | Own one bounded evidence-linked value-origin graph with explicit unresolved states |
| Symbolic paths are mistaken for runtime identities | Findings overstate what bytecode proves | Name the resolution basis, retain evidence, and separate symbolic lookup from runtime object identity |
| Customer feedback drives policy into the core | One investigation's assumptions become product behavior | Admit deterministic facts only; keep sink, taint, authentication, and exploitability outside |

## 16. Product decisions and open questions

### 16.1 Decisions made by this PRD

- The primary deliverable is a CLI, not a GUI or TUI.
- Versioned JSON/JSONL is the initial stable programmatic interface.
- Static analysis never executes an input chunk.
- The first promotable release candidate targets the exact OpenWrt-derived Lua 5.1.5
  LNUM32 profile and firmware-tree workflow.
- Version 1.0 additionally qualifies the exact stock PUC Lua 5.1.5 64-bit layout and
  PUC Lua 5.4.9 target named by the roadmap.
- Lua 5.2, 5.3, 5.5, additional Lua 5.1 layouts, and every other vendor profile remain
  experimental until independently promoted.
- LuaJIT and Luau require separate dialect families and an explicit post-release prioritization decision.
- Decompilation is not part of version 1.
- Losslessness, provenance, validation, and determinism are release requirements rather than optional polish.
- Persistent researcher state, interpretations, hypotheses, and agent planning remain outside `luad`.
- Symbolic callee paths, bounded value-expression origins, provable partial call
  relations, cross-file identities, and prototype content identities are implemented
  experimental research. They are not a stable version-1 promise unless the public
  automation-contract milestone qualifies an exact surface.
- Sink, taint, safety, authentication, reachability, and exploitability classifications
  remain external policy.

### 16.2 Decisions required before expanding the post-1.0 scope

1. Does the next dialect investment optimize for another stock-Lua correctness
   reference or a prevalent reverse-engineering ecosystem such as LuaJIT?
2. Which additional target platforms need release binaries and scheduled compatibility runners?
3. Which safety-limit values should become stable version-1 defaults?
4. Which public schemas can freeze at version 1, and which dialect-specific records still require tagged extension points?
5. Which cross-version semantic vocabulary is proven useful without erasing dialect differences?
6. Does user evidence justify SARIF, an in-process library contract, or additional export formats?
7. Which facts have independent evidence strong enough to support exact retrieval and full-fidelity export after the applicable target-specific release gate?

### 16.3 Criteria for reconsidering a GUI or TUI

A visual interface should be considered only if at least one of these becomes true:

- Researchers consistently need synchronized graph/listing interaction that cannot be represented through exported artifacts and stable IDs.
- A maintained third-party UI needs a supported in-process or local-service API.
- CLI query latency makes iterative navigation materially inefficient.
- User research demonstrates that the CLI blocks adoption among a priority audience.

If a UI is built, it must consume the same analysis model and machine contract rather than reimplement parsing or semantics.

## 17. Documentation requirements

The project documentation set includes:

- Installation and verification.
- Quick-start triage workflow.
- Concepts guide for Lua bytecode structure.
- Per-version format and opcode notes with official-source references.
- CLI reference generated from command definitions.
- JSON/JSONL schema reference.
- Stable-ID and query-language reference.
- Diagnostic catalog.
- Security model and safe-handling guidance.
- Fixture, oracle, and fuzzing methodology.
- Vendor-profile authoring guide.
- Compatibility and evidence manifest.
- Architecture and contributor guide.
- Known limitations and unsupported-format guidance.

Documentation examples must be executable tests. Version-specific pages state the exact Lua release used as their reference.

The root README indexes every maintained Markdown document with a summary, a
last-fresh date, and a concrete revalidation or deletion trigger. Plans and roadmaps
contain only future work and acceptance conditions; implementation history belongs in
the changelog, release notes, pull requests, and commits. Source comments describe
present invariants and rationale rather than earlier implementations.

## 18. Reference sources

The following primary or project-owned sources informed this PRD and should remain starting points for implementation research:

- [Lua version history and compatibility policy](https://www.lua.org/versions.html)
- [Lua 5.4.9 source index](https://www.lua.org/source/5.4/)
- [Lua 5.4.8-to-5.4.9 source diff](https://www.lua.org/work/diffs-lua-5.4.8-lua-5.4.9.html)
- [Lua 5.5 source index](https://www.lua.org/source/5.5/)
- [Lua 5.5 binary loader](https://www.lua.org/source/5.5/lundump.c.html)
- [Lua 5.5 instruction formats](https://www.lua.org/source/5.5/lopcodes.h.html)
- [Lua 5.5 opcode properties](https://www.lua.org/source/5.5/lopcodes.c.html)
- [Lua 5.5 official listing implementation](https://www.lua.org/source/5.5/luac.c.html)
- [Lua 5.5 virtual machine](https://www.lua.org/source/5.5/lvm.c.html)
- [Lua 5.1 binary loader and architecture-dependent header](https://www.lua.org/source/5.1/lundump.c.html)
- [OpenWrt 19.07 Lua 5.1 package and ordered patch series](https://github.com/openwrt/openwrt/tree/1da2e82c1182a3fd681da5760be96821213afadd/package/utils/lua)
- [Lua Workshop: Mitigating the Danger of Malicious Bytecode](https://www.lua.org/wshop11/Cawley.pdf)
- [LuaJIT bytecode dump format](https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/lj_bcdump.h)
- [LuaJIT bytecode definitions](https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/lj_bc.h)
- [LuaJIT bytecode listing module](https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/jit/bc.lua)
- [Binary Ninja intermediate-language overview](https://docs.binary.ninja/dev/bnil-overview.html)
- [Ghidra program graph documentation](https://www.ghidradocs.com/10.1.5_PUBLIC/help/ProgramGraph/help/topics/ProgramGraphPlugin/ProgramGraph.htm)
- [rr record/replay debugger](https://github.com/rr-debugger/rr)
- [Frida Stalker tracing documentation](https://frida.re/docs/stalker/)
- [Oracle `javap` documentation](https://docs.oracle.com/en/java/javase/21/docs/specs/man/javap.html)
- [WebAssembly Binary Toolkit](https://github.com/WebAssembly/wabt)
- [LLVM optimizer command guide](https://www.llvm.org/docs/CommandGuide/opt.html)
- [MLIR pass instrumentation](https://mlir.llvm.org/docs/PassManagement/)

---

This PRD intentionally defines a narrower first product than a general reverse-engineering suite. If `luad` can establish a trusted, queryable, lossless account of Lua bytecode and prove that account against official implementations, richer experiences can be layered on safely. Without that foundation, a sophisticated UI or decompiler would only make uncertain output easier to consume.
