# `luad` product roadmap

Status: authoritative product direction. Exact implementation and acceptance details
belong only in [the active sprint](docs/NEXT-SPRINT.md).

## Destination state

`luad` will be a deterministic, stateless fact tool that lets a human researcher or
external agent move from a firmware tree to reproducible answers about bytecode
identity, constants, symbolic call paths, captures, value origins, control flow, and
change across firmware versions. Every answer will carry the artifact interpretation
and instruction evidence needed to audit it. Machine consumers will be able to join and
query those facts without decoding Lua instructions or maintaining hidden stream state.

Security classification, attacker control, exploitability, inferred intent, research
memory, and autonomous planning will remain outside the executable. The product
boundary is whether competent analysts can disagree: deterministic VM facts belong in
`luad`; investigation-dependent judgments belong in the caller.

Every support claim will remain scoped to an exact release, profile, layout, public
surface, and evidence manifest. A private firmware corpus may test field relevance but
will never be the sole authority for promotion.

## Delivery sequence

### 1. Qualify the embedded Lua 5.1 authority and target

The first firmware target will be the OpenWrt-derived Lua 5.1.5 LNUM32 profile with
little-endian, 32-bit serialized string lengths. Its authority will pin the official
Lua archive, an immutable OpenWrt revision, every bytecode-affecting patch and build
setting, the target toolchain, and redistributable source-to-bytecode fixtures. Compiler
source identity will be portable; each built compiler binary will remain platform- and
toolchain-specific evidence.

Target promotion will follow authority acquisition as a separate sprint. It will close
the public `inspect`, `disasm`, `validate`, and batch-selection surfaces over the exact
profile and layout. Stock Lua 5.1.5 layouts will receive independent promotion after
the embedded target; their evidence will not substitute for LNUM32 evidence.

Exit outcome: one exact firmware-relevant Lua 5.1 target has a reproducible public
compiler oracle, a verified release manifest, honest capability output, and a
supplemental clean run over representative firmware.

### 2. Make firmware-tree streams self-identifying and stable

Every JSONL fact will carry or directly reference a stable input identity and the exact
interpretation identity used to decode it. Prototype and instruction identifiers will
be joinable across interleaved files without requiring a consumer to retain
`file_start` state. Schema discovery, compatibility rules, ordering, limits, failure
records, and interpretation provenance will be explicit at the live CLI boundary.

This stage will audit existing machine surfaces before adding new ones. One shared
machine-contract gate will own compatible response and stream behavior; later factual
record types will extend that contract rather than create parallel envelope systems.

Exit outcome: an agent can stream a mixed firmware tree into ordinary relational or
JSON tooling, join every fact to its file and interpretation, and reject incompatible
schema majors without prose parsing.

### 3. Resolve symbolic call paths

`CALL` and `TAILCALL` facts will expose a symbolic lookup path when bytecode establishes
one. Resolution will begin with literal global/table lookup chains and extend through
deterministic local aliases, closure captures, and upvalue-bound values. A literal
`require` call may contribute a module-labeled symbolic path, but the result will state
that basis rather than claim which runtime object a loader returns. Every resolved path
will link to the instructions and bindings that establish it.

Unresolved calls will remain first-class results with a bounded reason such as dynamic
table key, conflicting reaching definitions, unsupported control-flow boundary, or
analysis limit. The resolver will not infer a source-level name, classify a sink, or
claim one runtime function when more than one value is possible.

Exit outcome: callers can enumerate evidence-backed symbolic callee paths and unresolved
reasons across a firmware tree without reimplementing Lua register and closure
semantics.

### 4. Expose bounded value-expression origins

Call arguments and selected registers will link to an evidence-backed value-expression
graph. The graph will distinguish constants, parameters, upvalues, call results,
concatenations, other computed values, and explicit unknown or cutoff states. It will
resolve source operands at the writing instruction, including instructions such as
`CONCAT` whose destination may alias an input, and it will be cycle-safe.

The graph may recurse across basic blocks and closure bindings only where reaching
definitions are deterministic. Depth, node count, traversal, and output will be
bounded; hitting a bound will produce a visible cutoff rather than a plausible broad
classification. It will not label values tainted, safe, sanitized, or exploitable.

Exit outcome: an external investigator can distinguish a constant-leaf expression from
a parameter-dependent expression and can audit every included edge or explicit cutoff.

### 5. Publish provable call relations and content identity

`luad` will expose cross-prototype call edges only when closure construction, storage,
lookup, and invocation establish one target unambiguously. Dynamic dispatch and
ambiguous calls will remain unresolved. These partial edges will make intra-artifact
caller questions composable without turning framework routing or authentication policy
into bytecode facts.

Each prototype will also receive a versioned content identity derived from a documented
normalization of its instructions, constants, captures, and child relationships.
Artifact-local IDs will remain available for navigation; content identities will make
unchanged and changed functions joinable across firmware versions.

Exit outcome: consumers can build evidence-backed partial call graphs and compare
prototype inventories across releases with ordinary joins, while ambiguity remains
visible.

### 6. Complete factual queries, recipes, and the stable release

The query surface will address symbolic callees, value-expression shapes, call
relations, interpretation identity, and prototype content identity. Every predicate
will either apply its full operand or fail closed. Documentation will provide tested
end-to-end recipes for corpus constant search, capture traversal, callee enumeration,
argument-origin triage, caller navigation, and firmware-version comparison.

The release candidate will freeze the intended schema major, publish exact target and
platform artifacts, and undergo an uncoached customer investigation against
representative firmware. Reproducible correctness defects will become minimized public
fixtures before release; investigation-specific policy will remain external.

Exit outcome: a human or AI agent can complete the reference firmware workflows using
the supported CLI and a thin external judgment layer, with no private decoder or
stateful stream adapter.

### 7. Qualify additional targets independently

Stock Lua layouts, Lua 5.2, 5.3, 5.4, 5.5, LuaJIT, and vendor mappings will advance one
exact target at a time. Vendor qualification may consume a provenance-bound mapping of
opcode, header, field-layout, and numeric-format facts recovered by an external tool.
Interpreter execution, gadget testing, and firmware rehosting will remain external.

Exit outcome: each promoted target follows the same authority, fixture, validator,
machine-contract, and release-manifest discipline without broadening another target's
claim.

## Dependency order

```text
OpenWrt LNUM32 authority
  -> exact embedded-target promotion
       -> self-identifying firmware streams
            -> symbolic callee paths
                 -> bounded value-expression origins
                      -> provable call relations and prototype identity
                           -> query/recipe closure and stable release

additional target qualification reuses only the accepted boundaries it actually needs.
```

## Customer checkpoints

Customer work is an independent product signal, not a substitute oracle. At each
checkpoint, the firmware research agent receives the candidate CLI and a natural
investigation objective rather than an internal acceptance checklist.

- After embedded-target promotion: inventory and validate the firmware Lua corpus.
- After self-identifying streams and symbolic callees: repeat a corpus-wide call-site
  survey using only public machine output.
- After value origins and call relations: trace selected parameter-to-call and caller
  relationships, leaving reachability and security judgment external.
- Before release: investigate a different firmware version or objective without
  implementation guidance.

Correctness defects interrupt the sequence. Machine-consumption friction routes to the
nearest factual stage. Requests for security policy, inferred intent, or persistent
research state remain external unless they can be restated as deterministic facts.

## Delivery roles

- The product and acceptance steward selects the smallest customer-visible claim,
  chooses the evidence lane, reviews algorithms, runs gates, and decides acceptance.
- The customer research agent performs uncoached firmware assignments and reports
  commands, workarounds, incorrect answers, ambiguities, and blocked questions.
- Gemini Flash High implements bounded patches and semantic candidates in an isolated
  worktree; it does not own verification or promotion.
- Opus authors or critiques independent acceptance only for qualification work, new
  semantic primitives, and genuinely ambiguous contracts; routine patches do not pay
  this coordination cost.
- A model-diverse area review checks the combined public behavior after several
  related sprints. Portfolio-level roadmap critique, including a Fable-class reviewer,
  occurs before the stable release plan rather than once per sprint.

Serial work remains the default. Parallel work becomes eligible only when production
paths, acceptance paths, gates, worktrees, and integration order are demonstrably
independent.

## Persistent exclusions

The roadmap does not place these responsibilities inside `luad`:

- decompilation or pseudo-code generation;
- vulnerability and dangerous-sink classification;
- attacker-control, sanitization, authentication, or exploitability judgments;
- inferred names presented as facts;
- whole-system reachability across Lua, native code, IPC, and web routing;
- persistent projects, annotations, hypotheses, or sessions;
- autonomous research planning;
- firmware unpacking, target-interpreter execution, or dynamic gadget testing;
- execution of untrusted Lua bytecode.

Those capabilities belong in composable external layers unless a future roadmap
revision identifies a narrower deterministic fact with an auditable evidence boundary.
