# Active sprint: Lua 5.1 prototype content identity

Lane: semantic analysis. Target: make unchanged and changed prototype subtrees directly
joinable across firmware artifacts without confusing content equality with source
identity.

## Claim and researcher value

Every fully decoded Lua 5.1 prototype will receive a deterministic, versioned SHA-256
subtree-content identity over its decoded instruction content, constants, upvalue count,
capture shape, and ordered child relationships. The same normalized prototype subtree
will receive the same identity regardless of input path, artifact hash, source name,
byte offsets, or debug metadata.

Researchers will be able to compare firmware exports with an ordinary join and isolate
changed prototype subtrees. Artifact-local `proto:0/…` paths remain the only navigation
identity. Equal digests prove equality under the documented v1 encoding. Unequal digests
do not prove a behavioral difference, and a content match is not a claim of shared source
history, authorship, or runtime behavior.

## Canonical identity contract

The public identity record contains:

- `scheme: "luad-prototype-v1"`;
- `digest: "sha256:<64 lowercase hex characters>"`;
- the artifact-local prototype ID that the digest describes.

The v1 preimage is a domain-separated, length-prefixed binary encoding. It includes the
Lua base dialect, parameter count, the exact Lua 5.1 vararg flag byte, maximum stack
size, decoded instructions in physical PC order, physical instruction role and mnemonic,
typed operand values, ordered constant values, the upvalue count, and ordered child
content digests. Lua 5.1 capture bindings are represented by the typed
`closure_binding` instruction records following `CLOSURE`; the synthesized generic
`UpvalueDesc` fields are not separately encoded. Prototype and constant references
encode owner-local indices, jumps encode owner-local PCs, and RK operands encode as
distinct register or constant variants.

The normative encoder uses this grammar:

- The preimage starts with the 18 bytes represented by ASCII `luad-prototype-v1` and a
  trailing zero byte, followed by the
  prototype record. Every record and variant starts with the one-byte tag assigned in
  the machine-interface table authored in this sprint.
- Unsigned integers use the smallest width declared for the field (`u8`, `u32`, or
  `u64`); signed integers use the corresponding two's-complement width. All integers
  use big-endian byte order. Collection counts and byte-string lengths use `u64`.
- The prototype record encodes, in order, base dialect bytes (`lua5.1`), `numparams:u8`,
  `is_vararg:u8`, `maxstacksize:u8`, instruction count and records, constant count and
  records, `nups:u64`, child count, and each child's raw 32-byte digest.
- An instruction record encodes its role bytes, mnemonic bytes, operand count, and
  operands in public disassembly order. PCs are implied by collection order. An operand
  encodes its `OperandKind` variant and numeric value, then either a no-resolution tag or
  a resolved-fact variant with only its owner-local index, target PC, or metamethod name.
  Display strings, operand field labels, names, stable IDs, and resolved constant values
  are excluded; constants are encoded once in their owner table.
- Constant variants are distinct. Nil has no payload; booleans encode one byte; integers
  and floats encode their exact bytes from the chunk; short and long strings remain
  distinct and encode the parsed payload bytes without the serialized trailing NUL.
  Numeric values are never coerced, so integer and float encodings, `+0.0` and `-0.0`,
  and distinct NaN payloads remain different.

The machine-interface document will pin every tag value before production code is
accepted. Changing any v1 field, tag, order, or encoding rule requires a new scheme such
as `luad-prototype-v2`; existing v1 digests never change meaning.

The preimage excludes artifact paths and hashes, prototype paths, stable IDs, source
names, line tables, local/upvalue debug names, source locations, byte offsets, comments,
display strings, diagnostics, support tiers, and raw instruction words. Child identities
are computed bottom-up, so a changed descendant changes each ancestor on its path but
not an unchanged sibling.

The encoder never hashes implementation-dependent `Debug` output or ordinary JSON
serialization. Unsupported dialects receive no prototype identity rather than a v1 hash
under unproved normalization rules. Parsing must finish successfully within the existing
reader depth and resource limits before any prototype in the artifact receives an
identity; partial or over-limit trees receive none.

## Public surface

Recursive export will add one `prototype_identity` fact per Lua 5.1 prototype. Each
record carries the ordinary per-file context, artifact-local prototype ID, scheme, and
digest. Export and any prototype metadata must call the single analysis implementation.
The record is unconditional for successfully decoded Lua 5.1 prototypes and is an
additive schema-v2 record type. The export schema, example, capability discovery, and a
tested cross-firmware-version join recipe will describe the record and its size cost.

## Acceptance matrix

One table-driven fixture family will prove:

- byte-identical input and copied input produce identical fact sets;
- debug-present and stripped variants with identical executable content agree;
- source names, line metadata, local names, input paths, byte offsets, and diagnostics do
  not affect identity;
- changing a mnemonic, typed operand, exact constant value or type, parameter shape,
  upvalue count, capture descriptor, child order, or child content changes the intended
  digest;
- changing one nested child changes that child and its ancestors while preserving an
  unchanged sibling;
- structurally identical sibling subtrees receive identical digests regardless of their
  positions;
- an encoded-content change remains visible after debug data is stripped;
- every Lua 5.1 prototype receives exactly one identity in structural order;
- automatic and explicit LNUM32 selection produce the same identities;
- direct analysis and recursive export emit byte-identical identity facts.

Pinned golden digests derived from the normative encoding table and a small test-vector
encoder will reject field omission, field reordering, debug-field inclusion, path
inclusion, child-digest omission or substitution, sibling-position leakage, digest
truncation, scheme substitution, and upper-case or non-hex output. Degenerate and bounded
shapes cover empty collections and nesting at the configured reader limit. The canonical
encoding never depends on host byte order or float formatting.

## Allowed production paths

- one prototype-identity module in `crates/luad-analysis`
- recursive export integration and capability discovery
- typed core records only where shared machine contracts require them
- redistributable fixtures, one focused oracle module, one gate spec and runner
- indexed architecture, machine-interface, recipe, status, PRD, roadmap, and changelog
  documentation

## Non-goals

This sprint does not align reordered prototypes, infer source equivalence, add a general
diff engine, expand query grammar, persist an index, hash non-Lua-5.1 dialects, classify
security relevance, or use private firmware as an oracle. It does not replace artifact
hashes, interpretation identity, or structural prototype paths.

## Verification and stop condition

Acceptance requires the identity matrix and killers, canonical batch-export and
machine-interface checks, aggregate repository checks, green pull-request CI, and a clean
merged revision with local `main` equal to `origin/main`. The sprint stops rather than
normalizing a field whose semantic equivalence is not proved for Lua 5.1.
