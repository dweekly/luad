# Active product batch: deterministic scalar rendering on exact targets

Lane: product. Roadmap position: exactness of the public disassembly surface.

## Public claim

Every scalar the disassembler shows a user renders identically for the same bytes, on
every supported platform, through both the text listing and the typed machine facts.
One rendering authority owns integers, byte strings, escapes, finite floats, signed
zero, infinities, and NaN classification. No dialect carries its own scalar formatter.

The claim is limited to the exact targets: Lua 5.1.5 and Lua 5.4.8. It is a rendering
claim, not a semantic one. Bytes decide the output; nothing is inferred about what a
value means to a running interpreter.

## Acceptance matrix

### One rendering authority

- Move scalar rendering into a single owned module and delete the per-dialect scalar
  formatters that currently disagree. Today `luad-dialect-lua51` renders a float with
  the debug formatter while `luad-dialect-lua54` carries a private `format_float`, so
  the same bit pattern reaches a user as `NaN` from one target and `nan` from the other.
- The text listing and the typed machine facts must call the same authority. A field
  that appears in both must be produced once, not formatted twice.
- Rendering takes the preserved value, including its exact raw bytes, and returns a
  string. It performs no lookup, no dialect branch, and no width-dependent behavior.

### Scalar coverage

- Canonical integers across the full signed 64-bit range, including both boundary
  values, rendered without separators or width padding.
- Byte strings rendered from exact bytes with one escape policy: a defined escape for
  each byte that is not printable ASCII, a defined quoting rule, and a defined
  truncation rule stated in characters or bytes but not silently in both. Truncation
  must be reversible to the untruncated value through the typed facts.
- Finite floats rendered so that the printed form reads back to the identical bit
  pattern. Integral-valued floats stay visibly floats.
- Signed zero distinguishes `0.0` from `-0.0`.
- Positive and negative infinity render distinctly.
- NaN renders as one spelling and carries its classification in the typed facts. The
  preserved payload stays available; the rendered form does not vary with it.

### Proof

- Byte-for-byte goldens for both exact targets, produced on Linux and macOS from the
  same fixtures and asserted equal to each other. A platform difference is a failure,
  not a golden variant.
- One golden per scalar class above, driven by maintained exact-target fixtures.
- Mutation controls that fail when a scalar class regresses: at minimum, swap signed
  zero for unsigned zero, alter one NaN spelling, drop a float's decimal point, change
  one escape, and reintroduce a per-dialect formatter. Each mutation must break a named
  test rather than merely shift a golden.
- A test that fails if any dialect crate regains a private scalar formatting function.

## Scope

In scope: the shared rendering module, deletion of the per-dialect scalar formatters,
the call sites in text and typed-fact rendering for Lua 5.1.5 and Lua 5.4.8, goldens,
mutation controls, and the changelog.

Non-goals: decompilation, semantic inference about values, schema-major change,
promotion of any additional dialect, a general formatting or templating framework,
locale handling, user-configurable formats, and rendering changes on dialects outside
the two exact targets.

## Stop condition

Stop when one rendering authority serves both exact targets in both output surfaces,
the goldens agree byte-for-byte across Linux and macOS, and every listed mutation
breaks a named test. Do not extend the authority to unpromoted dialects, and do not
grow it into a configurable formatting layer.
