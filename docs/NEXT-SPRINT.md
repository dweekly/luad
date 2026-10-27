# Sprint: opt-in trusted-init LuCI link convention

Fresh as of: 2026-10-27. The owner approved an opt-in convention on 2026-10-27. After two
review rounds, the owner also decided to state the assumption rather than prove it.

## Why

The strict `luci-module-setglobal` index trusts a module's top level only when it does
nothing but declare itself and define functions. Any other call there could, in
principle, run code that replaces those definitions, so the module is marked dynamic.
One dynamic module degrades every cross-file answer in the corpus.

On the 55 public LuCI 23.05 modules that declare `module("luci...")`, 41 are refused.
The cause is the standard idiom (`local util = require "luci.util"`, `local t = {}`, a
field read before `module(...)`), not code that actually redefines exports. Cross-file
caller answers on real LuCI are therefore always degraded.

The new convention lets a user opt into one stated assumption. Answers that rely on it
carry a machine-readable label, so it is never presented as a plain fact.

## Claim

Selecting `--link-convention luci-module-trusted-init` changes only the behaviors below.
The precise user-facing statement is in
[MACHINE-INTERFACE](MACHINE-INTERFACE.md#luci-module-trusted-init-opt-in-assumption-labeled).

1. **Strict admissions unchanged.** A module the strict convention admits, ignores or
   limits is treated identically, and needs no assumption.
2. **The assumption, `trusted-init`, is stated, not proved.** Code run during module
   initialization does not replace, remove or alias any module's exported functions, or
   change a module's environment. That includes the root's own statements, same-file
   functions, and anything reached through values luad does not identify.
3. **Visible refusals, kept because they are cheap.** These leave the module in
   `dynamic_artifacts`, which degrades the whole corpus as strict refusals do:
   - no single literal `module` declaration that dominates every reachable root exit;
   - a second `GETGLOBAL module`;
   - a `GETGLOBAL setfenv`/`getfenv`, possibly copied by `MOVE`, used as a call target;
   - failed validation.

   Exceeding the existing `MAX_MODULE_INIT_*` caps is `ANA-LIMIT-001`. The pass is one
   linear scan of the root's instructions plus the shared root store analysis. Nested
   prototypes are not visited, so nesting depth adds no admission work.
4. **Exports, per name.** A root `SETGLOBAL` of a closure is a clean export only when all
   of these hold:
   - it is the name's only root store;
   - it is dominated by the declaration;
   - it is in a block that dominates every reachable exit;
   - its value's evidence lies in the store's block.

   Any other store makes `M.name` a dynamic prefix. A store the declaration does not
   dominate also makes `name` dynamic. Declaration options other than `package.seeall`
   make `M` dynamic.
5. **Labels.**
   - When the index holds any trust-admitted module, every `resolved`, `absent` and
     `duplicate` link carries `assumptions: ["trusted-init"]`.
   - Cross-chunk caller bases copy it, and the callers summary gains `assumptions` and
     `assumed_providers`.
   - Strict output is byte-identical: the fields are omitted when empty.
   - `degraded`, `coverage_complete` and the exit codes keep their meaning.

## Gates (commands that pass or fail)

- `cargo test -p luad-oracle --test test_trusted_init_linking` covers:
  - admissions;
  - per-name dynamic stores;
  - visible refusals;
  - the labeled examples the assumption covers, including both round-2 review
    findings;
  - strict answers staying unlabeled;
  - a hostile deep-nesting run through the CLI, which finishes in well under a second.
- `cargo test -p luad-oracle --test test_callers_luci_trusted_init` covers:
  - **Source-line oracle** on the vendored subset. Precision: each cross-file caller
    calls the target through its namespace or a name the file binds to it. Recall:
    every literal `luci.x.f(` call is found or degraded.
  - **Pinned counts** of 70, 39 and 0.
  - **Oracle negative controls**: shifted, renamed and re-namespaced callers are
    rejected.
- `cargo test -p luad-oracle --test test_callers_luci_corpus --test
  test_cross_chunk_linking`: strict behavior unchanged.
- `bash scripts/check.sh` passes.

## Local evidence (not in the repo)

- **Independent source-line oracle over all 55 public modules.** The tool and its
  output are in `evidence/trusted-init-oracle55/` of the private workspace.
  - Of 528 resolved links, 526 are cross-file, and 526 of 526 match source.
  - 0 resolved links lack the label.
  - 218 of 218 literal `luci.x.f(` calls to top-level functions of corpus modules are
    found.
  - Negative control: shifting every reported line by one yields 482 mismatches.
- **Strict byte identity.** 1,691 strict commands (export plus every root-child
  `callers` query, JSON and text) were compared between main and the branch. The
  export stream was re-checked at the simplified head.
- **Mutation.** 12 of 12 implementation mutants are killed.

## Out of scope

- Proving the assumption. ROADMAP records when to revisit that.
- Nested exports such as `function net.routes()`: `net = {}` makes them dynamic, and
  they are not indexed.
- Other dialects.
- The Python export consumer's caller recomputation stays strict-only (ROADMAP
  Hardening).

## Review history

1. **Design review, round 1** rejected the dataflow design for unspecified transfer
   rules. Round 2 rejected it again over same-file closures.
2. **Code review, round 1** rejected the dataflow version with three P1s, all fixed:
   untracked-value writes, rebound locals, and `_G.module` spellings.
3. **Code review, round 2** rejected it again with two new P1s: calls through
   unidentified values (`rawget(_G, "setfenv")(...)`), and tables returned by
   metamethods. The owner then chose to state the assumption.

   That removed the dataflow, including the unmemoized upvalue recursion that the round
   2 review flagged as exponential on crafted nesting. Both round-2 findings are now
   pinned as examples the assumption covers.
4. **One fresh code review of the simplified version** is scoped to boundedness,
   mislabeling, strict-mode changes and crashes. Its result is recorded in the PR.
