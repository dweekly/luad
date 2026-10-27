# Sprint: opt-in trusted-init LuCI link convention

Fresh as of: 2026-10-27. The owner approved an opt-in convention on 2026-10-27.

## Why

The strict `luci-module-setglobal` index trusts a module's top level only when it does
nothing but declare itself and define functions. Any other call there could, in
principle, run code that replaces those definitions, so the module is marked dynamic.
One dynamic module degrades every cross-file answer in the corpus. On the 55 public
LuCI 23.05 modules that declare `module("luci...")`, 41 are refused. The cause is the
standard idiom (`local util = require "luci.util"`, `local t = {}`, a field read before
`module(...)`), not code that actually redefines exports. Cross-file caller answers on
real LuCI are therefore always degraded.

The new convention lets a user opt into one stated assumption. Answers that rely on it
carry a machine-readable label, so it is never presented as a plain fact.

## Claim

Selecting `--link-convention luci-module-trusted-init` changes only these behaviors.

1. **Strict admissions unchanged.** A module that the strict convention admits, ignores
   or limits is treated identically, and needs no assumption.
2. **Trusted admission.** A Lua 5.1 module that the strict convention refuses as dynamic
   is re-examined (`crates/luad-analysis/src/trusted_init.rs`).
3. **The assumption, `trusted-init`.** It covers only what the root prototype cannot show:
   - No function that runs during initialization, other than the root itself and the
     mutating builtins `setmetatable`, `getmetatable` and `rawset` called by those names,
     defines, replaces or removes a function in a module namespace. Nor does it change a
     module's environment or metatable, including metatables already in effect. That
     covers required modules, other library functions, and same-file functions however
     they are called.
   - `require(name)` returns the table at the global dotted path `name`. No other call
     returns a module namespace table, except the namespace sources listed in item 5.
   - Initialization completes without error.

   Everything the root prototype's own instructions do is checked, never assumed.
4. **Tokens.** Every register holds a set of tokens, joined by union at CFG merges and
   iterated to a fixpoint:
   - `Path(own|global, segments, exact)` is a table reached by global lookup. A global
     `X` yields both `own:[X]` and `global:[X]`, because `package.seeall` falls back to
     `_G`. `_G` yields `global:[]`, `_M` yields `own:[]`, and `own` paths are prefixed
     with the module name `M`.
   - `Fresh(site)` is a table this root made at one `NEWTABLE`. What each site may hold
     is tracked by key: a constant admitted key, or "any" for other keys and list
     items. It is flow-insensitive, and the whole pass repeats until the contents
     settle (at most 8 rounds).
   - `Module` is the global `module`.
   - `Literal` is a string `LOADK`.
   - `AnyNamespace` is a namespace table the analysis cannot name.
   - `Opaque` is anything else: call results other than namespace sources, closures,
     arithmetic, and the initial frame.
5. **Transfer.** The instruction's lifted `writes` become `Opaque`, then:
   - **Reads and moves.**
     - `MOVE` copies the set, and `TESTSET` joins it.
     - `GETGLOBAL` yields the paths above, or `Module` for `module`. A name no admitted
       label can spell yields `AnyNamespace`.
     - `GETTABLE`/`SELF` on `Path(p, exact)` with a constant admitted key `k` yields
       `Path(p.k, exact)`; any other key yields `Path(p, inexact)`.
     - `package.loaded[name]` yields the path `name`, or `AnyNamespace` when the key is
       not a constant name.
     - A read from `Fresh(site)` yields what the site may hold under that key, plus
       `Opaque`. Reads from `Opaque` yield `Opaque`, and reads from `AnyNamespace` yield
       `AnyNamespace`.
     - `NEWTABLE` yields `Fresh(pc)`. `SETLIST` leaves its table register's set
       unchanged.
   - **Writes.** `SETTABLE`/`SETLIST`:
     - into a `Path` marks `p.k` (exact path and constant admitted key) or `p`;
     - into `Fresh(site)` records the value in the site's contents;
     - into `AnyNamespace` or `Module` refuses the whole corpus;
     - into `Opaque` is permitted under the assumption.
   - **Named stores.** A value stored only under names the analysis follows does not
     escape: it goes to fresh-table fields, to an exact path with a constant key, or
     to a `SETGLOBAL` name.
     - An exact `Path` value stored under a name becomes an alias of it. A mark under
       the alias later also marks the source, followed transitively, with at most 4096
       resolved marks.
     - Any other stored value escapes.
   - **Escapes.**
     - An escaping `Path` marks it.
     - An escaping `Fresh(site)` escapes everything the site may hold, recursively.
     - `Module`, `AnyNamespace` or an environment mutator refuses the whole corpus.
     - Arguments to the mutating builtins (`setmetatable`, `getmetatable`, `rawset`)
       escape.
     - Arguments to other callees are covered by the assumption, except that passing
       `Module` or an environment mutator refuses.
   - **Calls.**
     - The declaration is `F = {Module}` with `C = 1` and a single literal name.
     - Any other call with `Module` in `F` refuses the whole corpus.
     - Calling an environment mutator refuses the whole corpus: `setfenv`,
       `debug.setfenv`, `debug.setmetatable`, `debug.setupvalue`, `debug.setlocal`, or
       an inexact `_G[k]` or `debug[k]`.
     - Namespace sources return `AnyNamespace`: `getfenv`, `debug.getfenv`,
       `debug.getregistry`, `debug.getlocal` and `debug.getupvalue`. So does any call
       that receives one of them as an argument.
     - `require` of a constant admitted dotted name returns that `Path`; any other
       `require` returns `AnyNamespace`.
6. **Declaration.**
   - `module` must be loaded exactly once, and exactly one call must declare it.
   - The literal name is admitted exactly as in the strict rule.
   - The declaring call's block must dominate every reachable root exit.
   - Options other than a lone `package.seeall` receive the module table and may
     change its metatable, so they mark the whole namespace `M` dynamic.
   - Anything else refuses the whole corpus.
   - A refused module goes into `dynamic_artifacts`. That degrades every link in the
     corpus, exactly as strict refusals do today.
7. **Exports.** Only root `SETGLOBAL`s of closures to admitted names can be clean
   exports, and each must meet all of the following:
   - the name is stored exactly once in the root;
   - the store is dominated by the declaration;
   - its block dominates every reachable exit;
   - every instruction in the value's evidence lies in the store's block, at or before
     the store, so path-insensitive value transfer cannot have merged values.

   A dominated store that fails any condition marks `M.name`. A non-closure value is the
   exception: when it is single, unconditional and in-block, it marks nothing, as in
   the strict rule. An undominated store marks both `M.name` and `name`.
8. **Marks and resolution.**
   - A label is dynamic when some mark is a prefix of it, and it resolves `dynamic` with
     the mark's evidence.
   - Labels under a mark are always considered for linking.
   - A mark that resolves to the empty root namespace refuses the whole corpus.
   - When the index holds at least one trust-admitted module, every `resolved`,
     `absent` and `duplicate` link fact carries `assumptions: ["trusted-init"]`. That
     includes links to modules admitted strictly, because duplicate and absence claims
     also rest on what trust-admitted modules define. Otherwise the field is omitted.
   - Exceeding any cap (`MAX_MODULE_INIT_WORDS`, `MAX_MODULE_INIT_CONSTANT_BYTES`,
     31-segment paths, 32-token register sets, or `16 x blocks + 64` block visits) is
     `ANA-LIMIT-001`, never a partial admission.
9. **Callers.**
   - A cross-chunk caller basis copies the link's `assumptions`.
   - The callers summary gains `assumptions` and `assumed_providers`; both are omitted
     when empty.
   - `degraded`, `coverage_complete` and the exit codes keep their meaning. An
     assumption the user selected is labeled, not counted as degradation.
   - Strict-convention output is byte-identical: the new fields are absent.

## Gates (commands that pass or fail)

- `cargo test -p luad-oracle --test test_callers_luci_trusted_init` covers:
  - **Precision.** A source-line oracle, independent of luad's analyses, runs on the
    vendored `tests/corpus/luci-23.05` subset. Every cross-file caller luad reports
    under the new convention must sit on a source line that calls the target by its
    function name, and its file must name the target module in text. Cross-file links
    come only from symbolic global paths, so calls through local `require` aliases are
    outside both luad's answer and this oracle.
  - **Recall.** Every vendored source line that calls `luci.X.f(`, where `luci.X` is a
    vendored module defining a top-level `function f(`, appears as a caller or is
    classed `degraded`.
  - **Negative controls.** Each must not yield a clean `resolved` link:
    - an init that rebinds an export;
    - a conditional definition;
    - a double `module()`;
    - a root `setfenv`, including through a local alias;
    - `debug.setmetatable`;
    - `_M` passed to `setmetatable`;
    - a write into a module-own table;
    - a write into a `require` result, and into a non-literal `require`;
    - `package.loaded[name]` writes;
    - namespaces kept in, or escaping with, fresh tables;
    - writes through global aliases.

    Separate controls pin that aliases and re-exports leave their source clean, and that
    the stated gap (a callback or an unknown callee) is labeled rather than followed.
  - **Mutation.** An oracle mutation must fail. The `test_trusted_init_source_oracle_*`
    test rejects shifted and renamed callers. Fourteen implementation mutants are
    killed by these gates (recorded in the PR).
  - **Pinned counts.** The vendored-subset answer is pinned at 70 source-checked
    cross-file callers and 39 of 39 literal call sites found, so an admission change is
    a reviewed change.
- `cargo test -p luad-oracle --test test_callers_luci_corpus --test
  test_cross_chunk_linking`: strict output unchanged.
- `bash scripts/check.sh` passes.

## Out of scope

- Nested exports such as `function net.routes()`. They are marked dynamic, not indexed.
- What required modules and called functions do (the assumption).
- Other dialects.
- The Python export consumer's caller recomputation. It stays strict-only; that is
  recorded in ROADMAP.

## Design review

The design review was run twice (`scripts/agents/claude-opus.sh design-review`), and both
rounds rejected the contract.

- **Round 1** found that writes through untracked registers, such as `require` results,
  were covered neither by the tracking nor by the assumption, and that the transfer
  function was unspecified. Both are fixed: `require` results are now named, and item 5
  specifies the transfer.
- **Round 2** found that a same-file closure stored in a fresh table could run during
  initialization without being caught. The fix is to state plainly that the
  assumption covers every function body other than the root. The root's own
  instructions stay fully checked.

  The reviewer's alternative was to refuse every closure stored outside root globals.
  An implementation of that rule, which also refused writes into call results,
  refused 13 of the 55 modules, including util, http, json, cbi and template. Every
  corpus answer stayed degraded.

  The wider assumption is a judgment call the owner should confirm; it is flagged in
  the PR.
