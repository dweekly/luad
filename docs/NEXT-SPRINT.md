# Sprint: opt-in trusted-init LuCI link convention

Fresh as of: 2026-10-27. The owner approved an opt-in convention on 2026-10-27.

**Status: held.** The second code-review round found two new blockers, recorded at the
end of this file. By the review rule, a new blocker on round two means the approach
needs an owner decision before a third round. Do not merge until then.

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
     returns a module namespace table itself; what such a result holds is not assumed.
     The exceptions are the namespace sources in item 5 and the pass-through builtins
     (`assert`, `rawget`, `select`, `unpack`, `next`).
   - Initialization completes without error.

   Everything the root prototype's own instructions do is checked, never assumed. That
   includes same-file functions that assign a root local the root later uses (item 5).
4. **Tokens.** Every register holds a set of tokens, joined by union at CFG merges and
   iterated to a fixpoint:
   - `Path(own|global, segments, exact)` is a table reached by global lookup. A global
     `X` yields both `own:[X]` and `global:[X]`, because `package.seeall` falls back to
     `_G`. `_G` yields `global:[]`, `_M` yields `own:[]`, and `own` paths are prefixed
     with the module name `M`.
   - `Fresh(site)` is a table this root made at one `NEWTABLE`.
     - What each site may hold is tracked by key: a constant admitted key, or "any" for
       other keys and list items. That is flow-insensitive, and the whole pass repeats
       until the contents settle (at most 8 rounds).
     - Whether the site has been released (handed to code the analysis does not
       follow) is flow-sensitive state, joined by union.
   - `Module` is the global `module`.
   - `Literal` is a string `LOADK`.
   - `AnyNamespace` is a namespace table the analysis cannot name.
   - `CallResult` is a call result: not a namespace table, under the assumption.
   - `Unknown` is any value at all, possibly a namespace table. It comes from:
     - a field read from a `CallResult` or `Unknown`;
     - a generic-`for` value;
     - a field of a released fresh table;
     - a root local that same-file code may rebind;
     - what a callee left in registers its frame overlapped.
   - `Opaque` is a non-table: a scalar, a closure, `nil`, or the initial frame.
5. **Transfer.** The instruction's lifted `writes` become `Opaque`, then:
   - **Calls clobber.** After `CALL`/`TAILCALL`, registers `A..A+C-2` (to the top when
     `C = 0`) hold the result tokens. Every other register from `A` up becomes
     `Unknown`; for `TFORLOOP`, those from `A+3` up.
   - **Rebound locals.** A root register that a root closure captures, and that the
     closure or a function nested in it assigns (`SETUPVAL`), becomes `Unknown` after
     every instruction that can run code: anything but moves, loads, global access,
     `NEWTABLE`, `CLOSURE`, jumps, tests, `RETURN`, `VARARG` and `SETLIST`.
   - **Reads and moves.**
     - `MOVE` copies the set, and `TESTSET` joins it.
     - `GETGLOBAL` yields the paths above, or `Module` for `module`. A name no admitted
       label can spell yields `AnyNamespace`.
     - `GETTABLE`/`SELF` on `Path(p, exact)` with a constant admitted key `k` yields
       `Path(p.k, exact)`; any other key yields `Path(p, inexact)`.
     - `package.loaded[name]` yields the path `name`, or `AnyNamespace` when the key is
       not a constant name.
     - A read from `Fresh(site)` yields what the site may hold under that key, plus
       `Opaque`, plus `Unknown` once the site is released.
     - Reads from `CallResult`/`Unknown` yield `Unknown`, and reads from `AnyNamespace`
       yield `AnyNamespace`.
     - `NEWTABLE` yields `Fresh(pc)`. `SETLIST` leaves its table register's set
       unchanged.
   - **Writes.** `SETTABLE`/`SETLIST`:
     - into a `Path` marks `p.k` (exact path and constant admitted key) or `p`;
     - into an unreleased `Fresh(site)` records the value in the site's contents;
     - into a released fresh table, `Unknown`, `AnyNamespace` or `Module` refuses the
       whole corpus. A callee may have given a released table a forwarding
       `__newindex`;
     - into `CallResult` or `Opaque` is permitted under the assumption.
   - **Named stores.** A value stored only under names the analysis follows does not
     escape: it goes to fresh-table fields, to an exact path with a constant key, or
     to a `SETGLOBAL` name.
     - An exact `Path` value stored under a name becomes an alias of it. A mark under
       the alias later also marks the source, followed transitively, with at most 4096
       resolved marks.
     - An `Unknown` value stored under a name makes any mark under that name refuse
       the whole corpus.
     - Any other stored value escapes.
   - **Escapes.**
     - An escaping `Path` marks it.
     - An escaping `Fresh(site)` is released, and everything it may hold escapes,
       recursively.
     - `Module` (or any path spelled `module`), `AnyNamespace` or an environment
       mutator refuses the whole corpus.
   - **Calls.**
     - The declaration is `F = {Module}` with `C = 1` and a single literal name.
     - Any other call whose `F` may be `module` (including `_G.module`) refuses the
       whole corpus.
     - Calling an environment mutator refuses the whole corpus, and so does calling an
       `AnyNamespace` value (it could be one). The environment mutators are `setfenv`,
       `debug.setfenv`, `debug.setmetatable`, `debug.setupvalue`, `debug.setlocal`, and
       an inexact `_G[k]` or `debug[k]`.
     - Arguments to the mutating builtins (`setmetatable`, `getmetatable`, `rawset`)
       escape, and an `Unknown` argument to one refuses.
     - Arguments to any other callee are covered by the assumption, with two
       exceptions: fresh tables passed to it are released, and passing `module` or an
       environment mutator refuses.
     - Namespace sources return `AnyNamespace`: `getfenv`, `debug.getfenv`,
       `debug.getregistry`, `debug.getlocal` and `debug.getupvalue`. So does any call
       that receives one of them as an argument.
     - `require` of a constant admitted dotted name returns that `Path`; any other
       `require` returns `AnyNamespace`.
     - `assert` returns its arguments' tokens; `rawget`, `select`, `unpack` and `next`
       return `Unknown`.
     - Every other call returns `CallResult`.
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

   Every other root store marks `M.name`, including a single non-closure store.
   Unlike the strict rule, such a store is not proof of absence: `module('luci');
   sys = nil` replaces the namespace that `luci.sys.*` labels rely on. A store the
   declaration does not dominate marks both `M.name` and `name`.
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
    test rejects shifted, renamed and re-namespaced callers. Of 24 implementation
    mutants, 23 are killed by these gates. The survivor sets generic-`for` result
    registers to `Opaque` and is redundant: the call-frame clobber also sets them to
    `Unknown`. The list is recorded in the PR.
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

## Code review

**Round 1** (`scripts/agents/claude-opus.sh review-fresh`) rejected the change with three
blockers, all fixed with each repro added as a negative control.

1. The root could write into values whose contents were never tracked:
   - `table.insert(t, luci.sys); t[1].exec = nil`;
   - fields of call results;
   - a callee-installed `__newindex`.

   The fix splits `CallResult` and `Unknown` out of `Opaque`, and releases fresh tables
   handed to callees, flow-sensitively.
2. A same-file closure could rebind a root local that the root then writes through.
   Such locals now become `Unknown` whenever code runs.
3. `_G.module(...)`, `pcall(_G.module, ...)` and `getfenv(0).setfenv` reached `module`
   or an environment mutator by another spelling. Any path spelled `module` is now
   treated as `module`, and calls of `AnyNamespace` values refuse.

Residual risks the review raised, and what happened to each:

- **Folded in.**
  - Pass-through builtins: `assert`, `rawget`, `select`, `unpack`, `next`.
  - Generic-`for` values.
  - Inherited `sys = nil` absence: single non-closure stores now mark.
  - A stricter precision oracle: the line must call through the namespace or a name
    the file binds to it.
  - Call-frame clobbering for `CALL` with `C = 0` or `C = 1`, whose lifted effects
    list no writes.
- **Still open.** No compiled control exercises the clobbering, because the official
  compiler never reads those registers. Only crafted bytecode would.

**Round 2** rejected again, with two new blockers. Both are open.

1. **Calls through `Unknown` values are not refused.** `Unknown` may be `setfenv`,
   `module` or `require`. Repro:

   ```lua
   rawget(_G, 'setfenv')(1, luci.sys); function exec() return 'evil' end
   ```

   Variants: `rawget(_G, 'module')(...)`, `rawget(_G, 'require')('luci.sys').exec = nil`,
   and a generic `for` over `_G` that calls what it finds.

   The suggested fix is to refuse `Unknown` callees, or model `rawget(Path, k)` like
   `GETTABLE`. Neither is measured. Refusing `Unknown` callees would refuse common
   `obj:method()` calls on call results, such as `uci.cursor():get(...)`, so it needs a
   corpus measurement first.
2. **Arithmetic, concat, unary minus and length results are typed `Opaque`.** A
   metamethod can return any table. Repro: `local o = u.wrap() .. ''; o.sys.exec = nil`.
   The fix is to type those results `CallResult` or `Unknown` whenever an operand may be
   a table.

Residual risks from round 2:

- `assigned_upvalues` recurses into nested `CLOSURE`s without memoization. In hostile
  bytecode where many `CLOSURE`s name the same child at every level, work could grow
  exponentially. It needs a memo or budget.
- Each block visit clones the whole frame, so the work is block visits x block length x
  256, for up to 8 rounds.
- Metatables of strings or functions pointed at namespaces by required code.
- Writes into `getmetatable(<CallResult>)` when that metatable is shared with a
  namespace's metatable.
- There is still no crafted-bytecode control for the call-frame clobbering.

`ModuleExportIndex` does not derive `Serialize`, so the new fields cannot change strict
output; the reviewer's concern there does not apply.

**Pattern for the owner.** Each round finds another way for unconstrained code to hand
the root a namespace, or a namespace-changing function, through a value the token model
calls safe. The alternatives:

- (a) Keep tightening: `Unknown` callees, operator results and memoized recursion.
  Measure each change against the 55-module corpus.
- (b) Accept a broader assumption: the root itself never writes through, or calls,
  values it obtained from code outside the module. This is simpler, but more of the
  answer is assumed rather than checked.
- (c) Narrow the convention: admit only roots whose non-declarative code is `require`
  of literal names, table constructors and stores into fresh tables. That is the shape
  of most refused modules (33 of 41 first refusals were `require` calls). Refuse
  everything else. Unmeasured: it would refuse util at least, whose root writes into
  `getmetatable("")`.
