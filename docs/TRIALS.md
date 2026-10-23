# Outside trial kit

This kit lets someone outside the development loop try `luad` on public inputs without
coaching, so the roadmap's question can be answered honestly: does `luad` give a
concrete reason to choose or embed it? It defines the participants, what to hand them,
the questions and success assertions fixed in advance, and what to record. The answer
key is stored only as hashes, so the repository does not give the answers away.

Recruiting and contacting participants is the maintainer's decision; this file
authorizes no outreach.

## Participants

Two people, as roadmap D requires:

- **A firmware researcher**, who is used to extracted router images. Tasks T1a–T3.
- **A Lua tool author or maintainer** (decompiler, loader, or analysis tooling). Task
  T4, plus any of T1a–T3 they choose.

Neither has seen this repository's tests, fixtures, or evidence beforehand.

## What to hand them

1. **The packaged release** they will install: the latest experimental GitHub release,
   with its install instructions from the site.
2. **The inputs**, built by the moderator with
   `scripts/trials/build_inputs.sh OUT LUAC51 LNUM32_LUAC`. The arguments are official
   Lua 5.1.5 `luac` and the OpenWrt LNUM32 `luac` from
   `scripts/build_lua51_openwrt_lnum32.sh`. `OUT/firmware/usr/lib/lua/luci/` is a
   stripped OpenWrt-layout tree compiled from the vendored LuCI 23.05 subset, keeping
   the `.lua` names as devices do. `OUT/releases/` holds stripped stock builds of
   `luci.util` from 22.03 and 23.05. `OUT/SHA256SUMS` pins every file. Nothing is
   executed.
3. **The public site and the repository README.** Nothing else: no recipes pointed out,
   no hints, and no walkthrough.

They may use any other tools they like (a decompiler, the official `luac`, Rizin,
scripts). Record what they choose.

## Questions and success assertions

Ask each question exactly as written. An answer is correct only when
`python3 -I scripts/trials/check_answer.py <task> "<answer>"` prints `correct`. The checker
compares the answer's sorted, lower-case token set with a stored hash.

- **T1a.** In `firmware/usr/lib/lua/luci/sys.lua`, one function's body checks for
  `/etc/ethers`. How many call sites call that function? Give a number.
- **T1b.** Which distinct values do those call sites pass as the first argument?
- **T2.** In the same file, one function's body calls a `fileno` method. How many call
  sites call that function? Give a number.
- **T3.** Between `releases/util-22.03.luac` and `releases/util-23.05.luac`, which named
  functions changed or disappeared? Write table members as `table.member`.
- **T4.** For `firmware/usr/lib/lua/luci/sys.lua` and `releases/util-23.05.luac`, give
  each file's `size_t` width in bytes, and whether a stock 64-bit official `luac` 5.1.5
  can list it. Use the form `name=width=yes|no` for each.

Correct answers come from the Lua source and the tools' documented behavior, not from
`luad`. The inputs are public, and T3's answer also appears in the repository's recipes
and tests. Record whether a participant read them; an answer copied from docs is not a
tool result. A participant who answers with another tool scores the same as one who uses
`luad`.

## What to record

For each participant and task, record:
- the tools used, in order;
- the time to a first answer and the total time;
- the answer and whether the checker accepted it;
- any glue they wrote (the line count, and the code if they agree);
- installation problems;
- every error, refusal or misleading output they hit, quoted;
- any misconception about what `luad` claims;
- whether they would choose or embed `luad` for that task, and why, in their own words.

Do not correct them mid-task. Note where they got stuck and what they tried. Afterwards,
turn each blocking error or misconception into an issue.

## Reporting

Keep sanitized records (no private firmware, no personal details beyond a role) with
the release evidence or a PR, and update the dated comparison in
[PRIOR-ART-AND-CORPORA.md](PRIOR-ART-AND-CORPORA.md) from what was observed. If no task
shows a concrete reason to choose `luad`, the roadmap says to narrow the product rather
than add features.
