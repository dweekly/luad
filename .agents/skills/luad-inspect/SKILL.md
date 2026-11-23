---
name: luad-inspect
description: Use the luad CLI to trace a string in a compiled PUC Lua artifact to instruction uses and observed Lua 5.1 callers, including stripped chunks.
---

Start with `luad --version` and `luad inspect FILE -f json | jq '{input_identity, interpretation}'`. Retain the artifact hash, profile and declared layout alongside any IDs. For public source experiments use an explicit compiler, e.g. a stock Lua 5.1.5 `luac -s -o module.luac module.lua`. Identify these as locally compiled inputs. Compiling requires no module execution.

**Find the instruction.** Check `luad xrefs --help` for `--to-string`. When available, `luad xrefs FILE --to-string 'Usage: ' -f json` finds indexed references to exact UTF-8 bytes in every prototype. Pass literal characters in argv, including a real newline if needed. A fragment uses `luad query FILE --where 'string contains "Usage"' -f json`. Follow each matched constant ID with `luad xrefs FILE --to ID -f json`. Read `is_truncated` and follow the returned cursor before treating a query page as complete.

On packaged 0.4.1, quoted query comparisons can mistake escaped display text for the bytes. For control characters, backslashes or binary strings, use `luad export FILE --facts constant` and select the exact byte array, e.g. with jq:
```sh
jq -c 'select(.record_type == "constant" and .data.value.value.raw_bytes? == [10]) | .data.id'
```
When `query` or `xrefs` exits 4 because semantic analysis is unavailable, the same constant export can still answer a pool-membership question. For absence, check that each intended file succeeded, `is_truncated` is false, emitted and available fact counts agree, and the final totals cover the inputs. Report the constant ID and encoded record offset. An instruction use needs separate evidence, such as a matching official `luac -p -l -l` listing. For profiles with xrefs, follow the pool ID with `xrefs --to`.

On 0.4.1, combining `--from` and `--to` silently ignores the source filter. Check the returned edge's source yourself.

**Follow a use.** `proto:0/2:k:1` names pool slot 1 of prototype path `0/2`. A read identifies a physical PC in that artifact. Use the instruction ID with `luad explain FILE proto:0/2:pc:9`. For one-hop incoming calls, use `luad callers FILE --proto 0/2 -f json`. Include other artifacts only when they belong to the question's corpus. Read `param#0["options"]` as the options field of the caller's first parameter. For a generic `field` summary, inspect the argument JSON for the full base and key. Packaged 0.4.1 uses the generic summary for every field.

Report observed callers with the corpus, per-file `.data.files[].counts.unattributed`, degradation and any assumptions. A complete inventory can contain unattributed sites. A closure passed to a native callback API can have zero observed Lua callers. A constant read proves an instruction references a value. To name a source function in a stripped build, cite an independent source mapping or describe it by artifact and prototype path.
