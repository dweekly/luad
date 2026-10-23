"""Fair caller-task comparison on luci.sys across tools, builds and number layouts.

Task: given only a distinctive constant that appears in a function's body (what an
analyst searching a stripped image would have), find that function and list every call
site with its first argument (a literal value, or "<expr>" for anything else).

Ground truth comes from the Lua source. Each tool's glue receives only the handle
constant and the compiled chunk; the glue line counts are recorded. Chunks are compiled,
never executed.

Usage:
    python3 -I scripts/compare/luci_caller_tasks.py --sys tests/corpus/luci-23.05/.../sys.lua \
        --luac51 LUAC --lnum32-luac LNUM32_LUAC --luad LUAD --unluac UNLUAC \
        [--rizin NAME=PATH ...] --out OUT_JSON
The LNUM32 compiler comes from scripts/build_lua51_openwrt_lnum32.sh.
"""

import argparse
import inspect
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

STOCK_LUAC = LUAD = UNLUAC = None
RIZIN = {}
TASKS = [
    {"target": "init_action", "handle": "env -i %s%s %s >/dev/null"},
    {"target": "xclose", "handle": "fileno"},
]


def truth(source, name):
    out = []
    for line in source.splitlines():
        if re.search(r"function\s+" + name + r"\b", line):
            continue
        for m in re.finditer(r"(?<![\w.:])" + name + r"\(\s*([^,)]*)", line):
            arg = m.group(1).strip()
            out.append(
                arg[1:-1] if arg.startswith('"') and arg.endswith('"') else "<expr>"
            )
    return sorted(out)


def run(argv):
    start = time.monotonic()
    out = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False)
    return out, time.monotonic() - start


# --- luad: constant records locate the prototype; `callers` answers.
def luad(chunk, handle):
    out, t1 = run([LUAD, "export", chunk, "--facts", "constant"])
    protos = set()
    for line in out.stdout.splitlines():
        r = json.loads(line)
        inner = (
            r.get("data", {}).get("value", {}).get("value")
            if r.get("record_type") == "constant"
            else None
        )
        if isinstance(inner, dict) and inner.get("display") == handle:
            protos.add(r["data"]["id"].rsplit(":k:", 1)[0].removeprefix("proto:"))
    if len(protos) != 1:
        return None, t1, f"handle found in {len(protos)} prototypes"
    doc, t2 = run([LUAD, "callers", chunk, "--proto", protos.pop(), "-f", "json"])
    answer = []
    for c in json.loads(doc.stdout)["data"]["callers"]:
        arg = c["argument_window"].get("arguments", [{}])[0].get("origin", {})
        answer.append(
            arg["value"]["value"]["display"]
            if arg.get("kind") == "literal"
            else "<expr>"
        )
    return sorted(answer), t1 + t2, None


# --- unluac-rs: decompile, take the function whose body holds the handle, grep its calls.
#
def unluac(chunk, handle):
    out, t = run([UNLUAC, "-D", "lua5.1", "-i", chunk])
    if out.returncode != 0:
        return None, t, out.stderr.strip()[:120]
    lines = out.stdout.splitlines()
    pattern = re.compile(
        r'"' + re.escape(handle) + r'"|[.:]' + re.escape(handle) + r"\b"
    )
    hit = next((i for i, l in enumerate(lines) if pattern.search(l)), None)
    if hit is None:
        return None, t, "handle not in decompiled text"
    header = next(
        l
        for l in reversed(lines[: hit + 1])
        if re.match(r"\s*(local\s+)?function\s+\w+\(", l)
    )
    name = re.match(r"\s*(?:local\s+)?function\s+(\w+)\(", header).group(1)
    answer = []
    for l in lines:
        if re.search(r"function\s+" + name + r"\(", l):
            continue
        for m in re.finditer(r"(?<![\w.:])" + name + r"\(\s*([^,)]*)", l):
            arg = m.group(1).strip()
            answer.append(
                arg[1:-1] if arg.startswith('"') and arg.endswith('"') else "<expr>"
            )
    return sorted(answer), t, None


# --- official luac -l: follow the closure into its parent's register, the upvalue
# bindings into children, and GETUPVAL/MOVE into CALL.
def luac_listing(chunk, handle, luac=None):
    out, t = run([str(luac or STOCK_LUAC), "-l", "-l", "-p", chunk])
    if out.returncode != 0:
        return None, t, out.stderr.strip().splitlines()[-1][:120]
    funcs, constants, cur, section = {}, {}, None, None
    for line in out.stdout.splitlines():
        h = re.match(r"(main|function) <.*> \(.* at (0x[0-9a-f]+)\)", line)
        if h:
            cur, section = h.group(2), "code"
            funcs[cur] = []
            continue
        k = re.match(r"(constants|locals|upvalues) \(\d+\) for (0x[0-9a-f]+):", line)
        if k:
            section = k.group(1)
            continue
        if section == "constants":
            constants.setdefault(cur, set()).add(line.split("\t")[-1])
            continue
        m = re.match(r"\s+\d+\s+\[[-\d]+\]\s+(\w+)\s+([-\d ]+?)\s*(?:;\s*(.*))?$", line)
        if m and cur:
            funcs[cur].append(
                (m.group(1), [int(x) for x in m.group(2).split()], m.group(3) or "")
            )
    target = [a for a in funcs if '"' + handle + '"' in constants.get(a, set())]
    if len(target) != 1:
        return None, t, f"handle in {len(target)} functions"
    target = target[0]
    answer = []

    def first_arg(ins, call_index, base):
        for op, args, c in reversed(ins[:call_index]):
            if args and args[0] == base + 1:
                return c[1:-1] if op == "LOADK" and c.startswith('"') else "<expr>"
        return "<expr>"

    for ins in funcs.values():
        for i, (op, args, c) in enumerate(ins):
            if op != "CLOSURE" or c.strip() != target:
                continue
            reg = args[0]
            for j in range(i + 1, len(ins)):
                op2, a2, c2 = ins[j]
                if (
                    op2 == "MOVE"
                    and a2[1] == reg
                    and j + 1 < len(ins)
                    and ins[j + 1][0] == "CALL"
                    and ins[j + 1][1][0] == a2[0]
                ):
                    answer.append(first_arg(ins, j + 1, a2[0]))
                if op2 != "CLOSURE":
                    continue
                child = c2.strip()
                bound = [
                    k
                    for k, (b, ba, _) in enumerate(ins[j + 1 : j + 61])
                    if b in ("MOVE", "GETUPVAL") and ba[0] == 0
                ]
                slots = [
                    k
                    for k in bound
                    if ins[j + 1 + k][0] == "MOVE" and ins[j + 1 + k][1][1] == reg
                ]
                for slot in slots:
                    cins = funcs.get(child, [])
                    for p, (cop, cargs, _) in enumerate(cins):
                        if cop == "GETUPVAL" and cargs[1] == slot:
                            call = next(
                                (
                                    q
                                    for q in range(p + 1, len(cins))
                                    if cins[q][0] == "CALL"
                                    and cins[q][1][0] == cargs[0]
                                ),
                                None,
                            )
                            if call is not None:
                                answer.append(first_arg(cins, call, cargs[0]))
    return sorted(answer), t, None


# --- Rizin: locate the handle string, its owning function, then that function's xrefs.
#
def rizin(binary, chunk, handle):
    out, t = run([binary, "-q", "-c", "aaa; izj", chunk])
    if "Invalid luac proto" in out.stderr:
        return None, t, "refused: " + out.stderr.strip().splitlines()[0][:100]
    try:
        strings = json.loads(out.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return None, t, "no string table"
    hit = next((s for s in strings if s.get("string") == handle), None)
    if hit is None:
        return None, t, "handle string not listed"
    xrefs, t2 = run([binary, "-q", "-c", f"aaa; axtj @ {hit['vaddr']}", chunk])
    count = xrefs.stdout.count('"from"')
    return (
        None,
        t + t2,
        f"string found with {count} xrefs; no method established to map it to call sites",
    )


def glue_lines(function):
    """Non-blank, non-comment source lines of one tool's glue function."""
    return sum(
        1
        for line in inspect.getsource(function).splitlines()[1:]
        if line.strip() and not line.strip().startswith("#")
    )


def main():
    global STOCK_LUAC, LUAD, UNLUAC
    parser = argparse.ArgumentParser()
    for name in ["sys", "luac51", "lnum32-luac", "luad", "unluac", "out"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--rizin", action="append", default=[])
    args = parser.parse_args()
    STOCK_LUAC, LUAD, UNLUAC = Path(args.luac51), args.luad, args.unluac
    RIZIN.update(item.split("=", 1) for item in args.rizin)
    source_path, lnum32, out_path = (
        Path(args.sys),
        Path(args.lnum32_luac),
        Path(args.out),
    )
    source = source_path.read_text()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        builds = {}
        for layout, compiler in (("stock", STOCK_LUAC), ("lnum32", lnum32)):
            for kind, flags in (("debug", []), ("stripped", ["-s"])):
                chunk = str(Path(tmp) / f"sys-{layout}-{kind}.luac")
                subprocess.run(
                    [str(compiler), *flags, "-o", chunk, str(source_path)], check=True
                )
                builds[(layout, kind)] = chunk
        for task in TASKS:
            expected = truth(source, task["target"])
            for (layout, kind), chunk in builds.items():
                handle = task["handle"]
                tools = [
                    ("luad", luad, (chunk, handle)),
                    ("unluac-rs 1.4.4", unluac, (chunk, handle)),
                    ("luac 5.1.5 -l", luac_listing, (chunk, handle)),
                    ("OpenWrt LNUM32 luac -l", luac_listing, (chunk, handle, lnum32)),
                ]
                tools += [(n, rizin, (b, chunk, handle)) for n, b in RIZIN.items()]
                for name, fn, fn_args in tools:
                    answer, elapsed, note = fn(*fn_args)
                    rows.append(
                        {
                            "task": task["target"],
                            "layout": layout,
                            "build": kind,
                            "tool": name,
                            "answer": answer,
                            "correct": answer == expected,
                            "elapsed_s": round(elapsed, 3),
                            "note": note,
                        }
                    )
            rows.append({"task": task["target"], "truth": expected})
    glue = {
        "luad": glue_lines(luad),
        "unluac-rs": glue_lines(unluac),
        "luac -l -l": glue_lines(luac_listing),
        "rizin": glue_lines(rizin),
    }
    out_path.write_text(json.dumps({"glue_lines": glue, "rows": rows}, indent=1) + "\n")
    print("glue lines:", glue)
    for r in rows:
        if "truth" in r:
            print(f"== {r['task']} truth {r['truth']}")
        else:
            print(
                f"{r['task']:11} {r['layout']:6} {r['build']:8} {r['tool']:17} correct={r['correct']!s:5} t={r['elapsed_s']:<6} {r['note'] or ''}"
            )


if __name__ == "__main__":
    main()
