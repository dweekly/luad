#!/usr/bin/env python3
"""Bounded, decoder-independent capture and verification of luad export JSONL.

This example verifies a producer's wire contract and accounting, not Lua semantics.
No selected fact is returned until the entire bundle has passed verification. Importers
may reuse verify_bundle(..., retain={...}); that interface remains experimental.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry
from referencing.exceptions import Unresolvable

KINDS = frozenset(
    {
        "export_start",
        "file_start",
        "prototype",
        "instruction",
        "constant",
        "upvalue",
        "xref",
        "callee",
        "call_relation",
        "prototype_identity",
        "parameter_field",
        "origin",
        "cross_chunk_link",
        "diagnostic",
        "file_end",
        "export_end",
    }
)
FACTS = KINDS - {"export_start", "file_start", "diagnostic", "file_end", "export_end"}
FAMILIES = frozenset(
    {
        "prototype",
        "instruction",
        "constant",
        "upvalue",
        "xref",
        "callee",
        "call_relation",
        "prototype_identity",
        "origin",
    }
)
PROFILES = {
    p: p if p not in {"lua5.1-stock32", "lua5.1-lnum32"} else "lua5.1"
    for p in [
        "lua5.1",
        "lua5.1-stock32",
        "lua5.1-lnum32",
        "lua5.2",
        "lua5.3",
        "lua5.4",
        "lua5.5",
    ]
}
HASH = re.compile(r"[0-9a-f]{64}\Z")


class Refusal(ValueError):
    """A bundle is incomplete, inconsistent, unknown or outside a configured bound."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


@dataclass(frozen=True)
class Limits:
    line_bytes: int = 8 * 1024 * 1024
    stream_bytes: int = 1024 * 1024 * 1024
    records: int = 2_000_000
    depth: int = 96
    files: int = 10_000
    input_bytes: int = 64 * 1024 * 1024
    inventory_bytes: int = 4 * 1024 * 1024 * 1024
    stderr_bytes: int = 1024 * 1024
    retained_bytes: int = 64 * 1024 * 1024
    seconds: int = 300


DEFAULT_LIMITS = Limits()


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def load_json(raw: bytes, limit: int, depth: int = 96):
    require(len(raw) <= limit, "JSON byte limit exceeded")
    # Bound nesting before invoking either Python's parser or recursive schema code.
    quoted = escaped = False
    level = 0
    for b in raw:
        if quoted:
            if escaped:
                escaped = False
            elif b == 92:
                escaped = True
            elif b == 34:
                quoted = False
        elif b == 34:
            quoted = True
        elif b in (91, 123):
            level += 1
            require(level <= depth, "JSON nesting limit exceeded")
        elif b in (93, 125):
            level -= 1
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                Refusal("bare nonfinite token")
            ),
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refusal("invalid JSON: " + str(error)[:160]) from error
    # JSON 1e400 is syntactically a number but outside this f64-facing reader.
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, float):
            require(math.isfinite(item), "JSON number outside finite f64 range")
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return value


def json_bytes(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def open_regular(path: Path):
    # Nonblocking open prevents a FIFO/device from stalling before fstat can reject it.
    source = open(
        path, "rb", opener=lambda name, flags: os.open(name, flags | os.O_NONBLOCK)
    )
    try:
        require(
            stat.S_ISREG(os.fstat(source.fileno()).st_mode),
            "only regular files are supported",
        )
    except Exception:
        source.close()
        raise
    return source


def checked_limits(limits):
    require(
        all(
            type(value) is int and 0 < value <= getattr(Limits(), name) * 16
            for name, value in asdict(limits).items()
        ),
        "invalid or excessive limit",
    )


def digest_file(path: Path, maximum: int, budget=None):
    digest = hashlib.sha256()
    size = 0
    with open_regular(path) as source:
        while chunk := source.read(min(65536, maximum - size + 1)):
            size += len(chunk)
            if budget is not None:
                budget[0] -= len(chunk)
                require(budget[0] >= 0, "aggregate input byte limit exceeded")
            require(size <= maximum, "file byte limit exceeded")
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "byte_length": size}


def read_small(path: Path, maximum: int):
    with open_regular(path) as source:
        result = source.read(maximum + 1)
    require(len(result) <= maximum, "small-file byte limit exceeded")
    return result


def inventory(paths, limits):
    require(0 < len(paths) <= limits.files, "input count outside limit")
    require(len(set(paths)) == len(paths), "duplicate input path")
    checked_limits(limits)
    budget = [limits.inventory_bytes]
    result = []
    for path in paths:
        require(
            isinstance(path, str)
            and path
            and path != "-"
            and "\n" not in path
            and "\r" not in path
            and "\x00" not in path
            and path == path.strip(),
            "invalid input-list path",
        )
        try:
            identity = digest_file(Path(path), limits.input_bytes, budget)
            result.append({"path": path, **identity, "readable": True})
        except OSError:
            result.append({"path": path, "readable": False})
    return result


def run_bounded(argv, stdout: Path, stderr: Path, out_limit, err_limit, seconds):
    """Drain both pipes together; cap aggregate output and kill the process group on failure."""
    require(os.name == "posix", "capture currently requires Linux or macOS")
    started = time.monotonic()
    with stdout.open("xb") as out, stderr.open("xb") as err:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(
                    process.stdout, selectors.EVENT_READ, [out, out_limit, 0]
                )
                selector.register(
                    process.stderr, selectors.EVENT_READ, [err, err_limit, 0]
                )
                while selector.get_map():
                    remaining = seconds - (time.monotonic() - started)
                    require(remaining > 0, "producer timeout")
                    for key, _ in selector.select(min(remaining, 0.1)):
                        target, maximum, used = key.data
                        chunk = os.read(
                            key.fileobj.fileno(), min(65536, maximum - used + 1)
                        )
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        require(
                            used + len(chunk) <= maximum,
                            "producer output limit exceeded",
                        )
                        target.write(chunk)
                        key.data[2] += len(chunk)
                remaining = seconds - (time.monotonic() - started)
                require(remaining > 0, "producer timeout")
                return process.wait(timeout=remaining), time.monotonic() - started
        finally:
            # Descendants may retain pipes even after the main process exits.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            for pipe in [process.stdout, process.stderr]:
                if not pipe.closed:
                    pipe.close()


def schema_validators(raw):
    schema = load_json(raw, 2 * 1024 * 1024)
    require(isinstance(schema, dict), "schema must be an object")
    require(
        schema.get("$schema") == "http://json-schema.org/draft-07/schema#"
        and schema.get("title") == "ExportRecord",
        "unknown export schema",
    )
    stack = [schema]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            require(
                "$dynamicRef" not in node and "$id" not in node,
                "unsupported schema scope",
            )
            if "$ref" in node:
                require(
                    isinstance(node["$ref"], str) and node["$ref"].startswith("#/"),
                    "nonlocal schema reference",
                )
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    try:
        Draft7Validator.check_schema(schema)
    except SchemaError as error:
        raise Refusal("invalid export schema") from error
    result = {}
    for branch in schema.get("oneOf", []):
        names = branch.get("properties", {}).get("record_type", {}).get("enum", [])
        require(
            len(names) == 1 and names[0] in KINDS and names[0] not in result,
            "unknown or duplicate schema record variant",
        )
        # All definitions stay rooted in the original schema; only the disjoint
        # record_type branch is selected to avoid testing fifteen impossible tags.
        result[names[0]] = Draft7Validator(
            {**schema, "oneOf": [branch]}, registry=Registry()
        )
    require(set(result) == KINDS, "incomplete export schema")
    return result


def _identity(record):
    return {k: record[k] for k in ["path", "sha256", "byte_length"]}


def _interpretation(value):
    if value is None:
        return
    require(value["profile"] in PROFILES, "unknown profile")
    require(
        value["base_dialect"] == PROFILES[value["profile"]], "profile/base mismatch"
    )
    require(value["parse_mode"] in {"strict", "permissive"}, "unknown parse mode")
    require(
        value["selection_mode"] in {"detected", "explicit"}, "unknown selection mode"
    )
    require(
        isinstance(value.get("validated_layout"), str) and value["validated_layout"],
        "missing declared layout",
    )


def read_export(
    stream, schema_raw, expected, limits=DEFAULT_LIMITS, retain=frozenset()
):
    """Verify accounting and context; return selected facts only after terminal validation.

    expected is the capture inventory, not a count inferred from the stream. Each fact
    retains its full context, including interpretation. File-local IDs never join files.
    """
    checked_limits(limits)
    require(set(retain) <= FACTS | {"diagnostic"}, "unknown retained family")
    validators = schema_validators(schema_raw)
    require(
        isinstance(expected, list) and 0 < len(expected) <= limits.files,
        "invalid inventory",
    )
    by_path = {}
    for entry in expected:
        require(isinstance(entry, dict), "inventory entry must be an object")
        path = entry.get("path")
        require(
            isinstance(path, str) and path and path not in by_path,
            "invalid inventory path",
        )
        require(type(entry.get("readable")) is bool, "invalid readability marker")
        require(
            set(entry)
            == (
                {"path", "readable", "sha256", "byte_length"}
                if entry["readable"]
                else {"path", "readable"}
            ),
            "unknown inventory fields",
        )
        if entry["readable"]:
            require(
                isinstance(entry.get("sha256"), str)
                and HASH.fullmatch(entry["sha256"]),
                "invalid inventory hash",
            )
            require(
                type(entry.get("byte_length")) is int
                and 0 <= entry["byte_length"] <= limits.input_bytes,
                "invalid inventory length",
            )
        by_path[path] = entry
    active = None
    start = end = None
    files = []
    seen = set()
    total = retained_size = record_count = 0
    selected = []
    report_bytes = 0
    digest = hashlib.sha256()
    targets = []
    for line in iter(lambda: stream.readline(limits.line_bytes + 1), b""):
        record_count += 1
        total += len(line)
        digest.update(line)
        require(
            record_count <= limits.records and total <= limits.stream_bytes,
            "stream limit exceeded",
        )
        require(line.endswith(b"\n"), "missing newline or line limit exceeded")
        record = load_json(line, limits.line_bytes, limits.depth)
        require(isinstance(record, dict), "record must be an object")
        kind = record.get("record_type")
        require(isinstance(kind, str) and kind in KINDS, "unknown record kind")
        try:
            error = next(validators[kind].iter_errors(record), None)
        except (Unresolvable, RecursionError) as error:
            raise Refusal("unresolvable or recursive schema") from error
        require(error is None, "record schema mismatch for " + kind)
        for field in {
            "total_files",
            "byte_length",
            "instruction_count",
            "diagnostic_count",
            "emitted_fact_count",
            "available_fact_count",
            "files_processed",
            "files_succeeded",
            "files_skipped",
            "files_failed",
            "total_instructions",
        } & record.keys():
            require(
                type(record[field]) is int and 0 <= record[field] < 2**64,
                "invalid unsigned count",
            )
        require(end is None, "record after export_end")
        if start is None:
            require(kind == "export_start", "missing export_start")
            require(record["schema_version"] == 2, "unknown JSONL schema major")
            require(
                record["total_files"] == len(expected), "expected input count mismatch"
            )
            families = record.get("fact_families")
            require(
                families is None
                or (len(set(families)) == len(families) and set(families) <= FAMILIES),
                "unknown or duplicated fact selection",
            )
            require(
                isinstance(record["tool_version"], str)
                and 0 < len(record["tool_version"]) <= 64,
                "invalid tool version",
            )
            start = record
            continue
        if kind == "file_start":
            require(
                active is None and record["path"] not in seen,
                "overlapping or duplicate file",
            )
            entry = by_path.get(record["path"])
            require(entry is not None, "unexpected input")
            if entry["readable"]:
                require(
                    _identity(record) == _identity(entry), "input identity mismatch"
                )
            else:
                require(
                    record["sha256"] == ""
                    and record["byte_length"] == 0
                    and record.get("interpretation") is None,
                    "unreadable input gained identity",
                )
            _interpretation(record.get("interpretation"))
            context = {
                "input_identity": _identity(record) if entry["readable"] else None,
                "interpretation": record.get("interpretation"),
            }
            active = {
                "start": record,
                "context": context,
                "facts": Counter(),
                "diagnostics": 0,
                "ids": set(),
            }
            seen.add(record["path"])
        elif kind == "file_end":
            require(
                active is not None and record["path"] == active["start"]["path"],
                "unpaired file_end",
            )
            counts = active["facts"]
            emitted = sum(counts.values())
            require(
                record["status"] in {"succeeded", "skipped", "failed"},
                "unknown file status",
            )
            require(record["emitted_fact_count"] == emitted, "fact count mismatch")
            require(
                record["instruction_count"] == counts["instruction"],
                "instruction count mismatch",
            )
            require(
                record["diagnostic_count"] == active["diagnostics"],
                "diagnostic count mismatch",
            )
            available = record["available_fact_count"]
            require(
                available >= emitted
                and record["is_truncated"] == (available > emitted),
                "truncation mismatch",
            )
            readable = by_path[record["path"]]["readable"]
            if not readable:
                require(record["status"] == "failed", "unreadable input must fail")
            if record["status"] == "skipped":
                require(
                    active["start"].get("interpretation") is None,
                    "parsed input cannot be skipped",
                )
            if record["status"] == "succeeded":
                require(
                    active["start"].get("interpretation") is not None,
                    "success without interpretation",
                )
            else:
                require(
                    emitted == 0 and available == 0 and active["diagnostics"] > 0,
                    "unsuccessful file has facts or lacks diagnostic",
                )
            file_report = {
                "input": active["context"]["input_identity"],
                "interpretation": active["context"]["interpretation"],
                "export_derived_facts": (
                    "experimental-lua51"
                    if active["context"]["interpretation"] is not None
                    and active["context"]["interpretation"]["base_dialect"] == "lua5.1"
                    else "not-produced"
                ),
                "completion": record,
                "fact_counts": dict(sorted(counts.items())),
            }
            report_bytes += len(json_bytes(file_report))
            require(
                report_bytes <= 12 * 1024 * 1024, "coverage report byte limit exceeded"
            )
            files.append(file_report)
            active = None
        elif kind == "export_end":
            require(
                active is None and seen == set(by_path),
                "missing expected file completion",
            )
            counts = Counter(f["completion"]["status"] for f in files)
            require(record["files_processed"] == len(files), "processed count mismatch")
            for name in ["succeeded", "skipped", "failed"]:
                require(
                    record["files_" + name] == counts[name],
                    "file status total mismatch",
                )
            require(
                record["total_instructions"]
                == sum(f["completion"]["instruction_count"] for f in files),
                "total instruction mismatch",
            )
            end = record
        elif kind in FACTS | {"diagnostic"}:
            require(active is not None, "fact outside file")
            require(record["context"] == active["context"], "fact context mismatch")
            if kind == "diagnostic":
                active["diagnostics"] += 1
            else:
                require(
                    active["context"]["interpretation"] is not None,
                    "fact without interpretation",
                )
                active["facts"][kind] += 1
                data = record["data"]
                if kind == "cross_chunk_link" and data["status"] == "resolved":
                    targets.append(data["target_artifact"])
                identifier = next(
                    (
                        data[k]
                        for k in ["id", "call_id", "access_id", "proto_id"]
                        if k in data
                    ),
                    None,
                )
                # xrefs and links can have multiple distinct edges from one source.
                if identifier is not None and kind not in {"xref", "cross_chunk_link"}:
                    key = (kind, identifier)
                    require(key not in active["ids"], "duplicate file-local fact ID")
                    active["ids"].add(key)
            if kind in retain:
                retained_size += len(line)
                require(
                    retained_size <= limits.retained_bytes,
                    "retained fact byte limit exceeded",
                )
                selected.append(record)
        else:
            raise Refusal("duplicate export_start")
    require(
        start is not None and end is not None and active is None,
        "incomplete export stream",
    )
    for target in targets:
        entry = by_path.get(target["path"])
        require(
            entry is not None and entry["readable"] and _identity(entry) == target,
            "link target identity outside corpus",
        )
    return {
        "report_version": 1,
        "stream_complete": True,
        "analysis_precision": "not-assessed",
        "stream_sha256": digest.hexdigest(),
        "stream_bytes": total,
        "schema_version": start["schema_version"],
        "tool_version": start["tool_version"],
        "fact_families": start.get("fact_families"),
        "files": files,
        "summary": end,
        "all_files_succeeded": all(
            f["completion"]["status"] == "succeeded" for f in files
        ),
        "all_available_facts_emitted": not any(
            f["completion"]["is_truncated"] for f in files
        ),
    }, selected


def verify_bundle(directory: Path, limits=DEFAULT_LIMITS, retain=frozenset()):
    checked_limits(limits)
    manifest = load_json(
        read_small(directory / "capture.json", 4 * 1024 * 1024), 4 * 1024 * 1024
    )
    require(isinstance(manifest, dict), "manifest must be an object")
    require(
        isinstance(manifest.get("outputs"), dict)
        and isinstance(manifest.get("inputs"), list),
        "missing manifest outputs or inventory",
    )
    require(
        isinstance(manifest.get("argv"), list)
        and 0 < len(manifest["argv"]) <= 64
        and all(isinstance(arg, str) for arg in manifest["argv"])
        and isinstance(manifest.get("working_directory"), str),
        "missing producer invocation",
    )
    require(
        manifest.get("bundle_version") == 1
        and manifest.get("capture_complete") is True,
        "incomplete or unknown capture bundle",
    )
    require(
        type(manifest.get("exit_code")) is int and manifest["exit_code"] in range(7),
        "unknown producer exit",
    )
    require(
        isinstance(manifest.get("producer"), dict)
        and isinstance(manifest["producer"].get("sha256"), str)
        and HASH.fullmatch(manifest["producer"]["sha256"]),
        "missing producer identity",
    )
    for name, maximum in [
        ("export.jsonl", limits.stream_bytes),
        ("schema.json", 2 * 1024 * 1024),
        ("stderr.txt", limits.stderr_bytes),
    ]:
        require(
            digest_file(directory / name, maximum) == manifest["outputs"].get(name),
            "bundle output hash/length mismatch",
        )
    schema = read_small(directory / "schema.json", 2 * 1024 * 1024)
    require(
        {"sha256": hashlib.sha256(schema).hexdigest(), "byte_length": len(schema)}
        == manifest["outputs"]["schema.json"],
        "schema changed during verification",
    )
    with open_regular(directory / "export.jsonl") as stream:
        report, selected = read_export(
            stream, schema, manifest["inputs"], limits, retain
        )
    require(
        {"sha256": report["stream_sha256"], "byte_length": report["stream_bytes"]}
        == manifest["outputs"]["export.jsonl"],
        "consumed stream identity mismatch",
    )
    report.update(
        producer=manifest["producer"],
        producer_exit_code=manifest["exit_code"],
        producer_succeeded=manifest["exit_code"] == 0,
        stream_sha256=manifest["outputs"]["export.jsonl"]["sha256"],
        schema_sha256=manifest["outputs"]["schema.json"]["sha256"],
    )
    return report, selected


def capture(args, limits):
    checked_limits(limits)
    directory = Path(args.out)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    manifest = {"bundle_version": 1, "capture_complete": False}
    try:
        binary = shutil.which(args.luad)
        require(binary is not None, "luad executable not found")
        binary = str(Path(binary).resolve())
        producer = {"path": binary, **digest_file(Path(binary), 256 * 1024 * 1024)}
        raw = read_small(Path(args.input_list), 4 * 1024 * 1024)
        # Rust's producer list format splits LF, not Unicode line separators.
        paths = raw.decode("utf-8").split("\n")
        if paths and paths[-1] == "":
            paths.pop()
        paths = [path.removesuffix("\r") for path in paths]
        before = inventory(paths, limits)
        argv = [
            binary,
            "export",
            "--format",
            "jsonl",
            "--input-list",
            str(Path(args.input_list).resolve()),
        ]
        for name in ["facts", "dialect", "link_convention", "max_facts_per_file"]:
            value = getattr(args, name)
            if value is not None:
                argv += ["--" + name.replace("_", "-"), str(value)]
        if args.strict:
            argv.append("--strict")
        manifest.update(
            producer=producer,
            argv=argv,
            working_directory=str(Path.cwd()),
            inputs=before,
            limits=asdict(limits),
        )
        code, _ = run_bounded(
            [binary, "schema", "export"],
            directory / "schema.json",
            directory / "schema.stderr.txt",
            2 * 1024 * 1024,
            limits.stderr_bytes,
            limits.seconds,
        )
        require(code == 0, "schema command failed")
        schema_validators(read_small(directory / "schema.json", 2 * 1024 * 1024))
        code, elapsed = run_bounded(
            argv,
            directory / "export.jsonl",
            directory / "stderr.txt",
            limits.stream_bytes,
            limits.stderr_bytes,
            limits.seconds,
        )
        require(inventory(paths, limits) == before, "inputs changed during capture")
        require(
            read_small(Path(args.input_list), 4 * 1024 * 1024) == raw,
            "input list changed during capture",
        )
        require(
            digest_file(Path(binary), 256 * 1024 * 1024)
            == {k: producer[k] for k in ["sha256", "byte_length"]},
            "producer changed during capture",
        )
        manifest.update(
            exit_code=code,
            elapsed_seconds=elapsed,
            capture_complete=True,
            outputs={
                name: digest_file(directory / name, limit)
                for name, limit in [
                    ("export.jsonl", limits.stream_bytes),
                    ("schema.json", 2 * 1024 * 1024),
                    ("stderr.txt", limits.stderr_bytes),
                ]
            },
        )
        (directory / "capture.json").write_bytes(json_bytes(manifest))
        report, _ = verify_bundle(directory, limits)
        return report
    except Exception as error:
        manifest.update(capture_complete=False, refusal=str(error)[:300])
        (directory / "capture.json").write_bytes(json_bytes(manifest))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    cap = commands.add_parser(
        "capture", help="capture a new bounded, identity-pinned export bundle"
    )
    cap.add_argument("--luad", required=True)
    cap.add_argument("--input-list", required=True)
    cap.add_argument("--out", required=True)
    cap.add_argument("--facts")
    cap.add_argument("--dialect")
    cap.add_argument("--link-convention", choices=["luci-module-setglobal"])
    cap.add_argument("--max-facts-per-file", type=int)
    cap.add_argument("--strict", action="store_true")
    verify = commands.add_parser(
        "verify", help="verify a retained bundle without running its producer"
    )
    verify.add_argument("bundle", type=Path)
    for command in [cap, verify]:
        for name, default in asdict(Limits()).items():
            command.add_argument(
                "--max-" + name.replace("_", "-"), type=int, default=default
            )
    args = parser.parse_args()
    try:
        values = {name: getattr(args, "max_" + name) for name in asdict(Limits())}
        require(
            all(0 < n <= getattr(Limits(), name) * 16 for name, n in values.items()),
            "invalid or excessive limit",
        )
        limits = Limits(**values)
        report = (
            capture(args, limits)
            if args.command == "capture"
            else verify_bundle(args.bundle, limits)[0]
        )
        output = json_bytes(report)
        require(len(output) <= 16 * 1024 * 1024, "report byte limit exceeded")
        sys.stdout.buffer.write(output)
        return 0
    except (
        Refusal,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        RecursionError,
    ) as error:
        print("refused: " + str(error)[:300], file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
