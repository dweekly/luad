"""Public-boundary controls: generated Lua is compiled/listed, never executed."""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import luad_export as reader


class ExportReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ["CARGO_BIN_EXE_luad"]).resolve()
        cls.compiler = Path(os.environ["LUAD_LUAC51"]).resolve()
        version = subprocess.check_output(
            [str(cls.compiler), "-v"], stderr=subprocess.STDOUT
        )
        if not version.startswith(b"Lua 5.1.5 "):
            raise AssertionError("official Lua 5.1.5 is required")
        cls.root = Path(__file__).resolve().parents[3]
        cls.schema = subprocess.check_output([str(cls.binary), "schema", "export"])
        cls.scratch = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.scratch.name)
        cls.chunk = cls.compile(
            """
local function handler(p) sink(p.name, "prefix" .. p.mode) end
local function caller(p)
  handler({name=p, mode="safe"})
  sink(mystery())
end
caller("literal")
return "\\255\\000\\\"", 3.25
""",
            'quoted " 雪.luac',
        )
        cls.twin = cls.directory / "second.luac"
        cls.twin.write_bytes(cls.chunk.read_bytes())
        cls.source = cls.directory / "plain.lua"
        cls.source.write_text("return 1\n")
        cls.missing = cls.directory / "missing.luac"
        cls.paths = [str(x) for x in [cls.chunk, cls.twin, cls.source, cls.missing]]
        cls.expected = reader.inventory(cls.paths, reader.Limits())
        cls.rows, cls.exit = cls.export(cls.paths)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    @classmethod
    def compile(cls, source, name):
        target = cls.directory / name
        source_path = target.with_suffix(".source.lua")
        source_path.write_text(source)
        subprocess.run(
            [str(cls.compiler), "-o", str(target), str(source_path)],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return target

    @classmethod
    def export(cls, paths, *flags):
        result = subprocess.run(
            [str(cls.binary), "export", *paths, *flags],
            capture_output=True,
            timeout=30,
            check=False,
        )
        return [json.loads(x) for x in result.stdout.splitlines()], result.returncode

    def read(self, rows=None, expected=None, **kwargs):
        raw = b"".join(
            reader.json_bytes(row) for row in (self.rows if rows is None else rows)
        )
        return reader.read_export(
            io.BytesIO(raw),
            self.schema,
            self.expected if expected is None else expected,
            **kwargs,
        )

    def reject(self, rows, expected=None):
        with self.assertRaises(reader.Refusal):
            self.read(rows, expected)

    def args(self, paths, out, **kwargs):
        listing = self.directory / (out.name + ".list")
        listing.write_text("\n".join(paths) + "\n")
        values = dict(
            luad=str(self.binary),
            input_list=str(listing),
            out=str(out),
            facts=None,
            dialect=None,
            link_convention=None,
            max_facts_per_file=None,
            strict=False,
        )
        return argparse.Namespace(**(values | kwargs))

    def test_actual_mixed_stream_has_complete_explicit_coverage(self):
        report, _ = self.read()
        self.assertEqual(self.exit, 0)
        self.assertTrue(report["stream_complete"])
        self.assertFalse(report["all_files_succeeded"])
        self.assertEqual(
            [f["completion"]["status"] for f in report["files"]].count("succeeded"), 2
        )
        self.assertEqual(report["summary"]["files_skipped"], 1)
        self.assertEqual(report["summary"]["files_failed"], 1)
        self.assertTrue(report["all_available_facts_emitted"])
        self.assertEqual(
            {f["completion"]["path"] for f in report["files"]}, set(self.paths)
        )

    def test_retained_facts_keep_exact_artifact_scope_and_original_expressions(self):
        _, facts = self.read(retain={"origin", "constant", "parameter_field"})
        origins = [x for x in facts if x["record_type"] == "origin"]
        self.assertEqual(
            {x["context"]["input_identity"]["path"] for x in origins},
            {str(self.chunk), str(self.twin)},
        )
        left = [
            x
            for x in origins
            if x["context"]["input_identity"]["path"] == str(self.chunk)
        ]
        right = [
            x
            for x in origins
            if x["context"]["input_identity"]["path"] == str(self.twin)
        ]
        self.assertEqual([x["data"] for x in left], [x["data"] for x in right])
        # These are concrete expected expressions, not a cardinality-only check.
        text = json.dumps(left)
        self.assertIn('"kind": "parameter"', text)
        self.assertIn('"kind": "open"', text)
        self.assertIn('"reason":', text)
        constants = [x["data"] for x in facts if x["record_type"] == "constant"]
        raw_string = next(
            c
            for c in constants
            if c["value"].get("type") == "short-string"
            and c["value"]["value"]["raw_bytes"] == [255, 0, 34]
        )
        source = raw_string["source"]
        self.assertEqual(
            self.chunk.read_bytes()[
                source["byte_offset"] : source["byte_offset"] + source["byte_length"]
            ].hex(),
            source["raw_hex"],
        )
        parameter = [x["data"] for x in facts if x["record_type"] == "parameter_field"]
        self.assertTrue(
            any(
                x["parameter_index"] == 0 and x["key"]["value"]["display"] == "name"
                for x in parameter
            )
        )

    def test_every_selected_family_and_fact_cap_stays_explicit(self):
        for family in sorted(reader.FAMILIES):
            with self.subTest(family=family):
                rows, code = self.export([str(self.chunk)], "--facts", family)
                report, _ = self.read(
                    rows, reader.inventory([str(self.chunk)], reader.Limits())
                )
                self.assertEqual(code, 0)
                self.assertEqual(report["fact_families"], [family])
        rows, _ = self.export([str(self.chunk)], "--max-facts-per-file", "2")
        report, _ = self.read(
            rows, reader.inventory([str(self.chunk)], reader.Limits())
        )
        self.assertFalse(report["all_available_facts_emitted"])
        self.assertEqual(report["files"][0]["completion"]["emitted_fact_count"], 2)

    def test_authoritative_openwrt_fixture_preserves_pinned_facts(self):
        chunk = (
            self.root
            / "tests/fixtures/authority/lua51-openwrt-lnum32/authority_lnum32.luac"
        )
        authority = json.loads((chunk.parent / "AUTHORITY.json").read_bytes())
        self.assertEqual(
            hashlib.sha256(chunk.read_bytes()).hexdigest(),
            authority["fixtures"][0]["output_sha256"],
        )
        rows, code = self.export([str(chunk)])
        report, facts = self.read(
            rows,
            reader.inventory([str(chunk)], reader.Limits()),
            retain={"origin", "constant"},
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            report["files"][0]["interpretation"]["profile"], "lua5.1-lnum32"
        )
        direct = json.loads(
            subprocess.check_output(
                [str(self.binary), "origins", str(chunk), "--format", "json"]
            )
        )
        expected = [
            call for proto in direct["data"]["prototypes"] for call in proto["calls"]
        ]
        self.assertEqual(
            [x["data"] for x in facts if x["record_type"] == "origin"], expected
        )
        self.assertTrue(
            any(
                c["value"].get("type") == "float" and c["value"]["value"]["val"] == 1.5
                for c in (x["data"] for x in facts if x["record_type"] == "constant")
            )
        )

    def test_omitted_file_is_detected_even_with_consistent_rewritten_counters(self):
        remove = str(self.twin)
        rows = []
        in_removed = False
        removed_end = None
        for row in copy.deepcopy(self.rows):
            if row["record_type"] == "file_start" and row["path"] == remove:
                in_removed = True
            if in_removed:
                if row["record_type"] == "file_end":
                    removed_end = row
                    in_removed = False
                continue
            rows.append(row)
        rows[0]["total_files"] -= 1
        rows[-1]["files_processed"] -= 1
        rows[-1]["files_succeeded"] -= 1
        rows[-1]["total_instructions"] -= removed_end["instruction_count"]
        # The stream is valid against its smaller inventory, but fails the original one.
        reduced = [x for x in self.expected if x["path"] != remove]
        self.read(rows, reduced)
        self.reject(rows)

    def test_completion_and_count_mutations_are_not_empty_answers(self):
        mutations = []
        mutations += [self.rows[:-1], self.rows[1:], self.rows + [self.rows[-1]]]
        for index, row in enumerate(self.rows):
            if row["record_type"] in {"file_start", "file_end"}:
                mutations.append(self.rows[:index] + self.rows[index + 1 :])
        for kind, fields in [
            (
                "file_end",
                [
                    "emitted_fact_count",
                    "available_fact_count",
                    "instruction_count",
                    "diagnostic_count",
                ],
            ),
            (
                "export_end",
                [
                    "files_processed",
                    "files_succeeded",
                    "files_skipped",
                    "files_failed",
                    "total_instructions",
                ],
            ),
        ]:
            for field in fields:
                rows = copy.deepcopy(self.rows)
                next(x for x in rows if x["record_type"] == kind)[field] += 1
                mutations.append(rows)
        rows = copy.deepcopy(self.rows)
        next(x for x in rows if x["record_type"] == "file_end")["is_truncated"] = True
        mutations.append(rows)
        for rows in mutations:
            with self.subTest(last=rows[-1]):
                self.reject(rows)

    def test_context_closed_variant_and_duplicate_mutations_refuse(self):
        first = next(
            i for i, row in enumerate(self.rows) if row["record_type"] == "origin"
        )
        for path, value in [
            (("context", "input_identity", "sha256"), "0" * 64),
            (("context", "interpretation", "parse_mode"), "strict"),
            (("data", "argument_window", "kind"), "future-origin"),
        ]:
            rows = copy.deepcopy(self.rows)
            target = rows[first]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            self.reject(rows)
        rows = copy.deepcopy(self.rows)
        rows[first]["record_type"] = "future_fact"
        self.reject(rows)
        self.reject(self.rows[:first] + [self.rows[first]] + self.rows[first:])
        rows = copy.deepcopy(self.rows)
        rows[0]["schema_version"] = 77
        self.reject(rows)
        for field, value in [("profile", "future-lua"), ("parse_mode", "future-mode")]:
            rows = copy.deepcopy(self.rows)
            next(x for x in rows if x["record_type"] == "file_start")["interpretation"][
                field
            ] = value
            self.reject(rows)

    def test_link_target_joins_are_scoped_to_the_inventory(self):
        provider = self.compile(
            'module("demo.service", package.seeall); function handler(p) return p.name end',
            "provider.luac",
        )
        caller = self.compile('demo.service.handler({name="router"})', "caller.luac")
        paths = [str(provider), str(caller)]
        expected = reader.inventory(paths, reader.Limits())
        rows, code = self.export(paths, "--link-convention", "luci-module-setglobal")
        report, facts = self.read(rows, expected, retain={"cross_chunk_link", "origin"})
        self.assertEqual(code, 0)
        link = next(
            x
            for x in facts
            if x["record_type"] == "cross_chunk_link"
            and x["data"]["status"] == "resolved"
        )
        self.assertEqual(
            link["data"]["target_artifact"],
            {k: expected[0][k] for k in ["path", "sha256", "byte_length"]},
        )
        self.assertEqual(link["context"]["input_identity"]["path"], str(caller))
        damaged = copy.deepcopy(rows)
        next(
            x
            for x in damaged
            if x["record_type"] == "cross_chunk_link"
            and x["data"]["status"] == "resolved"
        )["data"]["target_artifact"]["sha256"] = ("0" * 64)
        self.reject(damaged, expected)

    def test_semantic_metadata_corruption_refuses_even_when_schema_accepts_it(self):
        for field, value in [
            ("available_fact_count", 1.5),
            ("emitted_fact_count", 1.0),
        ]:
            rows = copy.deepcopy(self.rows)
            next(x for x in rows if x["record_type"] == "file_end")[field] = value
            self.reject(rows)
        rows = copy.deepcopy(self.rows)
        next(
            x
            for x in rows
            if x["record_type"] == "file_end" and x["status"] == "failed"
        )["status"] = "skipped"
        rows[-1]["files_failed"] -= 1
        rows[-1]["files_skipped"] += 1
        self.reject(rows)

    def test_nonfinite_class_and_raw_payload_survive_without_coercion(self):
        inspected = json.loads(
            subprocess.check_output(
                [str(self.binary), "inspect", str(self.chunk), "--format", "json"]
            )
        )
        constant = next(
            x
            for x in inspected["data"]["main_proto"]["constants"]
            if x["value"]["type"] == "float"
        )
        offset = constant["source"]["byte_offset"]
        length = constant["source"]["byte_length"]
        raw = self.chunk.read_bytes()
        # Source location includes the tag; locate the exact original declared LE payload.
        payload = struct.pack("<d", 3.25)
        start = raw.index(payload, offset, offset + length)
        patched = self.directory / "nan.luac"
        expected = struct.pack("<Q", 0xFFF8000000000042)
        patched.write_bytes(raw[:start] + expected + raw[start + 8 :])
        rows, code = self.export([str(patched)], "--facts", "constant")
        report, facts = self.read(
            rows, reader.inventory([str(patched)], reader.Limits()), retain={"constant"}
        )
        self.assertEqual(code, 0)
        number = next(
            x["data"]["value"]["value"]
            for x in facts
            if x["data"]["value"]["type"] == "float"
        )
        self.assertEqual(number["val"], "nan")
        self.assertEqual(number["raw_hex"], expected.hex())
        self.assertTrue(number["is_nan"])
        damaged = copy.deepcopy(rows)
        next(
            x
            for x in damaged
            if x["record_type"] == "constant" and x["data"]["value"]["type"] == "float"
        )["data"]["value"]["value"]["val"] = None
        self.reject(damaged, reader.inventory([str(patched)], reader.Limits()))

    def test_json_and_schema_boundaries(self):
        for raw in [
            b'{"a":1,"a":2}',
            b'{"v":NaN}',
            b'{"v":Infinity}',
            b'{"v":1e400}',
            b"\xff",
            b"[[[[0]]]]",
        ]:
            with self.subTest(raw=raw), self.assertRaises(reader.Refusal):
                reader.load_json(raw, 100, depth=3)
        for limits in [
            replace(reader.Limits(), line_bytes=20),
            replace(reader.Limits(), stream_bytes=100),
            replace(reader.Limits(), records=2),
            replace(reader.Limits(), depth=2),
            replace(reader.Limits(), retained_bytes=1),
        ]:
            with self.subTest(limits=limits), self.assertRaises(reader.Refusal):
                self.read(limits=limits, retain={"origin"})
        schema = json.loads(self.schema)
        schema["definitions"]["InputIdentity"] = {
            "$ref": "https://example.invalid/private"
        }
        with self.assertRaises(reader.Refusal):
            reader.schema_validators(reader.json_bytes(schema))
        schema = json.loads(self.schema)
        schema["oneOf"].pop()
        with self.assertRaises(reader.Refusal):
            reader.schema_validators(reader.json_bytes(schema))

    def test_capture_and_offline_verification_detect_bundle_damage(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as scratch:
            out = Path(scratch) / "bundle"
            report = reader.capture(self.args(self.paths, out), reader.Limits())
            verified, _ = reader.verify_bundle(out)
            self.assertEqual(report, verified)
            self.assertTrue(report["producer_succeeded"])
            self.assertEqual(
                report["producer"]["sha256"],
                hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            )
            manifest = json.loads((out / "capture.json").read_bytes())
            self.assertIn("--input-list", manifest["argv"])
            with self.assertRaises(FileExistsError):
                reader.capture(self.args(self.paths, out), reader.Limits())
            for filename in ["schema.json", "export.jsonl", "stderr.txt"]:
                path = out / filename
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.subTest(filename=filename), self.assertRaises(reader.Refusal):
                    reader.verify_bundle(out)
                path.write_bytes(original)
            # Rewriting a stream's digest cannot make an incomplete stream complete.
            stream = out / "export.jsonl"
            stream.write_bytes(
                b"\n".join(stream.read_bytes().splitlines()[:-1]) + b"\n"
            )
            manifest["outputs"]["export.jsonl"] = reader.digest_file(
                stream, reader.Limits().stream_bytes
            )
            (out / "capture.json").write_bytes(reader.json_bytes(manifest))
            with self.assertRaises(reader.Refusal):
                reader.verify_bundle(out)

    def test_strict_and_capped_capture_separate_process_status_from_coverage(self):
        for flags in [{"strict": True}, {"facts": "origin", "max_facts_per_file": 1}]:
            with tempfile.TemporaryDirectory(dir=self.directory) as scratch:
                report = reader.capture(
                    self.args(self.paths, Path(scratch) / "bundle", **flags),
                    reader.Limits(),
                )
                self.assertTrue(report["stream_complete"])
                if flags.get("strict"):
                    self.assertFalse(report["producer_succeeded"])
                else:
                    self.assertFalse(report["all_available_facts_emitted"])

    def test_producer_timeout_and_output_limits_leave_failed_attempts(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as scratch:
            root = Path(scratch)
            for name, code in [
                ("timeout", "import time; time.sleep(3)"),
                ("stdout", "import sys; sys.stdout.write('x'*4096)"),
                ("stderr", "import sys; sys.stderr.write('x'*4096)"),
                ("early", "import sys; sys.exit(7)"),
            ]:
                with self.subTest(name=name):
                    script = root / (name + ".py")
                    script.write_text(code)
                    with (
                        self.assertRaises((reader.Refusal, subprocess.TimeoutExpired))
                        if name != "early"
                        else self.assertRaises(AssertionError)
                    ):
                        result, _ = reader.run_bounded(
                            [sys.executable, str(script)],
                            root / (name + ".out"),
                            root / (name + ".err"),
                            1024,
                            1024,
                            0.1,
                        )
                        self.assertEqual(result, 0)
            # An interrupted export cannot produce a successful capture manifest.
            out = root / "attempt"
            with patch.object(
                reader, "run_bounded", side_effect=reader.Refusal("producer timeout")
            ):
                with self.assertRaises(reader.Refusal):
                    reader.capture(self.args([str(self.chunk)], out), reader.Limits())
            self.assertFalse(
                json.loads((out / "capture.json").read_bytes())["capture_complete"]
            )

    def test_early_producer_exit_cannot_yield_a_successful_bundle(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as scratch:
            root = Path(scratch)
            fake = root / "fake-luad"
            schema_file = root / "schema.json"
            schema_file.write_bytes(self.schema)
            fake.write_text(
                f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\n"
                f"if sys.argv[1] == 'schema': sys.stdout.buffer.write(Path({str(schema_file)!r}).read_bytes())\n"
                'else: print(\'{"record_type":"export_start","schema_version":2,"tool_version":"test","total_files":1}\')\n'
            )
            fake.chmod(0o700)
            out = root / "bundle"
            with self.assertRaisesRegex(reader.Refusal, "incomplete"):
                reader.capture(
                    self.args([str(self.chunk)], out, luad=str(fake)), reader.Limits()
                )
            self.assertFalse(
                json.loads((out / "capture.json").read_bytes())["capture_complete"]
            )

    def test_changed_inputs_are_refused_before_any_report(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as scratch:
            out = Path(scratch) / "bundle"
            original = self.chunk.read_bytes()
            run = reader.run_bounded

            def mutate_after_export(argv, *args):
                result = run(argv, *args)
                if argv[1] == "export":
                    self.chunk.write_bytes(original + b"changed")
                return result

            try:
                with patch.object(
                    reader, "run_bounded", side_effect=mutate_after_export
                ):
                    with self.assertRaisesRegex(reader.Refusal, "inputs changed"):
                        reader.capture(
                            self.args([str(self.chunk)], out), reader.Limits()
                        )
            finally:
                self.chunk.write_bytes(original)
            self.assertFalse(
                json.loads((out / "capture.json").read_bytes())["capture_complete"]
            )

    def test_special_files_and_invalid_limits_refuse_without_blocking(self):
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        try:
            with self.assertRaises(reader.Refusal):
                reader.read_small(fifo, 100)
        finally:
            fifo.unlink()
        for limit in [-1, 0, True]:
            with self.subTest(limit=limit), self.assertRaises(reader.Refusal):
                self.read(limits=replace(reader.Limits(), line_bytes=limit))


if __name__ == "__main__":
    unittest.main()
