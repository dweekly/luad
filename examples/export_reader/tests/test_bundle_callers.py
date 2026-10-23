"""Caller answers from verified bundles must agree with `luad callers`.

The consumer rebuilds the answer from export records alone, a different interface from
the core command's in-process facts. Generated Lua and the vendored LuCI subset are
compiled with official Lua 5.1.5 (and 5.2.4 for a refusal control), never executed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import luad_export as reader

MOD_SVC = """
module("svc.config", package.seeall)
function network_get_firm(iface)
    os.execute("network_get_firm " .. iface)
end
function merge_profile(name)
    network_get_firm(name)
    os.execute("mkdir /tmp/profile.d/" .. name)
end
function never_called(path)
    os.execute("ls /tmp/merge/" .. path)
end
"""
CALLER_SVC_A = """
local cfg = require("svc.config")
local function handle(request) cfg.network_get_firm(request.ifname) end
local function handle_constant(_request) cfg.network_get_firm("eth0") end
return { handle = handle, handle_constant = handle_constant }
"""
CALLER_SVC_B = """
local cfg = require("svc.config")
local function handle(request) cfg.network_get_firm(request.query.iface .. "0") end
local function unrelated(request) cfg.merge_profile(request.name) end
return { handle = handle, unrelated = unrelated }
"""
MOD_SYS = 'module("luci.sys")\nfunction exec(cmd)\n    return cmd\nend\n'
MOD_SYS_DUP = 'module("luci.sys")\nfunction exec(cmd)\n    return "dup"\nend\n'
CALLER_SYS = 'luci.sys.exec("uname -a")\n'
MOD_DYNAMIC = (
    "local name = ...\nmodule(name)\nfunction exec(cmd)\n    return cmd\nend\n"
)
SAME = """
local function target(x) return x end
local function decoy()
    local function target(y) return y end
    return target(1)
end
local function via_capture() return target(2) end
function global_target(v) return v end
target(3)
target(4)
global_target(5)
return decoy, via_capture
"""
CONVENTION = "luci-module-setglobal"


class BundleCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ["CARGO_BIN_EXE_luad"]).resolve()
        cls.luac51 = Path(os.environ["LUAD_LUAC51"]).resolve()
        cls.luac52 = Path(os.environ["LUAD_LUAC52"]).resolve()
        for compiler, banner in [
            (cls.luac51, b"Lua 5.1.5 "),
            (cls.luac52, b"Lua 5.2.4 "),
        ]:
            version = subprocess.check_output(
                [str(compiler), "-v"], stderr=subprocess.STDOUT
            )
            if not version.startswith(banner):
                raise AssertionError(f"official {banner.decode().strip()} is required")
        cls.root = Path(__file__).resolve().parents[3]
        cls.scratch = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.scratch.name)
        cls.bundles = 0

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def compile(self, name, source, compiler=None):
        target = self.directory / f"{name}.luac"
        source_path = self.directory / f"{name}.source.lua"
        source_path.write_text(source)
        subprocess.run(
            [str(compiler or self.luac51), "-o", str(target), str(source_path)],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return str(target)

    def capture(self, paths, *flags):
        type(self).bundles += 1
        out = self.directory / f"bundle-{self.bundles}"
        listing = self.directory / f"bundle-{self.bundles}.list"
        listing.write_text("\n".join(paths) + "\n")
        values = {
            "luad": str(self.binary),
            "input_list": str(listing),
            "out": str(out),
            "facts": None,
            "dialect": None,
            "link_convention": None,
            "max_facts_per_file": None,
            "strict": False,
        }
        it = iter(flags)
        for flag in it:
            values[flag.removeprefix("--").replace("-", "_")] = next(it)
        if values["max_facts_per_file"] is not None:
            values["max_facts_per_file"] = int(values["max_facts_per_file"])
        reader.capture(argparse.Namespace(**values), reader.Limits())
        return out

    def core(self, target, proto, corpus, link):
        argv = [str(self.binary), "callers", target, "--proto", proto, "-f", "json"]
        if link:
            argv += [p for p in corpus if p != target] + [
                "--link-convention",
                CONVENTION,
            ]
        result = subprocess.run(argv, capture_output=True, timeout=120, check=False)
        return result.returncode, json.loads(result.stdout)["data"]

    @staticmethod
    def shape(callers, files):
        listed = [
            (
                c["caller"]["path"],
                c["call_id"],
                sorted(b["source"] for b in c["bases"]),
                c["argument_window"],
            )
            for c in callers
        ]
        counts = {f["path"]: f["counts"] for f in files if f["status"] == "analyzed"}
        statuses = {f["path"]: f["status"] for f in files}
        return listed, counts, statuses

    def assert_agree(self, bundle, target, proto, corpus, link, verified=None):
        report, records, argv = verified or self.verified(bundle)
        answer = reader.callers_from_records(report, records, argv, target, proto)
        _, core = self.core(target, proto, corpus, link)
        self.assertEqual(
            self.shape(answer["callers"], answer["files"]),
            self.shape(core["callers"], core["files"]),
            f"consumer and core disagree on {target} {proto}",
        )
        self.assertEqual(answer["summary"]["cross_artifact_searched"], link)
        return answer

    @staticmethod
    def verified(bundle):
        report, records = reader.verify_bundle(bundle, retain=reader.CALLER_RECORDS)
        argv = json.loads((bundle / "capture.json").read_text())["argv"]
        return report, records, argv

    def test_agreement_on_fixture_shapes(self):
        svc = [
            self.compile("mod_svc", MOD_SVC),
            self.compile("caller_svc_a", CALLER_SVC_A),
            self.compile("caller_svc_b", CALLER_SVC_B),
        ]
        linked = self.capture(svc, "--link-convention", CONVENTION)
        plain = self.capture(svc[:1])
        verified_linked = self.verified(linked)
        verified_plain = self.verified(plain)
        for proto in ["0/0", "0/1", "0/2"]:
            answer = self.assert_agree(
                linked, svc[0], proto, svc, True, verified_linked
            )
            self.assert_agree(plain, svc[0], proto, svc[:1], False, verified_plain)
            if proto == "0/0":
                self.assertEqual(len(answer["callers"]), 4)
                self.assertFalse(answer["summary"]["degraded"])
        dynamic = svc + [self.compile("mod_dynamic", MOD_DYNAMIC)]
        bundle = self.capture(dynamic, "--link-convention", CONVENTION)
        answer = self.assert_agree(bundle, svc[0], "0/0", dynamic, True)
        self.assertTrue(answer["summary"]["degraded"])
        sys_corpus = [
            self.compile("mod_sys", MOD_SYS),
            self.compile("caller_sys", CALLER_SYS),
        ]
        bundle = self.capture(sys_corpus, "--link-convention", CONVENTION)
        self.assert_agree(bundle, sys_corpus[0], "0/0", sys_corpus, True)
        dup = sys_corpus + [self.compile("mod_sys_dup", MOD_SYS_DUP)]
        bundle = self.capture(dup, "--link-convention", CONVENTION)
        answer = self.assert_agree(bundle, sys_corpus[0], "0/0", dup, True)
        self.assertEqual(answer["callers"], [])
        same = [self.compile("same", SAME)]
        bundle = self.capture(same)
        verified = self.verified(bundle)
        for proto in ["0/0", "0/1", "0/1/0", "0/2", "0/3"]:
            self.assert_agree(bundle, same[0], proto, same, False, verified)

    def test_agreement_on_the_vendored_luci_subset(self):
        corpus = self.root / "tests/corpus/luci-23.05"
        paths = []
        for source in sorted(corpus.rglob("*.lua")):
            name = source.relative_to(corpus).as_posix().replace("/", "__")
            paths.append(self.compile(name.removesuffix(".lua"), source.read_text()))
        bundle = self.capture(paths, "--link-convention", CONVENTION)
        verified = self.verified(bundle)
        report = verified[0]
        compared = 0
        for path in paths:
            protos = sorted(
                {
                    r["data"]["path"]
                    for r in verified[1]
                    if r["record_type"] == "prototype"
                    and r["context"]["input_identity"]["path"] == path
                    and r["data"]["path"] != "0"
                }
            )
            for proto in protos[:12]:
                self.assert_agree(bundle, path, proto, paths, True, verified)
                compared += 1
        self.assertGreaterEqual(compared, 60)
        self.assertTrue(report["stream_complete"])
        # Same-artifact answers without a convention agree too, on luci.sys.
        sys_path = next(p for p in paths if p.endswith("luasrc__sys.luac"))
        plain = self.capture([sys_path])
        answer = self.assert_agree(plain, sys_path, "0/28", [sys_path], False)
        self.assertEqual(len(answer["callers"]), 7)

    def test_refusals_and_coverage_boundaries(self):
        svc = [
            self.compile("r_mod_svc", MOD_SVC),
            self.compile("r_caller_a", CALLER_SVC_A),
        ]
        narrow = self.capture(svc, "--facts", "callee,origin")
        with self.assertRaisesRegex(reader.Refusal, "lacks"):
            reader.bundle_callers(narrow, svc[0], "0/0")
        capped = self.capture(svc, "--max-facts-per-file", "3")
        with self.assertRaisesRegex(reader.Refusal, "capped"):
            reader.bundle_callers(capped, svc[0], "0/0")
        good = self.capture(svc, "--link-convention", CONVENTION)
        with self.assertRaisesRegex(reader.Refusal, "inventory"):
            reader.bundle_callers(good, "/elsewhere.luac", "0/0")
        with self.assertRaisesRegex(reader.Refusal, "not found"):
            reader.bundle_callers(good, svc[0], "0/9")
        with self.assertRaisesRegex(reader.Refusal, "invalid prototype"):
            reader.bundle_callers(good, svc[0], "zero")
        lua52 = self.compile("r_old", "return 1\n", self.luac52)
        mixed = self.capture(svc + [lua52], "--link-convention", CONVENTION)
        with self.assertRaisesRegex(reader.Refusal, "Lua 5.1"):
            reader.bundle_callers(mixed, lua52, "0")
        answer = reader.bundle_callers(mixed, svc[0], "0/0")
        statuses = {f["path"]: f["status"] for f in answer["files"]}
        self.assertEqual(statuses[lua52], "unsupported_profile")
        self.assertFalse(answer["summary"]["coverage_complete"])
        # A damaged stream is refused before any caller answer.
        damaged = self.directory / "damaged"
        shutil.copytree(good, damaged)
        stream = damaged / "export.jsonl"
        data = bytearray(stream.read_bytes())
        data[len(data) // 2] ^= 1
        stream.write_bytes(bytes(data))
        with self.assertRaises(reader.Refusal):
            reader.bundle_callers(damaged, svc[0], "0/0")

    def test_joins_are_identity_scoped(self):
        first = self.compile("twin_a", SAME)
        second = self.directory / "twin_b.luac"
        second.write_bytes(Path(first).read_bytes())
        bundle = self.capture([first, str(second)])
        answer = reader.bundle_callers(bundle, first, "0/0")
        self.assertTrue(answer["callers"])
        self.assertTrue(all(c["caller"]["path"] == first for c in answer["callers"]))
        # A link naming the target's path but another digest is not a caller.
        target = {"path": first, "sha256": "0" * 64, "byte_length": 1}
        real = dict(answer["target"]["input_identity"])
        link = {
            "status": "resolved",
            "target_artifact": target,
            "target_proto": "0/0",
            "label_segments": ["x"],
            "evidence": [],
        }
        kind, _ = reader._classify_site(
            real,
            "0/0",
            real,
            {"status": "resolved-path"},
            None,
            [link],
            CONVENTION,
            False,
        )
        self.assertEqual(kind, "attributed_elsewhere")

    def test_classifier_precedence_matches_the_core_contract(self):
        me = {"path": "a.luac", "sha256": "1" * 64, "byte_length": 1}
        other = {"path": "b.luac", "sha256": "2" * 64, "byte_length": 1}
        starved = {"status": "unresolved", "reason": "analysis-limit"}
        label = {"status": "resolved-path"}
        elsewhere = {
            "status": "resolved",
            "target_artifact": other,
            "target_proto": "0/1",
            "label_segments": ["x", "y"],
            "evidence": [],
        }

        def classify(callee, relation, links, cutoff=False):
            return reader._classify_site(
                me, "0/0", other, callee, relation, links, CONVENTION, cutoff
            )

        # A limit outranks a resolution elsewhere: the site might still be a caller.
        self.assertEqual(
            classify(starved, None, [elsewhere]), ("degraded", "callee:analysis-limit")
        )
        # A label-only relation is the same proof as the callee label.
        only = {"status": "unresolved", "reason": "symbolic-path-only"}
        self.assertEqual(classify(label, only, []), ("unmapped_label", None))
        missing = {"status": "unresolved", "reason": "missing-prototype-store"}
        self.assertEqual(
            classify(label, missing, []),
            ("unattributed", "call_relation:missing-prototype-store"),
        )
        self.assertEqual(
            classify(label, None, [], cutoff=True), ("degraded", "link:cutoff")
        )
        conflict = dict(elsewhere, target_artifact=me, target_proto="0/0")
        self.assertEqual(classify(label, None, [conflict, elsewhere])[0], "conflicting")

    def test_removed_records_cannot_pass_as_a_smaller_answer(self):
        svc = [
            self.compile("n_mod_svc", MOD_SVC),
            self.compile("n_caller_a", CALLER_SVC_A),
        ]
        good = self.capture(svc, "--link-convention", CONVENTION)
        for family in ["origin", "callee"]:
            damaged = self.directory / f"without-{family}"
            shutil.copytree(good, damaged)
            stream = damaged / "export.jsonl"
            lines = stream.read_bytes().splitlines(keepends=True)
            index = next(
                i
                for i, line in enumerate(lines)
                if json.loads(line)["record_type"] == family
            )
            del lines[index]
            stream.write_bytes(b"".join(lines))
            manifest = json.loads((damaged / "capture.json").read_text())
            manifest["outputs"]["export.jsonl"] = reader.digest_file(
                stream, reader.Limits().stream_bytes
            )
            (damaged / "capture.json").write_text(json.dumps(manifest))
            with self.assertRaises(
                reader.Refusal, msg=f"dropped {family} record accepted"
            ):
                reader.bundle_callers(damaged, svc[0], "0/0")


if __name__ == "__main__":
    unittest.main()
