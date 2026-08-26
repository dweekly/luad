//! Public OpenWrt LNUM32 authority acceptance (Gate A51).

use std::path::PathBuf;
use std::process::{Command, Output};

use luad_core::envelope::{MachineDocument, ValidationResponse};
use luad_core::{Chunk, ConstantValue, DisassembledPrototype, Prototype, SelectionMode};
#[cfg(feature = "lnum32-authority-gate")]
use luad_oracle::{compare_chunk_tree_three_way_lua51, parse_luac_dump, LuacProtoDumpList};
use serde_json::Value;
use sha2::{Digest, Sha256};

const REL: &str = "tests/fixtures/authority/lua51-openwrt-lnum32";
const SOURCE_SHA: &str = "84862a976e997c6cbab296de0c02b096814ebe34978b55e0b42469f3a026133c";
const DEBUG_SHA: &str = "21b751768c37a930607c8a04e803206554887ef9b8a6f9c415a8cba6a8be4a3c";
const STRIPPED_SHA: &str = "3ad36ac1e1b7d94fbfa6f4171c8c1257b80e1813780e258ca139b0b1601e223d";
const LAYOUT: &str = "int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4";

#[derive(Debug, Clone, PartialEq)]
enum Atom {
    Nil,
    Bool(bool),
    Float(u64),
    Integer(i32),
    String(Vec<u8>),
}

#[derive(Debug, Default, PartialEq)]
struct Facts {
    constants: Vec<Atom>,
    instructions: Vec<Vec<u32>>,
    prototype_count: usize,
    debug_entries: usize,
    tag_offsets: Vec<usize>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("offset overflow")?;
        let out = self.bytes.get(self.pos..end).ok_or("truncated chunk")?;
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn string(&mut self) -> Result<Option<Vec<u8>>, String> {
        let n = self.u32()? as usize;
        if n == 0 {
            return Ok(None);
        }
        let bytes = self.take(n)?;
        if bytes.last() != Some(&0) {
            return Err("Lua string lacks terminator".into());
        }
        Ok(Some(bytes[..n - 1].to_vec()))
    }
}

fn parse_authority(bytes: &[u8]) -> Result<Facts, String> {
    const HEADER: [u8; 12] = [0x1b, b'L', b'u', b'a', 0x51, 0, 1, 4, 4, 4, 8, 4];
    if bytes.get(..12) != Some(&HEADER) {
        return Err("unexpected LNUM32 header".into());
    }
    let mut reader = Reader { bytes, pos: 12 };
    let mut facts = Facts::default();
    parse_proto(&mut reader, &mut facts)?;
    if reader.pos != bytes.len() {
        return Err(format!("{} trailing bytes", bytes.len() - reader.pos));
    }
    Ok(facts)
}

fn parse_proto(reader: &mut Reader<'_>, facts: &mut Facts) -> Result<(), String> {
    facts.prototype_count += 1;
    if reader.string()?.is_some() {
        facts.debug_entries += 1;
    }
    reader.take(8)?; // line-defined pair
    reader.take(4)?; // nups, params, vararg, maxstack

    let instruction_count = reader.u32()? as usize;
    let mut words = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        words.push(reader.u32()?);
    }
    facts.instructions.push(words);

    for _ in 0..reader.u32()? {
        facts.tag_offsets.push(reader.pos);
        match reader.u8()? {
            0 => facts.constants.push(Atom::Nil),
            1 => {
                let value = reader.u8()?;
                if value > 1 {
                    return Err("invalid boolean".into());
                }
                facts.constants.push(Atom::Bool(value != 0));
            }
            3 => facts.constants.push(Atom::Float(u64::from_le_bytes(
                reader.take(8)?.try_into().unwrap(),
            ))),
            4 => facts.constants.push(Atom::String(
                reader.string()?.ok_or("null constant string")?,
            )),
            9 => facts.constants.push(Atom::Integer(i32::from_le_bytes(
                reader.take(4)?.try_into().unwrap(),
            ))),
            tag => return Err(format!("invalid constant tag {tag}")),
        }
    }

    for _ in 0..reader.u32()? {
        parse_proto(reader, facts)?;
    }
    let lines = reader.u32()? as usize;
    reader.take(lines.checked_mul(4).ok_or("line count overflow")?)?;
    facts.debug_entries += lines;
    let locals = reader.u32()? as usize;
    for _ in 0..locals {
        reader.string()?.ok_or("null local name")?;
        reader.take(8)?;
    }
    facts.debug_entries += locals;
    let upvalue_names = reader.u32()? as usize;
    for _ in 0..upvalue_names {
        reader.string()?.ok_or("null upvalue name")?;
    }
    facts.debug_entries += upvalue_names;
    Ok(())
}

fn workspace() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn fixture(name: &str) -> PathBuf {
    workspace().join(REL).join(name)
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn luad() -> PathBuf {
    luad_oracle::resolve_test_binary().expect("resolve luad test binary")
}

fn run(args: &[&str]) -> Output {
    Command::new(luad()).args(args).output().expect("run luad")
}

fn assert_interpretation(doc: &MachineDocument<Chunk>, explicit: bool) {
    assert_eq!(doc.interpretation.base_dialect, "lua5.1");
    assert_eq!(
        doc.interpretation.patch_or_oracle_version.as_deref(),
        Some("lnum32")
    );
    assert_eq!(doc.interpretation.profile, "lua5.1-lnum32");
    assert_eq!(doc.interpretation.validated_layout.as_deref(), Some(LAYOUT));
    assert_eq!(
        doc.interpretation.selection_mode,
        if explicit {
            SelectionMode::Explicit
        } else {
            SelectionMode::Detected
        }
    );
}

fn collect_production(proto: &Prototype, constants: &mut Vec<Atom>, code: &mut Vec<Vec<u32>>) {
    code.push(
        proto
            .instructions
            .iter()
            .map(|word| word.raw_word)
            .collect(),
    );
    for constant in &proto.constants {
        constants.push(match &constant.value {
            ConstantValue::Nil => Atom::Nil,
            ConstantValue::Boolean(v) => Atom::Bool(*v),
            ConstantValue::Integer { val, .. } => Atom::Integer((*val).try_into().unwrap()),
            ConstantValue::Float { val, .. } => Atom::Float(val.to_bits()),
            ConstantValue::ShortString(v) | ConstantValue::LongString(v) => {
                Atom::String(v.raw_bytes.clone())
            }
        });
    }
    for child in &proto.protos {
        collect_production(child, constants, code);
    }
}

fn validate_manifest(value: &Value) -> Result<(), String> {
    let expected_patches = [
        "010-lua-5.1.3-lnum-full-260308.patch",
        "011-lnum-use-double.patch",
        "012-lnum-fix-ltle-relational-operators.patch",
        "015-lnum-ppc-compat.patch",
        "020-shared_liblua.patch",
        "030-archindependent-bytecode.patch",
        "040-use-symbolic-functions.patch",
        "050-honor-cflags.patch",
        "100-no_readline.patch",
        "200-lua-path.patch",
        "300-opcode_performance.patch",
    ];
    if value["profile"] != "lua5.1-lnum32" || value["layout"] != LAYOUT {
        return Err("profile or layout changed".into());
    }
    if value["upstream"]["lua_archive"]["sha256"]
        != "2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333"
        || value["upstream"]["openwrt_revision"] != "1da2e82c1182a3fd681da5760be96821213afadd"
    {
        return Err("upstream identity changed".into());
    }
    let patches = value["upstream"]["patches"]
        .as_array()
        .ok_or("patches absent")?;
    if patches.len() != expected_patches.len()
        || patches.iter().zip(expected_patches).any(|(p, name)| {
            !p["path"].as_str().unwrap_or_default().ends_with(name)
                || p["sha256"].as_str().is_none_or(|hash| hash.len() != 64)
        })
    {
        return Err("patch series changed".into());
    }
    let fixtures = value["fixtures"].as_array().ok_or("fixtures absent")?;
    if fixtures.len() != 2
        || fixtures[0]["source_sha256"] != SOURCE_SHA
        || fixtures[0]["output_sha256"] != DEBUG_SHA
        || fixtures[1]["output_sha256"] != STRIPPED_SHA
    {
        return Err("fixture identity changed".into());
    }
    Ok(())
}

#[test]
fn test_authority_manifest_and_frozen_artifacts_are_authenticated() {
    let manifest_bytes = std::fs::read(fixture("AUTHORITY.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    validate_manifest(&manifest).unwrap();
    for (name, expected) in [
        ("authority_lnum32.lua", SOURCE_SHA),
        ("authority_lnum32.luac", DEBUG_SHA),
        ("authority_lnum32_stripped.luac", STRIPPED_SHA),
    ] {
        assert_eq!(sha(&std::fs::read(fixture(name)).unwrap()), expected);
    }

    for pointer in [
        "/layout",
        "/upstream/lua_archive/sha256",
        "/upstream/openwrt_revision",
        "/upstream/patches/0/path",
        "/fixtures/0/output_sha256",
    ] {
        let mut changed = manifest.clone();
        *changed.pointer_mut(pointer).unwrap() = Value::String("tampered".into());
        assert!(
            validate_manifest(&changed).is_err(),
            "mutation survived at {pointer}"
        );
    }
    let mut reordered = manifest;
    reordered["upstream"]["patches"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    assert!(validate_manifest(&reordered).is_err());
}

#[test]
fn test_authority_independent_and_public_facts_agree() {
    for name in ["authority_lnum32.luac", "authority_lnum32_stripped.luac"] {
        let path = fixture(name);
        let bytes = std::fs::read(&path).unwrap();
        let independent = parse_authority(&bytes).unwrap();
        assert_eq!(independent.prototype_count, 4);
        assert!(independent.constants.contains(&Atom::Integer(0)));
        assert!(independent.constants.contains(&Atom::Integer(i32::MIN)));
        assert!(independent.constants.contains(&Atom::Integer(i32::MAX)));
        assert!(independent
            .constants
            .contains(&Atom::Float(1.0f64.to_bits())));
        assert!(independent
            .constants
            .contains(&Atom::Float(1.5f64.to_bits())));
        assert!(independent
            .constants
            .contains(&Atom::String(b"openwrt-lnum32".to_vec())));
        assert!(independent
            .constants
            .iter()
            .any(|v| matches!(v, Atom::String(s) if s.len() >= 300)));
        assert_eq!(independent.debug_entries == 0, name.contains("stripped"));

        let output = run(&["inspect", path.to_str().unwrap(), "--format", "json"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let doc: MachineDocument<Chunk> = serde_json::from_slice(&output.stdout).unwrap();
        assert_interpretation(&doc, false);
        assert_eq!(doc.input_identity.sha256, sha(&bytes));
        let mut constants = Vec::new();
        let mut code = Vec::new();
        collect_production(&doc.data.main_proto, &mut constants, &mut code);
        assert_eq!(constants, independent.constants);
        assert_eq!(code, independent.instructions);

        let disasm = run(&["disasm", path.to_str().unwrap(), "--format", "json"]);
        assert!(
            disasm.status.success(),
            "JSON disasm failed for {name}: {}",
            String::from_utf8_lossy(&disasm.stderr)
        );
        let _disasm: MachineDocument<DisassembledPrototype> =
            serde_json::from_slice(&disasm.stdout).unwrap();

        let text_disasm = run(&["disasm", path.to_str().unwrap(), "--format", "text"]);
        assert!(
            text_disasm.status.success(),
            "text disasm failed for {name}: {}",
            String::from_utf8_lossy(&text_disasm.stderr)
        );
        let text_out = String::from_utf8_lossy(&text_disasm.stdout);
        assert!(
            text_out.contains("LOADK") && text_out.contains("openwrt-lnum32"),
            "text disassembly missing LNUM32 facts for {name}"
        );
    }
}

#[cfg(feature = "lnum32-authority-gate")]
#[test]
fn test_authority_live_compiler_listing_agrees() {
    let compiler = std::env::var("LUAD_GATE_COMPILER_PATH")
        .expect("LUAD_GATE_COMPILER_PATH is required to execute authority listing comparison");
    for name in ["authority_lnum32.luac", "authority_lnum32_stripped.luac"] {
        let path = fixture(name);
        let inspect = run(&["inspect", path.to_str().unwrap(), "--format", "json"]);
        assert!(inspect.status.success());
        let chunk: MachineDocument<Chunk> = serde_json::from_slice(&inspect.stdout).unwrap();
        let disasm = run(&["disasm", path.to_str().unwrap(), "--format", "json"]);
        assert!(disasm.status.success());
        let disasm: MachineDocument<DisassembledPrototype> =
            serde_json::from_slice(&disasm.stdout).unwrap();
        let listing = Command::new(&compiler)
            .args(["-l", "-l", "-p", path.to_str().unwrap()])
            .output()
            .expect("run authority compiler listing");
        assert!(
            listing.status.success(),
            "compiler listing failed for {name}: {}",
            String::from_utf8_lossy(&listing.stderr)
        );
        let parsed =
            parse_luac_dump(&String::from_utf8_lossy(&listing.stdout)).expect("parse luac dump");
        let list = LuacProtoDumpList {
            functions: &parsed.functions,
        };
        compare_chunk_tree_three_way_lua51(&chunk.data.main_proto, &list, &disasm.data)
            .expect("three-way agreement between chunk, compiler dump, and disasm");
    }
}

#[test]
fn test_authority_public_selection_validation_export_and_substitution() {
    for name in ["authority_lnum32.luac", "authority_lnum32_stripped.luac"] {
        let path = fixture(name);
        let text = path.to_str().unwrap();
        let explicit = run(&[
            "inspect",
            text,
            "--dialect",
            "lua5.1-lnum32",
            "--format",
            "json",
        ]);
        let doc: MachineDocument<Chunk> = serde_json::from_slice(&explicit.stdout).unwrap();
        assert_interpretation(&doc, true);

        let valid = run(&["validate", text, "--format", "json"]);
        let valid: MachineDocument<ValidationResponse> =
            serde_json::from_slice(&valid.stdout).unwrap();
        assert_eq!(valid.data.diagnostic_count, 0);
        assert!(valid.diagnostics.is_empty());

        let export = run(&["export", "--format", "jsonl", text]);
        assert!(export.status.success());
        let file_start: Value = String::from_utf8(export.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .find(|v: &Value| v["record_type"] == "file_start")
            .unwrap();
        assert_eq!(file_start["sha256"], doc.input_identity.sha256);
        assert_eq!(file_start["interpretation"]["profile"], "lua5.1-lnum32");
        assert_eq!(file_start["interpretation"]["validated_layout"], LAYOUT);

        let q_loadk = run(&[
            "query",
            text,
            "--where",
            "mnemonic == \"LOADK\"",
            "--format",
            "json",
        ]);
        assert!(q_loadk.status.success());
        let doc_loadk: Value = serde_json::from_slice(&q_loadk.stdout).unwrap();
        let count_loadk = doc_loadk["data"]["count"].as_u64().unwrap();
        assert!(count_loadk > 0);
        let matches_loadk = doc_loadk["data"]["matches"].as_array().unwrap();
        for m in matches_loadk {
            let id = m["id"].as_str().unwrap();
            assert!(
                id.starts_with("proto:") && id.contains(":pc:"),
                "instruction ID must be owner-qualified: {id}"
            );
        }

        let q_closure = run(&[
            "query",
            text,
            "--where",
            "mnemonic == \"CLOSURE\"",
            "--format",
            "json",
        ]);
        assert!(q_closure.status.success());
        let doc_closure: Value = serde_json::from_slice(&q_closure.stdout).unwrap();
        let count_closure = doc_closure["data"]["count"].as_u64().unwrap();
        assert!(count_closure > 0);
        assert_ne!(
            count_loadk, count_closure,
            "changing query predicate operand must change match count"
        );
        let matches_closure = doc_closure["data"]["matches"].as_array().unwrap();
        for m in matches_closure {
            let id = m["id"].as_str().unwrap();
            assert!(
                id.starts_with("proto:") && id.contains(":pc:"),
                "instruction ID must be owner-qualified: {id}"
            );
        }

        let stock = run(&["inspect", text, "--dialect", "lua5.1", "--format", "json"]);
        assert!(!stock.status.success());
        assert!(String::from_utf8_lossy(&stock.stderr).contains("Invalid integral flag 4"));
    }

    let stock_fixture = workspace().join("tests/fixtures/precompiled/lua51/hello.luac");
    let lnum_fixture = fixture("authority_lnum32.luac");
    let mixed_export = run(&[
        "export",
        "--format",
        "jsonl",
        stock_fixture.to_str().unwrap(),
        lnum_fixture.to_str().unwrap(),
    ]);
    assert!(mixed_export.status.success());
    let export_lines: Vec<Value> = String::from_utf8(mixed_export.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let file_starts: Vec<&Value> = export_lines
        .iter()
        .filter(|v| v["record_type"] == "file_start")
        .collect();
    assert_eq!(file_starts.len(), 2, "expected 2 file_start records");
    assert_eq!(file_starts[0]["interpretation"]["profile"], "lua5.1");
    assert_eq!(
        file_starts[0]["interpretation"]["validated_layout"],
        "int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0"
    );
    assert_eq!(file_starts[1]["interpretation"]["profile"], "lua5.1-lnum32");
    assert_eq!(file_starts[1]["interpretation"]["validated_layout"], LAYOUT);

    let forced_stock = run(&[
        "inspect",
        stock_fixture.to_str().unwrap(),
        "--dialect",
        "lua5.1-lnum32",
        "--format",
        "json",
    ]);
    assert!(!forced_stock.status.success());
    let forced_stderr = String::from_utf8_lossy(&forced_stock.stderr);
    assert!(
        forced_stderr.contains("Invalid lua_Integer size 0 for LNUM32 profile")
            || forced_stderr.contains("Invalid integral flag"),
        "stock fixture forced through lua5.1-lnum32 must fail symmetrically: {forced_stderr}"
    );
}

#[test]
fn test_authority_mutations_are_rejected() {
    let bytes = std::fs::read(fixture("authority_lnum32.luac")).unwrap();
    let facts = parse_authority(&bytes).unwrap();
    let mut cases = Vec::new();
    let mut header = bytes.clone();
    header[11] = 0;
    cases.push(header);
    let mut tag = bytes.clone();
    tag[facts.tag_offsets[0]] = 71;
    cases.push(tag);
    cases.push(bytes[..bytes.len() - 1].to_vec());
    for changed in cases {
        assert!(parse_authority(&changed).is_err());
        assert_ne!(sha(&changed), DEBUG_SHA);
    }
}
