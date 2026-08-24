//! Independent public acceptance for owner-relative Lua 5.1 closure identities.
//!
//! The test-local parser transcribes the Lua 5.1.5 chunk tree and instruction-word
//! layout. It does not call production Lua 5.1 parsing, opcode, disassembly, ID,
//! rendering, or xref helpers to derive the expected closure paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use luad_analysis::{XrefRelation, XrefResponse};
use luad_core::envelope::MachineDocument;
use luad_core::{DisassembledPrototype, ResolvedFact};
use sha2::{Digest, Sha256};

const CLOSURES_FIXTURE: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/closures.luac",
    "62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e",
);
const HELLO_FIXTURE: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/hello.luac",
    "d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f",
);
const LUA_515_TARBALL_SHA256: &str =
    "2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333";
const AUTHORITY_HASHES: [(&str, &str); 4] = [
    (
        "lundump.c",
        "55ccb55abde44e94e6c4d0bafc94f5870d2674d1944e9a81f6537d9ac92e8ebc",
    ),
    (
        "lobject.h",
        "274c18373fbbad71bfebd534cae4b2d2e49934abf6672f44735edc6646fb6a8b",
    ),
    (
        "lopcodes.h",
        "a15fe349da7c1e73b563e8c3249fe7d535eccc844cb30ec80b4e335b0699279b",
    ),
    (
        "lvm.c",
        "b560aad0a1b8bfc4e4b732b2393e8f8ecc68b6c772e6d25763d6ef71c38ab709",
    ),
];

const OP_CLOSURE: u8 = 36;

#[derive(Clone, Debug, PartialEq, Eq)]
struct IndependentClosure {
    owner: String,
    instruction_id: String,
    pc: usize,
    bx: usize,
    child_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedClosure {
    owner: String,
    instruction_id: String,
    pc: usize,
    bx: usize,
    resolved_id: String,
    comment: String,
    text_suffix: String,
    xref_target: String,
}

#[derive(Clone, Debug)]
struct PublicObservation {
    closures: Vec<ObservedClosure>,
    disasm_stdout: Vec<u8>,
    disasm_stderr: Vec<u8>,
    text_stdout: Vec<u8>,
    text_stderr: Vec<u8>,
    xrefs_stdout: Vec<u8>,
    xrefs_stderr: Vec<u8>,
}

#[derive(Clone, Debug)]
struct IndependentProto {
    path: String,
    words: Vec<u32>,
    children: Vec<IndependentProto>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    sizeof_int: usize,
    sizeof_sizet: usize,
    number_size: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> u8 {
        let value = self.bytes[self.pos];
        self.pos += 1;
        value
    }

    fn uint(&mut self, width: usize) -> usize {
        assert!((1..=8).contains(&width));
        let mut value = 0_u64;
        for index in 0..width {
            value |= u64::from(self.bytes[self.pos + index]) << (index * 8);
        }
        self.pos += width;
        value as usize
    }

    fn int(&mut self) -> usize {
        self.uint(self.sizeof_int)
    }

    fn string(&mut self) {
        let length = self.uint(self.sizeof_sizet);
        self.pos += length;
    }

    fn word(&mut self) -> u32 {
        let word = u32::from_le_bytes(
            self.bytes[self.pos..self.pos + 4]
                .try_into()
                .expect("instruction word"),
        );
        self.pos += 4;
        word
    }
}

fn workspace() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse_chunk(bytes: &[u8]) -> IndependentProto {
    assert_eq!(&bytes[0..4], b"\x1bLua");
    assert_eq!(bytes[4], 0x51);
    assert_eq!(bytes[6], 1, "acceptance fixtures are little-endian");
    assert_eq!(bytes[9], 4, "Lua 5.1 instruction words are four bytes");
    let mut cursor = Cursor {
        bytes,
        pos: 12,
        sizeof_int: bytes[7] as usize,
        sizeof_sizet: bytes[8] as usize,
        number_size: bytes[10] as usize,
    };
    let root = parse_proto(&mut cursor, "0".to_string());
    assert_eq!(cursor.pos, bytes.len(), "independent parser consumed chunk");
    root
}

fn parse_proto(cursor: &mut Cursor<'_>, path: String) -> IndependentProto {
    cursor.string();
    cursor.int();
    cursor.int();
    cursor.byte();
    cursor.byte();
    cursor.byte();
    cursor.byte();

    let instruction_count = cursor.int();
    let words = (0..instruction_count).map(|_| cursor.word()).collect();

    for _ in 0..cursor.int() {
        match cursor.byte() {
            0 => {}
            1 => {
                cursor.byte();
            }
            3 => cursor.pos += cursor.number_size,
            4 => cursor.string(),
            tag => panic!("unexpected stock Lua 5.1 constant tag {tag}"),
        }
    }

    let child_count = cursor.int();
    let mut children = Vec::with_capacity(child_count);
    for index in 0..child_count {
        children.push(parse_proto(cursor, format!("{path}/{index}")));
    }

    let line_count = cursor.int();
    cursor.pos += line_count * cursor.sizeof_int;
    for _ in 0..cursor.int() {
        cursor.string();
        cursor.int();
        cursor.int();
    }
    for _ in 0..cursor.int() {
        cursor.string();
    }

    IndependentProto {
        path,
        words,
        children,
    }
}

fn opcode(word: u32) -> u8 {
    (word & 0x3f) as u8
}

fn field_bx(word: u32) -> usize {
    ((word >> 14) & 0x3ffff) as usize
}

fn collect_independent(proto: &IndependentProto, out: &mut Vec<IndependentClosure>) {
    for (pc, word) in proto.words.iter().copied().enumerate() {
        if opcode(word) == OP_CLOSURE {
            let bx = field_bx(word);
            assert!(bx < proto.children.len(), "valid compiler-produced CLOSURE");
            out.push(IndependentClosure {
                owner: format!("proto:{}", proto.path),
                instruction_id: format!("proto:{}:pc:{pc}", proto.path),
                pc,
                bx,
                child_id: format!("proto:{}/{}", proto.path, bx),
            });
        }
    }
    for child in &proto.children {
        collect_independent(child, out);
    }
}

fn independent_closures(path: &Path) -> Vec<IndependentClosure> {
    let bytes = std::fs::read(path).expect("read fixture");
    let root = parse_chunk(&bytes);
    let mut closures = Vec::new();
    collect_independent(&root, &mut closures);
    closures
}

fn luad_bin() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path.into();
    }
    let root = workspace();
    let output = Command::new("cargo")
        .args(["build", "-p", "luad-cli", "--bin", "luad"])
        .current_dir(&root)
        .output()
        .expect("build luad CLI");
    assert!(
        output.status.success(),
        "luad build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    root.join("target/debug/luad")
}

fn run(args: &[&str]) -> Output {
    Command::new(luad_bin())
        .args(args)
        .output()
        .expect("run public luad CLI")
}

fn schema_valid(schema_name: &str, bytes: &[u8]) {
    let schema_path = workspace().join("tests/schemas").join(schema_name);
    let schema: serde_json::Value =
        serde_json::from_slice(&std::fs::read(schema_path).expect("read schema"))
            .expect("parse schema");
    let instance: serde_json::Value = serde_json::from_slice(bytes).expect("parse output JSON");
    let validator = jsonschema::validator_for(&schema).expect("compile schema");
    if let Err(error) = validator.validate(&instance) {
        panic!("{schema_name} rejected public output: {error}");
    }
}

fn text_closure_suffixes(text: &str) -> BTreeMap<(String, usize), String> {
    let mut owner = None;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("; proto:") {
            if let Some((path, _)) = rest.split_once(" (") {
                owner = Some(format!("proto:{path}"));
            }
            continue;
        }
        if !line.contains(" CLOSURE ") {
            continue;
        }
        let current_owner = owner
            .clone()
            .expect("CLOSURE appears within prototype section");
        let pc = line
            .split_whitespace()
            .next()
            .expect("instruction PC")
            .parse::<usize>()
            .expect("numeric PC");
        let suffix = line
            .rsplit_once(" ; ")
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();
        assert!(
            result.insert((current_owner, pc), suffix).is_none(),
            "unique closure row"
        );
    }
    result
}

fn collect_public_disasm(
    proto: &DisassembledPrototype,
    text: &BTreeMap<(String, usize), String>,
    xrefs: &XrefResponse,
    out: &mut Vec<ObservedClosure>,
) {
    let owner = proto.id.to_string();
    for instruction in &proto.instructions {
        if instruction.mnemonic != "CLOSURE" {
            continue;
        }
        let bx = instruction.encoded_operands.bx as usize;
        let resolved_id = instruction
            .operands
            .iter()
            .find(|operand| operand.name == "Bx")
            .and_then(|operand| operand.resolved.as_ref())
            .and_then(|resolved| match resolved {
                ResolvedFact::Prototype { id, .. } => Some(id.to_string()),
                _ => None,
            })
            .expect("CLOSURE prototype resolution");
        let instantiates: Vec<_> = xrefs
            .entries
            .iter()
            .filter(|entry| {
                entry.source == instruction.id && entry.relation == XrefRelation::Instantiates
            })
            .collect();
        assert_eq!(instantiates.len(), 1, "one instantiates xref per CLOSURE");
        out.push(ObservedClosure {
            owner: owner.clone(),
            instruction_id: instruction.id.to_string(),
            pc: instruction.pc,
            bx,
            resolved_id,
            comment: instruction.comment.clone().unwrap_or_default(),
            text_suffix: text
                .get(&(owner.clone(), instruction.pc))
                .cloned()
                .expect("matching text CLOSURE"),
            xref_target: instantiates[0].target.to_string(),
        });
    }
    for child in &proto.child_protos {
        collect_public_disasm(child, text, xrefs, out);
    }
}

fn capture_public(path: &Path, explicit: bool) -> PublicObservation {
    let path_string = path.to_str().expect("UTF-8 fixture path");
    let mut disasm_args = vec!["disasm", path_string];
    if explicit {
        disasm_args.extend(["--dialect", "lua5.1"]);
    }
    let mut json_args = disasm_args.clone();
    json_args.extend(["--format", "json"]);
    let disasm = run(&json_args);
    assert!(disasm.status.success(), "public JSON disasm failed");

    let mut text_args = disasm_args;
    text_args.extend(["--format", "text"]);
    let text = run(&text_args);
    assert!(text.status.success(), "public text disasm failed");

    let xrefs = run(&["xrefs", path_string, "--format", "json"]);
    assert!(xrefs.status.success(), "public xrefs failed");

    let disasm_doc: MachineDocument<DisassembledPrototype> =
        serde_json::from_slice(&disasm.stdout).expect("typed disasm document");
    let xref_doc: MachineDocument<XrefResponse> =
        serde_json::from_slice(&xrefs.stdout).expect("typed xref document");
    let text_map = text_closure_suffixes(&String::from_utf8_lossy(&text.stdout));
    let mut closures = Vec::new();
    collect_public_disasm(&disasm_doc.data, &text_map, &xref_doc.data, &mut closures);

    PublicObservation {
        closures,
        disasm_stdout: disasm.stdout,
        disasm_stderr: disasm.stderr,
        text_stdout: text.stdout,
        text_stderr: text.stderr,
        xrefs_stdout: xrefs.stdout,
        xrefs_stderr: xrefs.stderr,
    }
}

fn compare(expected: &[IndependentClosure], observed: &[ObservedClosure]) -> Result<(), String> {
    if expected.len() != observed.len() {
        return Err(format!(
            "closure count mismatch: expected {}, observed {}",
            expected.len(),
            observed.len()
        ));
    }
    for (index, (expected, observed)) in expected.iter().zip(observed).enumerate() {
        let checks = [
            ("owner", expected.owner.as_str(), observed.owner.as_str()),
            (
                "instruction_id",
                expected.instruction_id.as_str(),
                observed.instruction_id.as_str(),
            ),
            (
                "resolved_id",
                expected.child_id.as_str(),
                observed.resolved_id.as_str(),
            ),
            (
                "comment",
                expected.child_id.as_str(),
                observed.comment.as_str(),
            ),
            (
                "text_suffix",
                expected.child_id.as_str(),
                observed.text_suffix.as_str(),
            ),
            (
                "xref_target",
                expected.child_id.as_str(),
                observed.xref_target.as_str(),
            ),
        ];
        for (field, expected_value, observed_value) in checks {
            if expected_value != observed_value {
                return Err(format!(
                    "closure[{index}] {field} mismatch: expected {expected_value}, observed {observed_value}"
                ));
            }
        }
        if expected.pc != observed.pc {
            return Err(format!(
                "closure[{index}] pc mismatch: expected {}, observed {}",
                expected.pc, observed.pc
            ));
        }
        if expected.bx != observed.bx {
            return Err(format!(
                "closure[{index}] Bx mismatch: expected {}, observed {}",
                expected.bx, observed.bx
            ));
        }
    }
    Ok(())
}

fn repaired_live_observation(
    expected: &[IndependentClosure],
    mut observed: PublicObservation,
) -> PublicObservation {
    assert_eq!(expected.len(), observed.closures.len());
    for (expected, observed) in expected.iter().zip(&mut observed.closures) {
        observed.comment.clone_from(&expected.child_id);
        observed.text_suffix.clone_from(&expected.child_id);
    }
    compare(expected, &observed.closures).expect("repaired live observation is valid");
    observed
}

fn expect_rejection(expected: &[IndependentClosure], observed: &[ObservedClosure], reason: &str) {
    let error = compare(expected, observed).expect_err("mutation must be rejected");
    assert!(
        error.contains(reason),
        "rejection reason '{error}' does not contain '{reason}'"
    );
}

#[test]
fn test_authority_fixture_and_independent_recursive_paths_pinned() {
    assert_eq!(LUA_515_TARBALL_SHA256.len(), 64);
    assert_eq!(AUTHORITY_HASHES.len(), 4);
    assert!(AUTHORITY_HASHES.iter().all(|(_, hash)| hash.len() == 64));
    for (relative, expected_hash) in [CLOSURES_FIXTURE, HELLO_FIXTURE] {
        let bytes = std::fs::read(workspace().join(relative)).expect("pinned fixture");
        assert_eq!(sha256(&bytes), expected_hash, "fixture hash: {relative}");
        parse_chunk(&bytes);
    }
    let expected = independent_closures(&workspace().join(CLOSURES_FIXTURE.0));
    assert_eq!(
        expected,
        vec![
            IndependentClosure {
                owner: "proto:0".to_string(),
                instruction_id: "proto:0:pc:0".to_string(),
                pc: 0,
                bx: 0,
                child_id: "proto:0/0".to_string(),
            },
            IndependentClosure {
                owner: "proto:0/0".to_string(),
                instruction_id: "proto:0/0:pc:3".to_string(),
                pc: 3,
                bx: 0,
                child_id: "proto:0/0/0".to_string(),
            },
            IndependentClosure {
                owner: "proto:0/0/0".to_string(),
                instruction_id: "proto:0/0/0:pc:6".to_string(),
                pc: 6,
                bx: 0,
                child_id: "proto:0/0/0/0".to_string(),
            },
        ]
    );
}

#[test]
fn test_public_closure_identity_agrees_across_json_text_and_xrefs() {
    let fixture = workspace().join(CLOSURES_FIXTURE.0);
    let expected = independent_closures(&fixture);
    let observed = capture_public(&fixture, true);
    assert!(observed.disasm_stderr.is_empty());
    assert!(observed.text_stderr.is_empty());
    assert!(observed.xrefs_stderr.is_empty());
    schema_valid("disasm.schema.json", &observed.disasm_stdout);
    schema_valid("xrefs.schema.json", &observed.xrefs_stdout);
    compare(&expected, &observed.closures).expect("owner-relative public closure identity");
}

#[test]
fn test_auto_explicit_schemas_determinism_and_no_closure_control() {
    let closures = workspace().join(CLOSURES_FIXTURE.0);
    let explicit = capture_public(&closures, true);
    let automatic = capture_public(&closures, false);
    assert_eq!(explicit.closures, automatic.closures);
    assert_eq!(explicit.disasm_stderr, automatic.disasm_stderr);
    assert_eq!(explicit.text_stderr, automatic.text_stderr);

    let repeated = capture_public(&closures, true);
    assert_eq!(explicit.disasm_stdout, repeated.disasm_stdout);
    assert_eq!(explicit.disasm_stderr, repeated.disasm_stderr);
    assert_eq!(explicit.text_stdout, repeated.text_stdout);
    assert_eq!(explicit.text_stderr, repeated.text_stderr);
    assert_eq!(explicit.xrefs_stdout, repeated.xrefs_stdout);
    assert_eq!(explicit.xrefs_stderr, repeated.xrefs_stderr);

    let hello = workspace().join(HELLO_FIXTURE.0);
    assert!(independent_closures(&hello).is_empty());
    let no_closures = capture_public(&hello, true);
    assert!(no_closures.closures.is_empty());
    schema_valid("disasm.schema.json", &no_closures.disasm_stdout);
    schema_valid("xrefs.schema.json", &no_closures.xrefs_stdout);
}

#[test]
fn test_killer_flattened_and_owner_path_mutations_rejected() {
    let fixture = workspace().join(CLOSURES_FIXTURE.0);
    let expected = independent_closures(&fixture);
    let base = repaired_live_observation(&expected, capture_public(&fixture, true));

    let mut flattened = base.clone();
    flattened.closures[1].comment = "proto:0".to_string();
    expect_rejection(&expected, &flattened.closures, "comment");

    let mut dropped_owner = base.clone();
    dropped_owner.closures[2].resolved_id = "proto:0/0/0".to_string();
    expect_rejection(&expected, &dropped_owner.closures, "resolved_id");
}

#[test]
fn test_killer_channel_and_xref_disagreement_rejected() {
    let fixture = workspace().join(CLOSURES_FIXTURE.0);
    let expected = independent_closures(&fixture);
    let base = repaired_live_observation(&expected, capture_public(&fixture, true));

    let mut json_only = base.clone();
    json_only.closures[0].comment = "proto:0".to_string();
    expect_rejection(&expected, &json_only.closures, "comment");

    let mut text_only = base.clone();
    text_only.closures[0].text_suffix = "proto:0".to_string();
    expect_rejection(&expected, &text_only.closures, "text_suffix");

    let mut xref = base;
    xref.closures[1].xref_target = "proto:0".to_string();
    expect_rejection(&expected, &xref.closures, "xref_target");
}

#[test]
fn test_killer_omission_decode_and_reordering_rejected() {
    let fixture = workspace().join(CLOSURES_FIXTURE.0);
    let expected = independent_closures(&fixture);
    let base = repaired_live_observation(&expected, capture_public(&fixture, true));

    let mut omitted = base.clone();
    omitted.closures.pop();
    expect_rejection(&expected, &omitted.closures, "closure count");

    let mut changed_decode = expected.clone();
    changed_decode[0].bx = 1;
    expect_rejection(&changed_decode, &base.closures, "Bx");

    let mut reordered = base;
    reordered.closures.swap(0, 1);
    expect_rejection(&expected, &reordered.closures, "owner");
}
