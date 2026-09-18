//! Independent public acceptance for Lua 5.1 reference and condition operands.
//!
//! The byte parser and instruction decoder below are test-local transcriptions of the
//! PUC-Rio Lua 5.1.5 chunk and opcode layouts. They deliberately do not call luad's
//! Lua 5.1 parser, opcode, disassembly, or validation helpers.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::envelope::{MachineDocument, ValidationResponse};
use luad_core::{DisassembledPrototype, OperandKind, ResolvedFact};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

const FIXTURES: [(&str, &str, &str); 5] = [
    (
        "tests/fixtures/precompiled/lua51/hello.luac",
        "d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f",
        "lua5.1",
    ),
    (
        "tests/fixtures/precompiled/lua51/control_flow.luac",
        "d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40",
        "lua5.1",
    ),
    (
        "tests/fixtures/precompiled/lua51/closures.luac",
        "62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e",
        "lua5.1",
    ),
    (
        "tests/fixtures/precompiled/lua51_32bit/hello.luac",
        "e3b4aecb3e5669ff3636603d38583acead47336d870377685716ed6dd32e4fb4",
        "lua5.1",
    ),
    (
        "tests/fixtures/precompiled/lua51_lnum32/hello.luac",
        "8376be37ec3042d3b0a87aa39db7d7396fb54ae390abe346d885e1527d23e353",
        "lua5.1-lnum32",
    ),
];

const AUTHORITY_HASHES: [(&str, &str); 3] = [
    (
        "lopcodes.h",
        "a15fe349da7c1e73b563e8c3249fe7d535eccc844cb30ec80b4e335b0699279b",
    ),
    (
        "lopcodes.c",
        "63cd74edc75970092a8ce078c4ab970efa1ee18de960d00eb826d49fe98d8a76",
    ),
    (
        "lvm.c",
        "b560aad0a1b8bfc4e4b732b2393e8f8ecc68b6c772e6d25763d6ef71c38ab709",
    ),
];

const OP_GETUPVAL: u8 = 4;
const OP_SETUPVAL: u8 = 8;
const OP_EQ: u8 = 23;
const OP_LT: u8 = 24;
const OP_LE: u8 = 25;
const OP_CLOSURE: u8 = 36;
const CLAIM_CODES: [&str; 3] = ["L51-UPVAL-001", "L51-PROTO-002", "L51-BOOL-001"];
const REG_CODES: [&str; 3] = ["L51-REG-001", "L51-REG-002", "L51-REG-003"];

#[derive(Clone, Debug)]
struct InstructionFact {
    pc: usize,
    byte_offset: usize,
    word: u32,
}

#[derive(Clone, Debug)]
struct ProtoFact {
    path: String,
    nups_offset: usize,
    maxstack_offset: usize,
    nups: u8,
    maxstack: u8,
    instructions: Vec<InstructionFact>,
    children: Vec<ProtoFact>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    sizeof_int: usize,
    sizeof_sizet: usize,
    number_size: usize,
}

impl<'a> Cursor<'a> {
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

    fn word(&mut self) -> (usize, u32) {
        let offset = self.pos;
        let value = u32::from_le_bytes(
            self.bytes[offset..offset + 4]
                .try_into()
                .expect("instruction"),
        );
        self.pos += 4;
        (offset, value)
    }
}

fn parse_fixture(bytes: &[u8]) -> ProtoFact {
    assert_eq!(&bytes[0..4], b"\x1bLua", "PUC chunk signature");
    assert_eq!(bytes[4], 0x51, "Lua 5.1 version byte");
    assert_eq!(bytes[6], 1, "little-endian fixture");
    assert_eq!(bytes[9], 4, "32-bit instruction words");
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

fn parse_proto(cursor: &mut Cursor<'_>, path: String) -> ProtoFact {
    cursor.string();
    cursor.int();
    cursor.int();
    let nups_offset = cursor.pos;
    let nups = cursor.byte();
    cursor.byte();
    cursor.byte();
    let maxstack_offset = cursor.pos;
    let maxstack = cursor.byte();

    let instruction_count = cursor.int();
    let mut instructions = Vec::with_capacity(instruction_count);
    for pc in 0..instruction_count {
        let (byte_offset, word) = cursor.word();
        instructions.push(InstructionFact {
            pc,
            byte_offset,
            word,
        });
    }

    for _ in 0..cursor.int() {
        match cursor.byte() {
            0 => {}
            1 => {
                cursor.byte();
            }
            3 => cursor.pos += cursor.number_size,
            4 => cursor.string(),
            9 => cursor.pos += 4,
            tag => panic!("unexpected Lua 5.1 constant tag {tag}"),
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

    ProtoFact {
        path,
        nups_offset,
        maxstack_offset,
        nups,
        maxstack,
        instructions,
        children,
    }
}

fn opcode(word: u32) -> u8 {
    (word & 0x3f) as u8
}
fn field_a(word: u32) -> u8 {
    ((word >> 6) & 0xff) as u8
}
fn field_b(word: u32) -> u16 {
    ((word >> 23) & 0x1ff) as u16
}
fn field_bx(word: u32) -> u32 {
    (word >> 14) & 0x3ffff
}
fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    u32::from(op) | (u32::from(a) << 6) | (u32::from(c) << 14) | (u32::from(b) << 23)
}
fn iabx(op: u8, a: u8, bx: u32) -> u32 {
    u32::from(op) | (u32::from(a) << 6) | (bx << 14)
}

fn compare_decoded(word: u32, expected_opcode: u8, expected_b: u16) -> Result<(), String> {
    let observed = (opcode(word), field_b(word));
    let expected = (expected_opcode, expected_b);
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "independent decode mismatch: observed={observed:?}, expected={expected:?}"
        ))
    }
}
fn root() -> PathBuf {
    luad_oracle::find_workspace_root()
}
fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn luad_bin() -> PathBuf {
    luad_oracle::luad_binary_path()
}

fn write_word(bytes: &mut [u8], instruction: &InstructionFact, replacement: u32) {
    let range = instruction.byte_offset..instruction.byte_offset + 4;
    assert_eq!(
        u32::from_le_bytes(bytes[range.clone()].try_into().expect("original word")),
        instruction.word
    );
    bytes[range].copy_from_slice(&replacement.to_le_bytes());
}

fn temp_chunk(bytes: &[u8]) -> NamedTempFile {
    let file = NamedTempFile::new().expect("temporary chunk");
    std::fs::write(file.path(), bytes).expect("write temporary chunk");
    file
}

fn run_validate(path: &Path, dialect: &str, strict: bool, format: &str) -> Output {
    let mut command = Command::new(luad_bin());
    command.args([
        "validate",
        path.to_str().expect("UTF-8 path"),
        "--dialect",
        dialect,
        "--format",
        format,
    ]);
    if strict {
        command.arg("--strict");
    }
    command.output().expect("run public validate CLI")
}

fn run_validate_auto(path: &Path) -> Output {
    Command::new(luad_bin())
        .args([
            "validate",
            path.to_str().expect("UTF-8 path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run auto-selected public validate CLI")
}

fn json_document(output: &Output) -> MachineDocument<ValidationResponse> {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "validate stdout is not JSON: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn claimed_for_target<'a>(
    doc: &'a MachineDocument<ValidationResponse>,
    target: &str,
) -> Vec<&'a Diagnostic> {
    doc.data
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic.target.to_string() == target
                && (CLAIM_CODES.contains(&diagnostic.code.as_str())
                    || REG_CODES.contains(&diagnostic.code.as_str()))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExpectedDiagnostic {
    verdict: Verdict,
    code: String,
    severity: Severity,
    category: DiagnosticCategory,
    target: String,
    message: String,
    byte_offset: usize,
    byte_length: usize,
    raw_hex: String,
}

fn compare_fact(actual: &ExpectedDiagnostic, expected: &ExpectedDiagnostic) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "diagnostic fact mismatch: actual={actual:?}, expected={expected:?}"
        ))
    }
}

fn expected(
    code: &str,
    proto: &ProtoFact,
    instruction: &InstructionFact,
    word: u32,
    message: String,
) -> ExpectedDiagnostic {
    ExpectedDiagnostic {
        verdict: Verdict::Invalid,
        code: code.to_string(),
        severity: Severity::Error,
        category: DiagnosticCategory::Instruction,
        target: format!("proto:{}:pc:{}", proto.path, instruction.pc),
        message,
        byte_offset: instruction.byte_offset,
        byte_length: 4,
        raw_hex: hex::encode(word.to_le_bytes()),
    }
}

fn compare_diagnostic(
    doc: &MachineDocument<ValidationResponse>,
    expected: &ExpectedDiagnostic,
) -> Result<(), String> {
    if doc.data.verdict != Verdict::Invalid {
        return Err("verdict is not invalid".to_string());
    }
    let matching = claimed_for_target(doc, &expected.target);
    if matching.len() != 1 {
        return Err(format!(
            "expected one claimed diagnostic, found {matching:?}"
        ));
    }
    let actual = matching[0];
    let source = actual.source.as_ref().ok_or("diagnostic source missing")?;
    let observed = ExpectedDiagnostic {
        verdict: doc.data.verdict,
        code: actual.code.clone(),
        severity: actual.severity,
        category: actual.category,
        target: actual.target.to_string(),
        message: actual.message.clone(),
        byte_offset: source.byte_offset,
        byte_length: source.byte_length,
        raw_hex: source.raw_hex.clone(),
    };
    compare_fact(&observed, expected)
}

fn mutated_upvalue(
    op: u8,
    declared_nups: u8,
    index: u16,
) -> (NamedTempFile, ProtoFact, InstructionFact, u32) {
    let mut bytes = std::fs::read(root().join(FIXTURES[0].0)).expect("hello fixture");
    let proto = parse_fixture(&bytes);
    assert_eq!(proto.nups, 0, "base fixture declares no root upvalues");
    let instruction = proto.instructions[0].clone();
    bytes[proto.nups_offset] = declared_nups;
    let word = iabc(op, 0, index, 0);
    write_word(&mut bytes, &instruction, word);
    (temp_chunk(&bytes), proto, instruction, word)
}

fn mutated_comparison(op: u8, flag: u8) -> (NamedTempFile, ProtoFact, InstructionFact, u32) {
    let mut bytes = std::fs::read(root().join(FIXTURES[0].0)).expect("hello fixture");
    let proto = parse_fixture(&bytes);
    let instruction = proto.instructions[0].clone();
    bytes[proto.maxstack_offset] = 1;
    let word = iabc(op, flag, 0x100, 0x101);
    write_word(&mut bytes, &instruction, word);
    (temp_chunk(&bytes), proto, instruction, word)
}

#[test]
fn test_authority_and_fixture_hashes_are_pinned() {
    for (relative, expected_hash, _) in FIXTURES {
        let bytes = std::fs::read(root().join(relative)).expect("pinned fixture");
        assert_eq!(sha256(&bytes), expected_hash, "fixture hash: {relative}");
        parse_fixture(&bytes);
    }
    assert_eq!(AUTHORITY_HASHES.len(), 3);
    assert!(AUTHORITY_HASHES.iter().all(|(_, hash)| hash.len() == 64));
}

#[test]
fn test_pinned_public_controls_have_no_reference_operand_diagnostics() {
    for (relative, _, dialect) in FIXTURES {
        let output = run_validate(&root().join(relative), dialect, false, "json");
        assert!(output.status.success(), "control failed: {relative}");
        assert!(output.stderr.is_empty(), "machine stderr: {relative}");
        let doc = json_document(&output);
        assert!(
            doc.data
                .diagnostics
                .iter()
                .all(|d| !CLAIM_CODES.contains(&d.code.as_str())),
            "unexpected claimed diagnostic for {relative}: {:?}",
            doc.data.diagnostics
        );
        let automatic = run_validate_auto(&root().join(relative));
        assert!(
            automatic.status.success(),
            "auto-selection failed: {relative}"
        );
        let automatic_doc = json_document(&automatic);
        assert_eq!(
            automatic_doc.data, doc.data,
            "auto/explicit result: {relative}"
        );
    }
}

#[test]
fn test_valid_upvalue_at_maxstack_is_not_a_register_for_get_and_set() {
    for op in [OP_GETUPVAL, OP_SETUPVAL] {
        let (file, proto, instruction, word) = mutated_upvalue(op, 5, 4);
        assert_eq!((opcode(word), field_b(word), proto.maxstack), (op, 4, 4));
        let output = run_validate(file.path(), "lua5.1", false, "json");
        let doc = json_document(&output);
        let target = format!("proto:{}:pc:{}", proto.path, instruction.pc);
        assert!(
            claimed_for_target(&doc, &target).is_empty(),
            "valid upvalue misclassified: {:?}",
            doc.data.diagnostics
        );
        assert!(
            output.status.success(),
            "valid upvalue mutation must validate"
        );
    }
}

#[test]
fn test_getupval_first_out_of_range_index_has_exact_diagnostic() {
    let (file, proto, instruction, word) = mutated_upvalue(OP_GETUPVAL, 4, 4);
    let expected = expected(
        "L51-UPVAL-001",
        &proto,
        &instruction,
        word,
        "GETUPVAL field B upvalue index 4 out of bounds (declared upvalues: 4) at PC 0".to_string(),
    );
    compare_diagnostic(
        &json_document(&run_validate(file.path(), "lua5.1", false, "json")),
        &expected,
    )
    .expect("exact GETUPVAL diagnostic");
}

#[test]
fn test_setupval_first_out_of_range_index_has_exact_diagnostic() {
    let (file, proto, instruction, word) = mutated_upvalue(OP_SETUPVAL, 4, 4);
    let expected = expected(
        "L51-UPVAL-001",
        &proto,
        &instruction,
        word,
        "SETUPVAL field B upvalue index 4 out of bounds (declared upvalues: 4) at PC 0".to_string(),
    );
    compare_diagnostic(
        &json_document(&run_validate(file.path(), "lua5.1", false, "json")),
        &expected,
    )
    .expect("exact SETUPVAL diagnostic");
}

#[test]
fn test_closure_first_out_of_range_child_has_exact_diagnostic() {
    let mut bytes = std::fs::read(root().join(FIXTURES[0].0)).expect("hello fixture");
    let proto = parse_fixture(&bytes);
    assert!(proto.children.is_empty());
    let instruction = proto.instructions[0].clone();
    let word = iabx(OP_CLOSURE, 0, 0);
    write_word(&mut bytes, &instruction, word);
    assert_eq!(field_bx(word), 0);
    let file = temp_chunk(&bytes);
    let expected = expected(
        "L51-PROTO-002",
        &proto,
        &instruction,
        word,
        "CLOSURE field Bx child prototype index 0 out of bounds (child prototypes: 0) at PC 0"
            .to_string(),
    );
    compare_diagnostic(
        &json_document(&run_validate(file.path(), "lua5.1", false, "json")),
        &expected,
    )
    .expect("exact CLOSURE diagnostic");
}

#[test]
fn test_comparison_boolean_domain_is_exact_for_eq_lt_and_le() {
    for (op, name) in [(OP_EQ, "EQ"), (OP_LT, "LT"), (OP_LE, "LE")] {
        for flag in [0, 1] {
            let (file, proto, instruction, word) = mutated_comparison(op, flag);
            assert_eq!(field_a(word), flag);
            let doc = json_document(&run_validate(file.path(), "lua5.1", false, "json"));
            let target = format!("proto:{}:pc:{}", proto.path, instruction.pc);
            assert!(
                claimed_for_target(&doc, &target).is_empty(),
                "{name} A={flag} misclassified: {:?}",
                doc.data.diagnostics
            );
        }
        let (file, proto, instruction, word) = mutated_comparison(op, 2);
        let expected = expected(
            "L51-BOOL-001",
            &proto,
            &instruction,
            word,
            format!("{name} field A comparison flag 2 outside legal boolean domain 0..=1 at PC 0"),
        );
        compare_diagnostic(
            &json_document(&run_validate(file.path(), "lua5.1", false, "json")),
            &expected,
        )
        .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn test_public_disasm_uses_non_register_reference_operand_kinds() {
    let (file, _, _, _) = mutated_upvalue(OP_GETUPVAL, 5, 4);
    let output = Command::new(luad_bin())
        .args([
            "disasm",
            file.path().to_str().expect("UTF-8 path"),
            "--dialect",
            "lua5.1",
            "--format",
            "json",
        ])
        .output()
        .expect("run disasm");
    assert!(output.status.success());
    let doc: MachineDocument<DisassembledPrototype> =
        serde_json::from_slice(&output.stdout).expect("disasm document");
    let getupval = &doc.data.instructions[0];
    let operand = getupval
        .operands
        .iter()
        .find(|operand| operand.name == "B")
        .expect("B operand");
    assert!(matches!(
        operand.kind,
        OperandKind::ImmediateUnsigned { value: 4 }
    ));
    assert!(matches!(
        operand.resolved,
        Some(ResolvedFact::Upvalue { index: 4, .. })
    ));

    let closure_path = root().join(FIXTURES[2].0);
    let output = Command::new(luad_bin())
        .args([
            "disasm",
            closure_path.to_str().expect("UTF-8 path"),
            "--dialect",
            "lua5.1",
            "--format",
            "json",
        ])
        .output()
        .expect("run closure disasm");
    let doc: MachineDocument<DisassembledPrototype> =
        serde_json::from_slice(&output.stdout).expect("closure disasm document");
    let bx = doc.data.instructions[0]
        .operands
        .iter()
        .find(|operand| operand.name == "Bx")
        .expect("Bx operand");
    assert!(matches!(
        bx.kind,
        OperandKind::ImmediateUnsigned { value: 0 }
    ));
    assert!(matches!(
        bx.resolved,
        Some(ResolvedFact::Prototype { index: 0, .. })
    ));

    let (comparison_file, _, _, _) = mutated_comparison(OP_LT, 1);
    let output = Command::new(luad_bin())
        .args([
            "disasm",
            comparison_file.path().to_str().expect("UTF-8 path"),
            "--dialect",
            "lua5.1",
            "--format",
            "json",
        ])
        .output()
        .expect("run comparison disasm");
    let doc: MachineDocument<DisassembledPrototype> =
        serde_json::from_slice(&output.stdout).expect("comparison disasm document");
    let flag = doc.data.instructions[0]
        .operands
        .iter()
        .find(|operand| operand.name == "A")
        .expect("A operand");
    assert!(matches!(
        flag.kind,
        OperandKind::ImmediateUnsigned { value: 1 }
    ));
}

#[test]
fn test_strict_permissive_text_schema_and_determinism() {
    let (file, proto, instruction, word) = mutated_upvalue(OP_GETUPVAL, 4, 4);
    let expected = expected(
        "L51-UPVAL-001",
        &proto,
        &instruction,
        word,
        "GETUPVAL field B upvalue index 4 out of bounds (declared upvalues: 4) at PC 0".to_string(),
    );
    let permissive_one = run_validate(file.path(), "lua5.1", false, "json");
    let permissive_two = run_validate(file.path(), "lua5.1", false, "json");
    assert_eq!(permissive_one.stdout, permissive_two.stdout);
    assert_eq!(permissive_one.stderr, permissive_two.stderr);
    let strict = run_validate(file.path(), "lua5.1", true, "json");
    assert!(!permissive_one.status.success() && !strict.status.success());
    assert!(permissive_one.stderr.is_empty() && strict.stderr.is_empty());
    let permissive_doc = json_document(&permissive_one);
    let strict_doc = json_document(&strict);
    compare_diagnostic(&permissive_doc, &expected).expect("permissive identity");
    compare_diagnostic(&strict_doc, &expected).expect("strict identity");
    assert_eq!(permissive_doc.data.diagnostics, strict_doc.data.diagnostics);

    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root().join("tests/schemas/validate.schema.json"))
            .expect("validation schema"),
    )
    .expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("compile schema");
    let instance: serde_json::Value =
        serde_json::from_slice(&permissive_one.stdout).expect("validation JSON");
    validator
        .validate(&instance)
        .expect("live JSON satisfies schema");

    let text = String::from_utf8(run_validate(file.path(), "lua5.1", false, "text").stdout)
        .expect("text output");
    assert!(text.contains(&expected.code) && text.contains(&expected.target));
}

#[test]
fn test_killer_bound_mutations_are_rejected_by_positive_comparator() {
    let (_, proto, instruction, word) = mutated_upvalue(OP_GETUPVAL, 4, 4);
    let good = expected(
        "L51-UPVAL-001",
        &proto,
        &instruction,
        word,
        "GETUPVAL field B upvalue index 4 out of bounds (declared upvalues: 4) at PC 0".to_string(),
    );
    compare_fact(&good, &good).expect("positive comparator route");
    let mut bad = good.clone();
    bad.message =
        "GETUPVAL field B upvalue index 4 out of bounds (declared upvalues: 5) at PC 0".to_string();
    assert!(compare_fact(&good, &bad).is_err());
}

#[test]
fn test_killer_diagnostic_identity_mutations_are_rejected() {
    let (_, proto, instruction, word) = mutated_upvalue(OP_GETUPVAL, 4, 4);
    let good = expected(
        "L51-UPVAL-001",
        &proto,
        &instruction,
        word,
        "GETUPVAL field B upvalue index 4 out of bounds (declared upvalues: 4) at PC 0".to_string(),
    );
    for mutation in 0..9 {
        let mut bad = good.clone();
        match mutation {
            0 => bad.code = "L51-REG-002".to_string(),
            1 => bad.target = "proto:0:pc:1".to_string(),
            2 => bad.byte_offset += 1,
            3 => bad.raw_hex = "00000000".to_string(),
            4 => bad.message.push_str(" (mutated)"),
            5 => bad.severity = Severity::Warning,
            6 => bad.category = DiagnosticCategory::Structure,
            7 => bad.verdict = Verdict::ValidForParser,
            8 => bad.byte_length = 3,
            _ => unreachable!(),
        }
        assert!(
            compare_fact(&good, &bad).is_err(),
            "killer mutation {mutation}"
        );
    }
}

#[test]
fn test_killer_independent_decode_mutation_is_rejected() {
    let (_, _, _, observed_word) = mutated_upvalue(OP_GETUPVAL, 5, 4);
    compare_decoded(observed_word, OP_GETUPVAL, 4).expect("positive decoder route");
    assert!(compare_decoded(observed_word, OP_SETUPVAL, 4).is_err());
    assert!(compare_decoded(observed_word, OP_GETUPVAL, 5).is_err());
}
