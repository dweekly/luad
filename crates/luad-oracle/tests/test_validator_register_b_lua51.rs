//! Independent public acceptance for the Lua 5.1 fixed-role register-`B` authority.
//!
//! This module is being built one durable checkpoint at a time; it currently holds only
//! the first acceptance assertion, that a high but legal scalar `NEWTABLE.B` is not a
//! register and therefore carries no `L51-REG-002`.
//!
//! The chunk reader and instruction encoder below are test-local transcriptions of the
//! PUC-Rio Lua 5.1.5 chunk and opcode layouts. They deliberately do not call luad's
//! Lua 5.1 opcode, disassembly, or validation helpers, and they decode only the root
//! prototype prologue: the tail of the chunk is never interpreted.
//!
//! Derivation note: the pinned `control_flow` fixture is compiled from a source with no
//! table constructor, so it contains no `NEWTABLE` to edit in place. The derivation is
//! therefore two single-word steps from the pinned bytes at the same code offset: a
//! `NEWTABLE A=0 B=0 C=0` control, and the case that changes only that word's `B` field
//! to 255. Both steps record their full provenance.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use luad_core::diagnostic::{Diagnostic, Verdict};
use luad_core::envelope::{MachineDocument, ValidationResponse};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

/// Pinned sprint fixture the derived chunks are built from.
const CONTROL_FLOW: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/control_flow.luac",
    "d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40",
);

/// Positions in the official Lua 5.1.5 opcode enumeration.
const OP_SETUPVAL: u8 = 8;
const OP_NEWTABLE: u8 = 10;
/// Total number of stock Lua 5.1.5 opcodes, used only as an alignment sanity check.
const OPCODE_COUNT: u8 = 38;

const REG_B_CODE: &str = "L51-REG-002";
/// Owned by the prerequisite reference-operand contract; used here purely to prove that
/// the derived word really is decoded as the instruction at the recorded PC.
const UPVAL_CODE: &str = "L51-UPVAL-001";

/// `NEWTABLE.B` is an encoded ("floating point byte") array-size hint, so every value in
/// `0..=255` is legal regardless of `maxstacksize`. 255 is the largest such value and is
/// far above any fixture's register count.
const HIGH_LEGAL_B: u16 = 255;

/// The nine physical `B` bits of an `iABC` word.
const B_MASK: u32 = 0x1ff << 23;

/// Facts read from the base chunk by the test-local reader.
struct RootProto {
    path: String,
    maxstacksize: u8,
    pc: usize,
    byte_offset: usize,
    word: u32,
}

/// Reads the root prototype prologue and its first instruction word. Only the fields the
/// derived cases need are decoded.
fn read_root_proto(bytes: &[u8]) -> RootProto {
    assert_eq!(&bytes[0..4], b"\x1bLua", "PUC chunk signature");
    assert_eq!(bytes[4], 0x51, "Lua 5.1 version byte");
    assert_eq!(bytes[6], 1, "little-endian fixture");
    assert_eq!(bytes[9], 4, "32-bit instruction words");
    let sizeof_int = bytes[7] as usize;
    let sizeof_sizet = bytes[8] as usize;
    assert_eq!(sizeof_int, 4, "stock 64-bit layout");
    assert_eq!(sizeof_sizet, 8, "stock 64-bit layout");

    let uint = |pos: usize, width: usize| -> usize {
        assert!((1..=8).contains(&width));
        let mut value = 0_u64;
        for index in 0..width {
            value |= u64::from(bytes[pos + index]) << (index * 8);
        }
        value as usize
    };

    let mut pos = 12;
    let source_len = uint(pos, sizeof_sizet);
    pos += sizeof_sizet + source_len;
    pos += 2 * sizeof_int; // linedefined, lastlinedefined
    pos += 3; // nups, numparams, is_vararg
    let maxstacksize = bytes[pos];
    pos += 1;
    let instruction_count = uint(pos, sizeof_int);
    pos += sizeof_int;
    assert!(instruction_count > 0, "root prototype has code");
    assert!(
        pos + 4 * instruction_count <= bytes.len(),
        "code array lies inside the chunk"
    );

    RootProto {
        path: "0".to_string(),
        maxstacksize,
        pc: 0,
        byte_offset: pos,
        word: u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("instruction word")),
    }
}

fn opcode(word: u32) -> u8 {
    (word & 0x3f) as u8
}

fn field_b(word: u32) -> u16 {
    ((word >> 23) & 0x1ff) as u16
}

fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    u32::from(op) | (u32::from(a) << 6) | (u32::from(c) << 14) | (u32::from(b) << 23)
}

fn root() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn luad_bin() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path.into();
    }
    let workspace = root();
    let output = Command::new("cargo")
        .args(["build", "-p", "luad-cli", "--bin", "luad"])
        .current_dir(&workspace)
        .output()
        .expect("build luad CLI");
    assert!(
        output.status.success(),
        "luad build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    workspace.join("target/debug/luad")
}

fn run_validate(path: &Path) -> Output {
    Command::new(luad_bin())
        .args([
            "validate",
            path.to_str().expect("UTF-8 path"),
            "--dialect",
            "lua5.1",
            "--format",
            "json",
        ])
        .output()
        .expect("run public validate CLI")
}

/// Runs the public `validate` boundary over an in-memory chunk.
fn validate_bytes(bytes: &[u8]) -> MachineDocument<ValidationResponse> {
    let file = NamedTempFile::new().expect("temporary chunk");
    std::fs::write(file.path(), bytes).expect("write derived chunk");
    let output = run_validate(file.path());
    assert!(
        output.stderr.is_empty(),
        "machine stderr must be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "validate stdout is not JSON: {error}\nstdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn findings<'a>(doc: &'a MachineDocument<ValidationResponse>, code: &str) -> Vec<&'a Diagnostic> {
    doc.data
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == code)
        .collect()
}

/// A test-local chunk derived by replacing exactly one instruction word of the pinned
/// base, together with the provenance the sprint requires for every derived case.
struct Derived {
    bytes: Vec<u8>,
    word: u32,
    evidence: String,
}

/// Replaces the word at `proto.byte_offset` with `word` and records base hash, prototype
/// path, PC, original word, changed `B`, changed word, and result hash.
fn derive(base: &[u8], base_hash: &str, proto: &RootProto, word: u32, note: &str) -> Derived {
    let mut bytes = base.to_vec();
    bytes[proto.byte_offset..proto.byte_offset + 4].copy_from_slice(&word.to_le_bytes());
    let result = sha256(&bytes);
    let evidence = format!(
        "{note}: base={base_hash} proto={} pc={} byte_offset={} original_word={:#010x} \
         changed_b={} changed_word={word:#010x} maxstacksize={} result={result}",
        proto.path,
        proto.pc,
        proto.byte_offset,
        proto.word,
        field_b(word),
        proto.maxstacksize,
    );
    assert_ne!(base_hash, result, "derived chunk differs: {evidence}");
    Derived {
        bytes,
        word,
        evidence,
    }
}

#[test]
fn test_high_legal_scalar_b_values_report_no_register_b_findings() {
    let base = std::fs::read(root().join(CONTROL_FLOW.0)).expect("pinned base fixture");
    let base_hash = sha256(&base);
    assert_eq!(
        base_hash, CONTROL_FLOW.1,
        "base fixture hash: {}",
        CONTROL_FLOW.0
    );

    let proto = read_root_proto(&base);
    assert!(
        opcode(proto.word) < OPCODE_COUNT,
        "PC {} decodes to a stock opcode, so the code offset is aligned: word={:#010x}",
        proto.pc,
        proto.word
    );
    assert!(
        (1..HIGH_LEGAL_B as u8).contains(&proto.maxstacksize),
        "the high legal B value must sit above this prototype's register count: \
         maxstacksize={}",
        proto.maxstacksize
    );

    // Control and case differ in nothing but the nine physical `B` bits.
    let control_word = iabc(OP_NEWTABLE, 0, 0, 0);
    let case_word = iabc(OP_NEWTABLE, 0, HIGH_LEGAL_B, 0);
    assert_eq!(control_word & !B_MASK, case_word & !B_MASK);
    assert_eq!(field_b(control_word), 0);
    assert_eq!(field_b(case_word), HIGH_LEGAL_B);

    let case = derive(
        &base,
        &base_hash,
        &proto,
        case_word,
        "case: NEWTABLE B=255 array-size hint",
    );
    let case_doc = validate_bytes(&case.bytes);
    let reg_b = findings(&case_doc, REG_B_CODE);
    assert!(
        reg_b.is_empty(),
        "NEWTABLE.B is an encoded array-size hint, not a direct register, so the high \
         legal value {HIGH_LEGAL_B} must not produce {REG_B_CODE}\n{}\nfindings={reg_b:?}",
        case.evidence
    );

    // The derived word really is the instruction at the recorded PC. `SETUPVAL.B` is an
    // upvalue reference whose bounds belong to the prerequisite reference-operand
    // contract, so this locator is independent of the `B`-register claim under test.
    let locator = derive(
        &base,
        &base_hash,
        &proto,
        iabc(OP_SETUPVAL, 0, 7, 0),
        "locator: SETUPVAL B=7 against a root prototype with no upvalues",
    );
    let locator_doc = validate_bytes(&locator.bytes);
    let located = findings(&locator_doc, UPVAL_CODE);
    let expected_target = format!("proto:{}:pc:{}", proto.path, proto.pc);
    let expected_raw_hex = hex::encode(locator.word.to_le_bytes());
    let hit = located.iter().find(|diagnostic| {
        let source = diagnostic.source.as_ref().expect("diagnostic source word");
        diagnostic.target.to_string() == expected_target
            && source.byte_offset == proto.byte_offset
            && source.byte_length == 4
            && source.raw_hex == expected_raw_hex
    });
    assert!(
        hit.is_some(),
        "the derived word must be validated as the instruction at {expected_target}\n{}\n\
         diagnostics={:?}",
        locator.evidence,
        locator_doc.data.diagnostics
    );

    // Control: the same NEWTABLE with an in-range `B` is clean, so any finding on the
    // case above is attributable to the changed `B` value alone.
    let control = derive(
        &base,
        &base_hash,
        &proto,
        control_word,
        "control: NEWTABLE B=0 array-size hint",
    );
    let control_doc = validate_bytes(&control.bytes);
    assert_eq!(
        control_doc.data.verdict,
        Verdict::ValidForParser,
        "control chunk is otherwise valid\n{}\ndiagnostics={:?}",
        control.evidence,
        control_doc.data.diagnostics
    );
    assert!(
        findings(&control_doc, REG_B_CODE).is_empty(),
        "in-range NEWTABLE.B must not produce {REG_B_CODE}\n{}\ndiagnostics={:?}",
        control.evidence,
        control_doc.data.diagnostics
    );
}
