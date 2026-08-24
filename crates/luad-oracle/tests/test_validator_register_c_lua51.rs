//! Independent public acceptance for the Lua 5.1 fixed-role register-`C` authority.
//!
//! This module is the first authoring checkpoint of the sprint and holds one dimension
//! only: a physical `C` field that the VM never dereferences as a stack slot carries no
//! `L51-REG-003`, however large that field's encoded value is. The remaining dimensions
//! of the contract - the `CONCAT` boundary, bit-8 `CONCAT.C`, disassembly typing, mode
//! invariance and recursion, and the conditional `RK` rows - are deliberately absent
//! until the steward authorizes suite expansion.
//!
//! The 38-row authority below is a test-local transcription of PUC-Rio Lua 5.1.5
//! `lopcodes.h`, `lopcodes.c` and `lvm.c`: a row is `FixedRegister` only where the VM
//! arm unconditionally uses `C` as a direct register index. So is the chunk reader and
//! the instruction encoder. Nothing here calls luad's Lua 5.1 opcode, disassembly, or
//! validation helpers, and the reader decodes only the root prototype prologue - the
//! tail of the chunk is never interpreted.
//!
//! Terminology: the driven values below are not called "legal non-registers". They are
//! values of a `C` field that lies outside the fixed-role register claim, so the sprint
//! makes no statement about whether some other contract bounds them.
//!
//! Derivation note: every case is one single-word replacement of the pinned
//! `control_flow` fixture at the root prototype's PC 0, and records its full provenance
//! (base hash, prototype path, PC, byte offset, original word, changed `C`, changed
//! word, result hash).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use luad_core::diagnostic::Diagnostic;
use luad_core::envelope::{MachineDocument, ValidationResponse};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

/// A machine document read structurally, so no assertion depends on envelope field names.
type Json = serde_json::Value;

/// The pinned sprint fixture every derived chunk is built from.
const CONTROL_FLOW: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/control_flow.luac",
    "d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40",
);

/// Total number of stock Lua 5.1.5 opcodes.
const OPCODE_COUNT: usize = 38;

/// The fixed-role register-`C` diagnostic this checkpoint claims.
const REG_C_CODE: &str = "L51-REG-003";

/// The largest `C` value whose ninth bit is clear, so the probes below ask about the
/// fixed-register role alone and never enter the `RK` constant encoding. It is far above
/// any fixture's `maxstacksize`, which Lua 5.1 caps at 250.
const HIGH_C: u16 = 255;

/// The nine physical `C` bits of an `iABC` word.
const C_MASK: u32 = 0x1ff << 14;

// ---------------------------------------------------------------------------
// The independent authority
// ---------------------------------------------------------------------------

/// What the Lua 5.1.5 VM does with the nine physical `C` bits of one opcode.
///
/// A test-local restatement of the PUC-Rio operand modes, deliberately independent of
/// luad's own opcode metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CRole {
    /// `C` is always a register index and must be below `maxstacksize`.
    FixedRegister,
    /// `C` is an `RK` slot: a register while `C < 256`, otherwise a constant index.
    /// Outside this sprint's fixed-role claim in either encoding.
    ConditionalRk,
    /// `C` is a control flag the VM compares, never an index.
    Boolean,
    /// `C` encodes a result or variable count.
    Count,
    /// `C` is an encoded table size hint.
    SizeHint,
    /// `C` is a `SETLIST` block index into the table being filled.
    ListBlockIndex,
    /// The opcode's VM arm never reads `C`.
    Unused,
    /// The word has no `C` field at all: those bits belong to `Bx` or `sBx`.
    NoCField,
}

impl CRole {
    /// Whether `C` is unconditionally dereferenced as a register, and so must be bounded
    /// by `maxstacksize` and reported under `L51-REG-003` when it is not.
    fn checked_as_register(self) -> bool {
        matches!(self, CRole::FixedRegister)
    }
}

/// One claimed row of the register-`C` authority table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CRow {
    op: u8,
    name: &'static str,
    role: CRole,
}

const fn row(op: u8, name: &'static str, role: CRole) -> CRow {
    CRow { op, name, role }
}

/// The authority: every official Lua 5.1.5 opcode, in enumeration order, with the role
/// of its physical `C` field.
const OFFICIAL_C_ROLES: [CRow; OPCODE_COUNT] = [
    row(0, "MOVE", CRole::Unused),
    row(1, "LOADK", CRole::NoCField),
    row(2, "LOADBOOL", CRole::Boolean),
    row(3, "LOADNIL", CRole::Unused),
    row(4, "GETUPVAL", CRole::Unused),
    row(5, "GETGLOBAL", CRole::NoCField),
    row(6, "GETTABLE", CRole::ConditionalRk),
    row(7, "SETGLOBAL", CRole::NoCField),
    row(8, "SETUPVAL", CRole::Unused),
    row(9, "SETTABLE", CRole::ConditionalRk),
    row(10, "NEWTABLE", CRole::SizeHint),
    row(11, "SELF", CRole::ConditionalRk),
    row(12, "ADD", CRole::ConditionalRk),
    row(13, "SUB", CRole::ConditionalRk),
    row(14, "MUL", CRole::ConditionalRk),
    row(15, "DIV", CRole::ConditionalRk),
    row(16, "MOD", CRole::ConditionalRk),
    row(17, "POW", CRole::ConditionalRk),
    row(18, "UNM", CRole::Unused),
    row(19, "NOT", CRole::Unused),
    row(20, "LEN", CRole::Unused),
    row(21, "CONCAT", CRole::FixedRegister),
    row(22, "JMP", CRole::NoCField),
    row(23, "EQ", CRole::ConditionalRk),
    row(24, "LT", CRole::ConditionalRk),
    row(25, "LE", CRole::ConditionalRk),
    row(26, "TEST", CRole::Boolean),
    row(27, "TESTSET", CRole::Boolean),
    row(28, "CALL", CRole::Count),
    row(29, "TAILCALL", CRole::Unused),
    row(30, "RETURN", CRole::Unused),
    row(31, "FORLOOP", CRole::NoCField),
    row(32, "FORPREP", CRole::NoCField),
    row(33, "TFORLOOP", CRole::Count),
    row(34, "SETLIST", CRole::ListBlockIndex),
    row(35, "CLOSE", CRole::Unused),
    row(36, "CLOSURE", CRole::NoCField),
    row(37, "VARARG", CRole::Unused),
];

/// The same authority stated a second way: each category named with its exact membership.
/// The audit requires the two statements to agree, so a silently edited row in either one
/// is a failure rather than a redefinition.
const CATEGORIES: [(CRole, &[&str]); 8] = [
    (CRole::FixedRegister, &["CONCAT"]),
    (
        CRole::ConditionalRk,
        &[
            "GETTABLE", "SETTABLE", "SELF", "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "EQ", "LT",
            "LE",
        ],
    ),
    (CRole::Boolean, &["LOADBOOL", "TEST", "TESTSET"]),
    (CRole::Count, &["CALL", "TFORLOOP"]),
    (CRole::SizeHint, &["NEWTABLE"]),
    (CRole::ListBlockIndex, &["SETLIST"]),
    (
        CRole::Unused,
        &[
            "MOVE", "LOADNIL", "GETUPVAL", "SETUPVAL", "UNM", "NOT", "LEN", "TAILCALL", "RETURN",
            "CLOSE", "VARARG",
        ],
    ),
    (
        CRole::NoCField,
        &[
            "LOADK",
            "GETGLOBAL",
            "SETGLOBAL",
            "JMP",
            "FORLOOP",
            "FORPREP",
            "CLOSURE",
        ],
    ),
];

/// Proves the authority is exact before any of it is used as evidence: 38 rows, one per
/// official opcode number in order, no duplicate name, and a category partition that
/// agrees with the rows in both directions.
fn audit_authority() {
    assert_eq!(
        OFFICIAL_C_ROLES.len(),
        OPCODE_COUNT,
        "the authority states every stock Lua 5.1.5 opcode"
    );

    for (index, entry) in OFFICIAL_C_ROLES.iter().enumerate() {
        assert_eq!(
            usize::from(entry.op),
            index,
            "{} sits at its official opcode number",
            entry.name
        );
        for other in &OFFICIAL_C_ROLES[index + 1..] {
            assert_ne!(entry.name, other.name, "no opcode is stated twice");
            assert_ne!(entry.op, other.op, "no opcode number is stated twice");
        }
    }

    // Every category names rows that exist and claims their role.
    let mut covered: Vec<&str> = Vec::new();
    for (role, names) in CATEGORIES {
        for name in names {
            let entry = OFFICIAL_C_ROLES
                .iter()
                .find(|entry| entry.name == *name)
                .unwrap_or_else(|| panic!("category {role:?} names an unknown opcode {name}"));
            assert_eq!(
                entry.role, role,
                "{name} is categorised as {role:?} and must carry that role in the table"
            );
            assert!(
                !covered.contains(name),
                "{name} appears in more than one category"
            );
            covered.push(name);
        }
    }
    assert_eq!(
        covered.len(),
        OPCODE_COUNT,
        "the categories partition all {OPCODE_COUNT} opcodes: covered={covered:?}"
    );
    // And every row is named by exactly one category, so neither statement can drift.
    for entry in OFFICIAL_C_ROLES.iter() {
        assert!(
            covered.contains(&entry.name),
            "{} is stated in the table but named by no category",
            entry.name
        );
    }

    let fixed: Vec<&str> = OFFICIAL_C_ROLES
        .iter()
        .filter(|entry| entry.role.checked_as_register())
        .map(|entry| entry.name)
        .collect();
    assert_eq!(
        fixed,
        vec!["CONCAT"],
        "CONCAT is the only opcode whose C is unconditionally a direct register"
    );
}

/// The authority's role for one opcode number.
fn role_of(op: u8) -> CRole {
    OFFICIAL_C_ROLES
        .iter()
        .find(|entry| entry.op == op)
        .unwrap_or_else(|| panic!("opcode {op} has a row in the authority table"))
        .role
}

/// The authority's name for one opcode number.
fn name_of(op: u8) -> &'static str {
    OFFICIAL_C_ROLES
        .iter()
        .find(|entry| entry.op == op)
        .unwrap_or_else(|| panic!("opcode {op} has a row in the authority table"))
        .name
}

// ---------------------------------------------------------------------------
// Test-local chunk reading and encoding
// ---------------------------------------------------------------------------

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

fn field_c(word: u32) -> u16 {
    ((word >> 14) & 0x1ff) as u16
}

fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    u32::from(op) | (u32::from(a) << 6) | (u32::from(c) << 14) | (u32::from(b) << 23)
}

/// One probe word: `op` with the `C` under test, and `A`/`B` controls chosen so `C` is the
/// only operand that can be at fault. Register 0 exists in every prototype, so both are
/// held there.
///
/// A probe that happened to equal the fixture's own word would make its derivation a
/// no-op, so that collision is resolved by moving `A` to the other end of the register
/// file, which is equally legal.
fn probe(op: u8, c: u16, proto: &RootProto) -> u32 {
    let word = iabc(op, 0, 0, c);
    if word != proto.word {
        return word;
    }
    let alternate = iabc(op, proto.maxstacksize - 1, 0, c);
    assert_ne!(
        alternate, proto.word,
        "a probe must differ from the fixture's own word at PC {}",
        proto.pc
    );
    alternate
}

// ---------------------------------------------------------------------------
// The public machine boundary
// ---------------------------------------------------------------------------

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

/// How strictly the boundary is asked to report what it finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The default machine boundary.
    Permissive,
    /// `--strict`.
    Strict,
}

/// Both reporting modes, in the order the sweep drives them.
const MODES: [Mode; 2] = [Mode::Permissive, Mode::Strict];

/// The live JSON Schema the CLI publishes for one machine boundary, compiled once.
fn schema_validator(command: &str) -> &'static jsonschema::Validator {
    static VALIDATE: OnceLock<jsonschema::Validator> = OnceLock::new();
    static DISASM: OnceLock<jsonschema::Validator> = OnceLock::new();
    let cell = match command {
        "validate" => &VALIDATE,
        "disasm" => &DISASM,
        other => panic!("no published schema boundary for {other}"),
    };
    cell.get_or_init(|| {
        let output = Command::new(luad_bin())
            .args(["schema", command])
            .output()
            .unwrap_or_else(|error| panic!("run public schema CLI for {command}: {error}"));
        assert!(
            output.status.success(),
            "luad schema {command} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let schema: Json = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("luad schema {command} is not JSON: {error}"));
        jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("compile the live {command} schema: {error}"))
    })
}

/// Runs one public machine boundary over an in-memory chunk under one reporting mode and
/// returns stdout, having required the live schema to accept the document. A document that
/// has drifted from the published contract cannot be read as evidence for anything.
fn run_bytes(command: &str, bytes: &[u8], mode: Mode, path: &Path) -> Vec<u8> {
    std::fs::write(path, bytes).expect("write derived chunk");
    let mut args = vec![
        command,
        path.to_str().expect("UTF-8 path"),
        "--dialect",
        "lua5.1",
        "--format",
        "json",
    ];
    if mode == Mode::Strict {
        args.push("--strict");
    }
    let output = Command::new(luad_bin())
        .args(&args)
        .output()
        .unwrap_or_else(|error| panic!("run public {command} CLI {mode:?}: {error}"));
    let document: Json = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command} stdout is not JSON ({mode:?}): {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let errors: Vec<String> = schema_validator(command)
        .iter_errors(&document)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "the live {command} schema must accept the document ({mode:?}): {errors:#?}"
    );
    output.stdout
}

/// Runs the public `validate` boundary over an in-memory chunk.
fn validate_bytes(bytes: &[u8], mode: Mode, path: &Path) -> MachineDocument<ValidationResponse> {
    let stdout = run_bytes("validate", bytes, mode, path);
    serde_json::from_slice(&stdout).expect("validate stdout is a machine document")
}

/// Runs the public `disasm` boundary over an in-memory chunk.
fn disasm_bytes(bytes: &[u8], path: &Path) -> Json {
    let stdout = run_bytes("disasm", bytes, Mode::Permissive, path);
    serde_json::from_slice(&stdout).expect("disasm stdout is JSON")
}

/// Every diagnostic carrying one code.
fn findings<'a>(doc: &'a MachineDocument<ValidationResponse>, code: &str) -> Vec<&'a Diagnostic> {
    doc.data
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == code)
        .collect()
}

/// Every diagnostic code the document carries, for evidence in failure messages. Codes
/// other than the one under test never satisfy or defeat an assertion here; they are
/// printed so a red is never mistaken for a different contract's finding.
fn all_codes(doc: &MachineDocument<ValidationResponse>) -> Vec<String> {
    doc.data
        .diagnostics
        .iter()
        .map(|diagnostic| format!("{}@{}", diagnostic.code, diagnostic.target))
        .collect()
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/// A test-local chunk derived by replacing exactly one instruction word of the pinned
/// base, together with the provenance the sprint requires for every derived case.
struct Derived {
    bytes: Vec<u8>,
    word: u32,
    evidence: String,
}

/// Replaces the word at `proto.byte_offset` with `word` and records base hash, prototype
/// path, PC, original word, changed `C`, changed word, and result hash.
fn derive(base: &[u8], base_hash: &str, proto: &RootProto, word: u32, note: &str) -> Derived {
    let mut bytes = base.to_vec();
    bytes[proto.byte_offset..proto.byte_offset + 4].copy_from_slice(&word.to_le_bytes());
    let result = sha256(&bytes);
    let evidence = format!(
        "{note}: base={base_hash} proto={} pc={} byte_offset={} original_word={:#010x} \
         changed_c={} changed_word={word:#010x} maxstacksize={} result={result}",
        proto.path,
        proto.pc,
        proto.byte_offset,
        proto.word,
        field_c(word),
        proto.maxstacksize,
    );
    assert_ne!(base_hash, result, "derived chunk differs: {evidence}");
    Derived {
        bytes,
        word,
        evidence,
    }
}

/// Reads the pinned base fixture, pins its hash, and decodes the root prologue facts every
/// derived case is built from.
fn pinned_base() -> (Vec<u8>, String, RootProto) {
    let relative = CONTROL_FLOW.0;
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative),
        root().join(relative),
    ];
    let path = candidates
        .iter()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| panic!("pinned fixture {relative} must exist: tried {candidates:?}"));
    let base = std::fs::read(path).unwrap_or_else(|error| panic!("read {relative}: {error}"));
    let base_hash = sha256(&base);
    assert_eq!(
        base_hash, CONTROL_FLOW.1,
        "pinned fixture {relative} must hash to its recorded SHA-256"
    );

    let proto = read_root_proto(&base);
    assert!(
        usize::from(opcode(proto.word)) < OPCODE_COUNT,
        "PC {} decodes to a stock opcode, so the code offset is aligned: word={:#010x}",
        proto.pc,
        proto.word
    );
    assert!(
        proto.maxstacksize >= 1 && u16::from(proto.maxstacksize) < HIGH_C,
        "the driven C value must sit above this prototype's register count: maxstacksize={}",
        proto.maxstacksize
    );
    (base, base_hash, proto)
}

/// Proves the derived word really reached public disassembly as the instruction at the
/// recorded PC, so an absent finding cannot be an artefact of a chunk the boundary never
/// decoded the way this test believes it did.
fn assert_word_reached_disasm(case: &Derived, proto: &RootProto, op: u8, path: &Path) {
    let document = disasm_bytes(&case.bytes, path);
    let mut instructions: Vec<&Json> = Vec::new();
    fn walk<'a>(value: &'a Json, out: &mut Vec<&'a Json>) {
        match value {
            Json::Object(map) => {
                if value.get("opcode_num").is_some() && value.get("encoded_operands").is_some() {
                    out.push(value);
                }
                map.values().for_each(|nested| walk(nested, out));
            }
            Json::Array(items) => items.iter().for_each(|item| walk(item, out)),
            _ => {}
        }
    }
    walk(&document, &mut instructions);

    let instruction = instructions
        .iter()
        .find(|instruction| instruction["pc"].as_u64() == Some(proto.pc as u64))
        .unwrap_or_else(|| {
            panic!(
                "the disassembly must list PC {}\n{}",
                proto.pc, case.evidence
            )
        });
    assert_eq!(
        (
            instruction["opcode_num"].as_u64(),
            instruction["mnemonic"].as_str(),
            instruction["raw_word"].as_u64(),
        ),
        (
            Some(u64::from(op)),
            Some(name_of(op)),
            Some(u64::from(case.word)),
        ),
        "the derived word must reach public disassembly as {} at PC {}\n{}",
        name_of(op),
        proto.pc,
        case.evidence
    );
}

// ---------------------------------------------------------------------------
// The checkpoint
// ---------------------------------------------------------------------------

/// The representative rows this checkpoint drives: one size hint, one count, one unused
/// field. Each is driven at a `C` well above `maxstacksize` and inside nine bits.
const DRIVEN: [(u8, CRole); 3] = [
    (10, CRole::SizeHint), // NEWTABLE.C: encoded hash-size hint
    (33, CRole::Count),    // TFORLOOP.C: loop-variable count
    (29, CRole::Unused),   // TAILCALL.C: never read by the VM arm
];

/// The opcode whose `C` the authority does class as a direct register, used only as the
/// positive control that `L51-REG-003` is observable through this harness at all.
const OP_CONCAT: u8 = 21;

#[test]
fn test_high_non_register_c_fields_report_no_register_c_findings() {
    audit_authority();

    let (base, base_hash, proto) = pinned_base();
    let file = NamedTempFile::new().expect("temporary chunk");
    let path = file.path();
    let target = format!("proto:{}:pc:{}", proto.path, proto.pc);

    // Positive control. `CONCAT.C` is the one fixed-register C in the authority, so an
    // out-of-frame value there must be reported. This proves the code under test is
    // observable at this PC through this harness, so the absences asserted below are
    // evidence rather than an artefact of a silent boundary.
    let control_word = iabc(OP_CONCAT, 0, 0, u16::from(proto.maxstacksize));
    let control = derive(
        &base,
        &base_hash,
        &proto,
        control_word,
        &format!(
            "positive control: CONCAT C={} against maxstacksize={}",
            proto.maxstacksize, proto.maxstacksize
        ),
    );
    assert_word_reached_disasm(&control, &proto, OP_CONCAT, path);
    for mode in MODES {
        let doc = validate_bytes(&control.bytes, mode, path);
        let observed = findings(&doc, REG_C_CODE);
        assert!(
            observed
                .iter()
                .any(|diagnostic| diagnostic.target.to_string() == target),
            "the fixed-register C of CONCAT out of frame must be reported under \
             {REG_C_CODE} at {target} ({mode:?}), otherwise this harness cannot see the \
             code whose absence the cases below assert\n{}\ncodes={:?}",
            control.evidence,
            all_codes(&doc)
        );
    }

    // The cases. Each is one word differing from its own in-frame control in nothing but
    // the nine physical `C` bits.
    let mut false_positives: Vec<String> = Vec::new();
    for (op, expected_role) in DRIVEN {
        let name = name_of(op);
        assert_eq!(
            role_of(op),
            expected_role,
            "{name}.C is driven as the role the authority states"
        );
        assert!(
            !role_of(op).checked_as_register(),
            "{name}.C lies outside the fixed-role register claim"
        );

        let baseline_word = probe(op, 0, &proto);
        let case_word = probe(op, HIGH_C, &proto);
        assert_eq!(
            baseline_word & !C_MASK,
            case_word & !C_MASK,
            "{name}: baseline and case differ in nothing but the physical C bits"
        );
        assert_eq!(field_c(baseline_word), 0);
        assert_eq!(field_c(case_word), HIGH_C);

        let baseline = derive(
            &base,
            &base_hash,
            &proto,
            baseline_word,
            &format!("baseline: {name} C=0 ({expected_role:?})"),
        );
        let case = derive(
            &base,
            &base_hash,
            &proto,
            case_word,
            &format!("case: {name} C={HIGH_C} ({expected_role:?})"),
        );

        // Vacuity: both words reach public disassembly as this opcode at this PC.
        assert_word_reached_disasm(&baseline, &proto, op, path);
        assert_word_reached_disasm(&case, &proto, op, path);

        for mode in MODES {
            // Only `L51-REG-003` is claimed. Diagnostics from other contracts are neither
            // required nor forbidden here, and are recorded, not counted.
            let baseline_doc = validate_bytes(&baseline.bytes, mode, path);
            assert!(
                findings(&baseline_doc, REG_C_CODE).is_empty(),
                "an in-frame {name}.C must not produce {REG_C_CODE} ({mode:?}), so any \
                 finding on the case is attributable to the changed C alone\n{}\ncodes={:?}",
                baseline.evidence,
                all_codes(&baseline_doc)
            );

            let case_doc = validate_bytes(&case.bytes, mode, path);
            let observed = findings(&case_doc, REG_C_CODE);
            if !observed.is_empty() {
                false_positives.push(format!(
                    "{name}.C is a {expected_role:?} field, not a direct register, yet C={HIGH_C} \
                     produced {} {REG_C_CODE} finding(s) under {mode:?}\n  {}\n  findings={:?}\n  \
                     all codes in document={:?}",
                    observed.len(),
                    case.evidence,
                    observed
                        .iter()
                        .map(|diagnostic| format!(
                            "{}@{}: {}",
                            diagnostic.code, diagnostic.target, diagnostic.message
                        ))
                        .collect::<Vec<_>>(),
                    all_codes(&case_doc)
                ));
            }
        }
    }

    assert!(
        false_positives.is_empty(),
        "a physical C field that the VM never dereferences as a register must not produce \
         {REG_C_CODE} at any nine-bit value; {} case/mode combination(s) of {} did:\n\n{}",
        false_positives.len(),
        DRIVEN.len() * MODES.len(),
        false_positives.join("\n\n")
    );
}
