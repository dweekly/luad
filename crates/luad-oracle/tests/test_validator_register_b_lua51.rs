//! Independent public acceptance for the Lua 5.1 fixed-role register-`B` authority.
//!
//! This module holds six acceptance dimensions:
//!
//! - High but legal scalar `B` values, such as a large `NEWTABLE.B`, are not registers and
//!   therefore carry no `L51-REG-002`.
//! - The role table: an independent 38-row restatement of every official opcode's `B` role,
//!   audited by one pure comparator that must reject the killer mutations of that authority.
//! - The public disassembly types each instruction's `B` operand in agreement with that
//!   authority table.
//! - The register-`B` bound is exact at `maxstacksize`: the highest in-frame index is clean
//!   and the index one past it is reported.
//! - Register-`B` findings are mode-invariant, schema-valid, and reach recursive child
//!   prototypes.
//! - Scalar counts and unused `B` fields are never typed as registers.
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
use std::sync::OnceLock;

use luad_core::diagnostic::{Diagnostic, Verdict};
use luad_core::envelope::{MachineDocument, ValidationResponse};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

/// Pinned sprint fixture the derived chunks are built from.
const CONTROL_FLOW: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/control_flow.luac",
    "d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40",
);

/// The other two pinned Lua 5.1 fixtures of the sprint. `closures.luac` is the one whose
/// prototype tree is deep enough to carry a nested `proto:0/0/0` target.
const HELLO: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/hello.luac",
    "d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f",
);
const CLOSURES: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/closures.luac",
    "62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e",
);

/// Every pinned fixture, in the order the mode sweep drives them.
const PINNED_FIXTURES: [(&str, (&str, &str)); 3] = [
    ("hello", HELLO),
    ("control_flow", CONTROL_FLOW),
    ("closures", CLOSURES),
];

/// Positions in the official Lua 5.1.5 opcode enumeration.
const OP_SETUPVAL: u8 = 8;
const OP_NEWTABLE: u8 = 10;
const OP_CONCAT: u8 = 21;
const OP_TESTSET: u8 = 27;
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

/// How the boundary is told which dialect a chunk is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selection {
    /// No `--dialect`: the CLI identifies the chunk itself.
    Automatic,
    /// `--dialect lua5.1`, naming the dialect the fixtures are compiled for.
    Explicit,
}

/// How strictly the boundary is asked to report what it finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The default machine boundary.
    Permissive,
    /// `--strict`.
    Strict,
}

/// Every selection/mode combination, in the order the sweeps drive them.
const MODE_MATRIX: [(Selection, Mode); 4] = [
    (Selection::Automatic, Mode::Permissive),
    (Selection::Automatic, Mode::Strict),
    (Selection::Explicit, Mode::Permissive),
    (Selection::Explicit, Mode::Strict),
];

/// Runs one public machine boundary of the CLI over a chunk on disk under one
/// selection/mode combination.
fn run_luad_as(command: &str, path: &Path, selection: Selection, mode: Mode) -> Output {
    let mut args = vec![command, path.to_str().expect("UTF-8 path")];
    if selection == Selection::Explicit {
        args.extend(["--dialect", "lua5.1"]);
    }
    args.extend(["--format", "json"]);
    if mode == Mode::Strict {
        args.push("--strict");
    }
    Command::new(luad_bin())
        .args(&args)
        .output()
        .unwrap_or_else(|error| panic!("run public {command} CLI {selection:?}/{mode:?}: {error}"))
}

/// The live JSON Schema the CLI publishes for one machine boundary, fetched from
/// `luad schema <command>` and compiled once per process.
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
        let schema: Json = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "luad schema {command} is not JSON: {error}\nstdout={}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
        jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("compile the live {command} schema: {error}"))
    })
}

/// Rejects a document unless the live schema for `command` accepts it. Every validation
/// error is fatal: a document that has drifted from the published contract cannot be read
/// as evidence for anything.
fn assert_live_schema(command: &str, document: &Json) {
    let errors: Vec<String> = schema_validator(command)
        .iter_errors(document)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "the live {command} schema must accept the document: {errors:#?}\ndocument={document}"
    );
}

/// One observation of a public machine boundary: exit status, stderr, and stdout parsed and
/// checked against the live schema for that command.
struct Run {
    status: Option<i32>,
    stderr: String,
    stdout: Vec<u8>,
}

/// Runs a public machine boundary over an in-memory chunk under one selection/mode
/// combination. Every document that leaves this function has passed the live schema.
fn run_bytes(command: &str, bytes: &[u8], selection: Selection, mode: Mode) -> Run {
    let file = NamedTempFile::new().expect("temporary chunk");
    std::fs::write(file.path(), bytes).expect("write derived chunk");
    let output = run_luad_as(command, file.path(), selection, mode);
    let document: Json = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command} stdout is not JSON ({selection:?}/{mode:?}): {error}\nstdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_live_schema(command, &document);
    Run {
        status: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        stdout: output.stdout,
    }
}

/// Runs a public machine boundary over an in-memory chunk and returns its stdout.
fn json_stdout(command: &str, bytes: &[u8]) -> Vec<u8> {
    let run = run_bytes(command, bytes, Selection::Explicit, Mode::Permissive);
    assert!(
        run.stderr.is_empty(),
        "machine stderr must be empty ({command}): {}",
        run.stderr
    );
    run.stdout
}

/// Runs the public `validate` boundary over an in-memory chunk.
fn validate_bytes(bytes: &[u8]) -> MachineDocument<ValidationResponse> {
    let stdout = json_stdout("validate", bytes);
    serde_json::from_slice(&stdout).unwrap_or_else(|error| {
        panic!(
            "validate stdout is not JSON: {error}\nstdout={}",
            String::from_utf8_lossy(&stdout)
        )
    })
}

/// Runs the public `disasm` boundary over an in-memory chunk.
fn disasm_bytes(bytes: &[u8]) -> Json {
    let stdout = json_stdout("disasm", bytes);
    serde_json::from_slice(&stdout).unwrap_or_else(|error| {
        panic!(
            "disasm stdout is not JSON: {error}\nstdout={}",
            String::from_utf8_lossy(&stdout)
        )
    })
}

/// Reads a pinned fixture and refuses to hand back bytes that do not hash to its pin. The
/// sprint pins content, so the file is looked for under both the crate and workspace roots.
fn load_pinned((relative, expected): (&str, &str)) -> Vec<u8> {
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative),
        root().join(relative),
    ];
    let path = candidates
        .iter()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| panic!("pinned fixture {relative} must exist: tried {candidates:?}"));
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("read {relative}: {error}"));
    assert_eq!(
        sha256(&bytes),
        expected,
        "pinned fixture {relative} must hash to its recorded SHA-256"
    );
    bytes
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
    let (base, base_hash, proto) = pinned_base();
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

/// A `B` value no prototype in this fixture can address as a register, so a finding on any
/// row below is a false positive attributable to the `B` field alone.
const OUT_OF_RANGE_B: u16 = 255;

/// The ten rows the authority table types as a scalar or an unused field, each with the `B`
/// value it is driven at. `LOADBOOL.B` is a boolean, so 1 is its widest meaningful value; the
/// others carry counts, hints, or nothing at all, so each is driven at the largest encodable
/// `B`, which is out of register range for this fixture.
const SCALAR_OR_UNUSED_CASES: [(&str, u16); 10] = [
    ("LOADBOOL", 1),
    ("NEWTABLE", OUT_OF_RANGE_B),
    ("TEST", OUT_OF_RANGE_B),
    ("CALL", OUT_OF_RANGE_B),
    ("TAILCALL", OUT_OF_RANGE_B),
    ("RETURN", OUT_OF_RANGE_B),
    ("TFORLOOP", OUT_OF_RANGE_B),
    ("SETLIST", OUT_OF_RANGE_B),
    ("CLOSE", OUT_OF_RANGE_B),
    ("VARARG", OUT_OF_RANGE_B),
];

#[test]
fn test_scalar_count_and_unused_b_fields_are_never_typed_as_registers() {
    let (base, base_hash, proto) = pinned_base();
    assert!(
        u16::from(proto.maxstacksize) < OUT_OF_RANGE_B,
        "the out-of-range probe must sit above this prototype's register count: \
         maxstacksize={}",
        proto.maxstacksize
    );

    // The driven rows are exactly the authority's `ScalarOrUnused` rows, so neither list can
    // grow or shrink without the other.
    let driven: Vec<&str> = SCALAR_OR_UNUSED_CASES
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let claimed: Vec<&str> = OFFICIAL_B_ROLES
        .iter()
        .filter(|row| row.role == BRole::ScalarOrUnused)
        .map(|row| row.name)
        .collect();
    assert_eq!(
        driven, claimed,
        "every scalar-or-unused B row is driven, in authority order"
    );

    let mut false_positives: Vec<String> = Vec::new();
    for (name, b) in SCALAR_OR_UNUSED_CASES {
        let row = OFFICIAL_B_ROLES
            .iter()
            .find(|row| row.name == name)
            .unwrap_or_else(|| panic!("{name} has a row in the authority table"));
        assert_eq!(
            row.role,
            BRole::ScalarOrUnused,
            "{name}.B is a scalar or unused field, not a register"
        );

        let word = probe(row.op, b, &proto);
        let case = derive(
            &base,
            &base_hash,
            &proto,
            word,
            &format!("scalar-or-unused: {name} B={b}"),
        );
        // Unrelated domain diagnostics are allowed: only the register-`B` code is claimed.
        let doc = validate_bytes(&case.bytes);
        let reg_b = findings(&doc, REG_B_CODE);
        if !reg_b.is_empty() {
            false_positives.push(format!("{}\nfindings={reg_b:?}", case.evidence));
        }
    }

    assert!(
        false_positives.is_empty(),
        "a B field that is never dereferenced as a register must not produce {REG_B_CODE} at \
         any value; {} of {} rows did\n{}",
        false_positives.len(),
        SCALAR_OR_UNUSED_CASES.len(),
        false_positives.join("\n")
    );
}

/// A machine document read structurally, so no assertion depends on envelope field names.
type Json = serde_json::Value;

/// Reads the pinned base fixture, pins its hash, and decodes the root prologue facts every
/// derived case is built from.
fn pinned_base() -> (Vec<u8>, String, RootProto) {
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
        proto.maxstacksize >= 1,
        "the base prototype declares a register file: maxstacksize={}",
        proto.maxstacksize
    );
    (base, base_hash, proto)
}

/// One probe word: `op` with the `B` under test, and `A`/`C` controls chosen so `B` is the
/// only operand that can be at fault. `A` is register 0, always legal here; `C` is 0 except
/// for `CONCAT`, whose `C` closes the `B..C` register range and so is kept in range itself.
///
/// A probe that happened to equal the fixture's own first word would make its derivation a
/// no-op, so the collision is resolved by moving `A` to the other end of the register file,
/// which is equally legal.
fn probe(op: u8, b: u16, proto: &RootProto) -> u32 {
    let c = if op == OP_CONCAT {
        u16::from(proto.maxstacksize - 1)
    } else {
        0
    };
    let word = iabc(op, 0, b, c);
    if word != proto.word {
        return word;
    }
    let alternate = iabc(op, proto.maxstacksize - 1, b, c);
    assert_ne!(
        alternate, proto.word,
        "a probe must differ from the fixture's own word at PC {}",
        proto.pc
    );
    alternate
}

/// The rows the authority table claims are always registers: the nine opcodes whose `B` is
/// dereferenced as a stack slot regardless of its value.
fn fixed_register_rows() -> Vec<&'static BRow> {
    OFFICIAL_B_ROLES
        .iter()
        .filter(|row| row.role.checked_as_register())
        .collect()
}

/// Whether a value is a disassembled instruction, judged by its own shape.
fn is_instruction(value: &Json) -> bool {
    value.get("opcode_num").is_some() && value.get("encoded_operands").is_some()
}

/// Every instruction object in a disassembly document, located by its own shape.
fn disasm_instructions(document: &Json) -> Vec<&Json> {
    fn walk<'a>(value: &'a Json, out: &mut Vec<&'a Json>) {
        match value {
            Json::Object(map) => {
                if is_instruction(value) {
                    out.push(value);
                }
                map.values().for_each(|nested| walk(nested, out));
            }
            Json::Array(items) => items.iter().for_each(|item| walk(item, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(document, &mut out);
    out
}

/// Checks a `disasm` document against the schema the CLI itself publishes, rather than
/// against a restatement of it kept here.
fn assert_disasm_schema(document: &Json) {
    assert_live_schema("disasm", document);
}

/// The typed `B` operand of one disassembled instruction, if the disassembler emits one.
fn typed_b(instruction: &Json) -> Option<&Json> {
    instruction["operands"]
        .as_array()?
        .iter()
        .find(|operand| operand["name"].as_str() == Some("B"))
}

#[test]
fn test_public_disasm_types_register_b_against_the_authority_table() {
    let (base, base_hash, proto) = pinned_base();
    // Register 0 exists in every prototype, so the probe value is legal for all 38 rows and
    // the operand's typed kind is the only thing that varies.
    const PROBE_B: u16 = 0;

    let mut typed: Vec<(&'static str, bool)> = Vec::new();
    for row in OFFICIAL_B_ROLES.iter() {
        let word = probe(row.op, PROBE_B, &proto);
        let case = derive(
            &base,
            &base_hash,
            &proto,
            word,
            &format!("disasm probe: {} B={PROBE_B}", row.name),
        );
        let document = disasm_bytes(&case.bytes);
        assert_disasm_schema(&document);

        let instructions = disasm_instructions(&document);
        let instruction = instructions
            .iter()
            .find(|instruction| instruction["pc"].as_u64() == Some(proto.pc as u64))
            .unwrap_or_else(|| {
                panic!(
                    "the disassembly must list PC {}\n{}\ndocument={document}",
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
                Some(u64::from(row.op)),
                Some(row.name),
                Some(u64::from(word)),
            ),
            "the derived word must disassemble as {} at PC {}\n{}",
            row.name,
            proto.pc,
            case.evidence
        );

        let operand_b = typed_b(instruction);
        let is_register = operand_b
            .map(|operand| {
                operand["kind"]["kind"].as_str() == Some("register")
                    && operand["kind"]["index"].as_u64() == Some(u64::from(PROBE_B))
            })
            .unwrap_or(false);
        typed.push((row.name, is_register));
    }

    // `RK` operands are register-or-constant by encoding: deciding which is `RK` authority,
    // so they are excluded here rather than claimed either way.
    let deferred: Vec<&str> = OFFICIAL_B_ROLES
        .iter()
        .filter(|row| row.role == BRole::ConditionalRk)
        .map(|row| row.name)
        .collect();
    let observed: Vec<&str> = typed
        .iter()
        .filter(|(name, is_register)| *is_register && !deferred.contains(name))
        .map(|(name, _)| *name)
        .collect();
    let expected: Vec<&str> = fixed_register_rows().iter().map(|row| row.name).collect();
    assert_eq!(
        observed, expected,
        "the public disassembler must type B as a register for exactly the fixed-register \
         opcodes; {deferred:?} stay deferred to RK authority\ntyped={typed:?}"
    );
}

#[test]
fn test_register_b_boundary_is_exact_at_maxstacksize() {
    let (base, base_hash, proto) = pinned_base();
    let maxstacksize = proto.maxstacksize;
    let rows = fixed_register_rows();
    assert_eq!(
        rows.len(),
        9,
        "every fixed-register B opcode is driven: {:?}",
        rows.iter().map(|row| row.name).collect::<Vec<_>>()
    );
    let target = format!("proto:{}:pc:{}", proto.path, proto.pc);

    for row in rows {
        // `maxstacksize - 1` is the last legal slot and `maxstacksize` the first illegal
        // one, so the two neighbours straddle the bound in one derived chunk each.
        for (b, flagged) in [
            (u16::from(maxstacksize) - 1, false),
            (u16::from(maxstacksize), true),
        ] {
            let word = probe(row.op, b, &proto);
            let case = derive(
                &base,
                &base_hash,
                &proto,
                word,
                &format!(
                    "boundary: {} B={b} against maxstacksize={maxstacksize}",
                    row.name
                ),
            );
            let doc = validate_bytes(&case.bytes);
            let observed: Vec<_> = findings(&doc, REG_B_CODE)
                .iter()
                .map(|diagnostic| {
                    let source = diagnostic.source.as_ref().expect("diagnostic source word");
                    (
                        diagnostic.target.to_string(),
                        source.byte_offset,
                        source.byte_length,
                        source.raw_hex.clone(),
                        diagnostic.message.clone(),
                    )
                })
                .collect();
            let expected: Vec<_> = flagged
                .then(|| {
                    (
                        target.clone(),
                        proto.byte_offset,
                        4_usize,
                        hex::encode(word.to_le_bytes()),
                        format!(
                            "Register B ({b}) exceeds maxstacksize ({maxstacksize}) at PC {}",
                            proto.pc
                        ),
                    )
                })
                .into_iter()
                .collect();
            assert_eq!(
                observed, expected,
                "{}.B at {b} must carry exactly the frozen {REG_B_CODE} evidence for \
                 maxstacksize {maxstacksize}\n{}\ndiagnostics={:?}",
                row.name, case.evidence, doc.data.diagnostics
            );
        }
    }
}

/// The shallowest values under `value` that satisfy `wanted`. Descent stops at a match, so
/// a nested prototype is never confused with the prototype that encloses it.
fn outermost<'a>(value: &'a Json, wanted: &dyn Fn(&Json) -> bool) -> Vec<&'a Json> {
    fn walk<'a>(value: &'a Json, wanted: &dyn Fn(&Json) -> bool, out: &mut Vec<&'a Json>) {
        if wanted(value) {
            out.push(value);
            return;
        }
        match value {
            Json::Object(map) => map.values().for_each(|nested| walk(nested, wanted, out)),
            Json::Array(items) => items.iter().for_each(|item| walk(item, wanted, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, wanted, &mut out);
    out
}

/// The shallowest matching values strictly inside `parent`, in document order.
fn children<'a>(parent: &'a Json, wanted: &dyn Fn(&Json) -> bool) -> Vec<&'a Json> {
    match parent {
        Json::Object(map) => map
            .values()
            .flat_map(|nested| outermost(nested, wanted))
            .collect(),
        Json::Array(items) => items
            .iter()
            .flat_map(|item| outermost(item, wanted))
            .collect(),
        _ => Vec::new(),
    }
}

/// The register-file size a prototype object declares, whatever the document calls it.
fn proto_maxstacksize(value: &Json) -> Option<u64> {
    ["maxstacksize", "max_stack_size", "maxstack"]
        .iter()
        .find_map(|key| value.get(key).and_then(Json::as_u64))
}

/// Whether a value is a prototype: it declares a register file and owns code.
fn is_proto(value: &Json) -> bool {
    proto_maxstacksize(value).is_some() && !outermost(value, &is_instruction).is_empty()
}

/// Every prototype in a disassembly document, keyed by the `0`-rooted, `/`-separated path
/// the validator uses to name it. Nesting is read from the document's own shape.
fn protos_by_path(document: &Json) -> Vec<(String, &Json)> {
    fn walk<'a>(path: String, proto: &'a Json, out: &mut Vec<(String, &'a Json)>) {
        out.push((path.clone(), proto));
        for (index, child) in children(proto, &is_proto).into_iter().enumerate() {
            walk(format!("{path}/{index}"), child, out);
        }
    }
    let roots = outermost(document, &is_proto);
    assert_eq!(
        roots.len(),
        1,
        "a chunk has exactly one root prototype, found {}: document={document}",
        roots.len()
    );
    let mut out = Vec::new();
    walk("0".to_string(), roots[0], &mut out);
    out
}

/// The instructions a prototype owns; a child prototype's code stops the descent.
fn own_instructions(proto: &Json) -> Vec<&Json> {
    children(proto, &|value: &Json| {
        is_instruction(value) || is_proto(value)
    })
    .into_iter()
    .filter(|value| is_instruction(value))
    .collect()
}

/// The semantic instruction records of a disassembly, keyed by the prototype path that owns
/// them. This is the part of the document that must not depend on how the chunk was
/// selected; the surrounding envelope is not comparable because it names the input path.
fn disasm_records(stdout: &[u8]) -> Vec<(String, Json)> {
    let document: Json = serde_json::from_slice(stdout).unwrap_or_else(|error| {
        panic!(
            "disasm stdout is not JSON: {error}\nstdout={}",
            String::from_utf8_lossy(stdout)
        )
    });
    protos_by_path(&document)
        .into_iter()
        .flat_map(|(path, proto)| {
            own_instructions(proto)
                .into_iter()
                .map(move |instruction| (path.clone(), instruction.clone()))
        })
        .collect()
}

/// Locates one instruction by the identity the validator reports for it: the prototype path
/// from the chunk root, and the PC inside that prototype's code array.
fn locate<'a>(document: &'a Json, proto_path: &str, pc: u64) -> (&'a Json, &'a Json) {
    let protos = protos_by_path(document);
    let paths: Vec<&str> = protos.iter().map(|(path, _)| path.as_str()).collect();
    let proto = protos
        .iter()
        .find(|(path, _)| path == proto_path)
        .unwrap_or_else(|| panic!("the disassembly must contain prototype {proto_path}: {paths:?}"))
        .1;
    let matched: Vec<&Json> = own_instructions(proto)
        .into_iter()
        .filter(|instruction| instruction["pc"].as_u64() == Some(pc))
        .collect();
    assert_eq!(
        matched.len(),
        1,
        "prototype {proto_path} must list PC {pc} exactly once: {matched:?}"
    );
    (proto, matched[0])
}

/// The byte offset the disassembler reports for an instruction word. Which key carries it
/// is the document's business; the value is checked against the chunk by the caller.
fn reported_offset(instruction: &Json) -> usize {
    let source = instruction.get("source").unwrap_or(instruction);
    ["byte_offset", "offset", "source_offset", "file_offset"]
        .iter()
        .find_map(|key| {
            instruction
                .get(key)
                .or_else(|| source.get(key))
                .and_then(Json::as_u64)
        })
        .unwrap_or_else(|| panic!("the disassembler must report a source offset: {instruction}"))
        as usize
}

/// One register-`B` finding, reduced to the evidence tuple the sprint freezes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RegBTuple {
    code: String,
    target: String,
    byte_offset: usize,
    byte_length: usize,
    raw_hex: String,
    message: String,
}

/// What one selection/mode combination did at the `validate` boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ModeObservation {
    selection: Selection,
    mode: Mode,
    status: Option<i32>,
    stderr: String,
    tuples: Vec<RegBTuple>,
}

/// Observes the public `validate` boundary once, under one selection/mode combination. The
/// document is schema-checked on the way through by `run_bytes`.
fn observe(bytes: &[u8], selection: Selection, mode: Mode) -> ModeObservation {
    let run = run_bytes("validate", bytes, selection, mode);
    let doc: MachineDocument<ValidationResponse> = serde_json::from_slice(&run.stdout)
        .unwrap_or_else(|error| {
            panic!(
                "validate stdout is not a machine document ({selection:?}/{mode:?}): {error}\n\
                 stdout={}",
                String::from_utf8_lossy(&run.stdout)
            )
        });
    let tuples = doc
        .data
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == REG_B_CODE)
        .map(|diagnostic| {
            let source = diagnostic.source.as_ref().expect("diagnostic source word");
            RegBTuple {
                code: diagnostic.code.to_string(),
                target: diagnostic.target.to_string(),
                byte_offset: source.byte_offset,
                byte_length: source.byte_length,
                raw_hex: source.raw_hex.to_string(),
                message: diagnostic.message.to_string(),
            }
        })
        .collect();
    ModeObservation {
        selection,
        mode,
        status: run.status,
        stderr: run.stderr,
        tuples,
    }
}

/// The single judgement behind every positive assertion below: the four selection/mode
/// combinations must all be present, all fail the chunk quietly, agree with one another,
/// name the nested prototype, and report exactly the expected finding. Returning the
/// rejection instead of panicking lets the killers drive this same comparator.
fn compare_modes(observed: &[ModeObservation], expected: &RegBTuple) -> Result<(), String> {
    let covered: Vec<(Selection, Mode)> = observed
        .iter()
        .map(|observation| (observation.selection, observation.mode))
        .collect();
    if covered[..] != MODE_MATRIX[..] {
        return Err(format!(
            "every selection/mode combination must be observed, in order: expected \
             {MODE_MATRIX:?}, observed {covered:?}"
        ));
    }
    for observation in observed {
        let (selection, mode) = (observation.selection, observation.mode);
        if observation.status != Some(1) {
            return Err(format!(
                "{selection:?}/{mode:?} must exit 1 on a rejected chunk, exited {:?}",
                observation.status
            ));
        }
        if !observation.stderr.is_empty() {
            return Err(format!(
                "{selection:?}/{mode:?} must keep stderr empty, wrote {:?}",
                observation.stderr
            ));
        }
    }
    let first = &observed[0];
    for other in &observed[1..] {
        if other.tuples != first.tuples {
            return Err(format!(
                "{:?}/{:?} and {:?}/{:?} must not diverge: {:?} versus {:?}",
                first.selection,
                first.mode,
                other.selection,
                other.mode,
                first.tuples,
                other.tuples
            ));
        }
    }
    for observation in observed {
        let path = observation.tuples.first().and_then(|tuple| {
            tuple
                .target
                .strip_prefix("proto:")
                .and_then(|rest| rest.rsplit_once(":pc:"))
                .map(|(path, _)| path)
        });
        if let Some(path) = path {
            if !path.contains('/') {
                return Err(format!(
                    "{:?}/{:?} must name the nested prototype path of the offending word, \
                     named {path:?}",
                    observation.selection, observation.mode
                ));
            }
        }
    }
    for observation in observed {
        if observation.tuples != vec![expected.clone()] {
            return Err(format!(
                "{:?}/{:?} must report exactly one {REG_B_CODE} finding {expected:?}, reported \
                 {:?}",
                observation.selection, observation.mode, observation.tuples
            ));
        }
    }
    Ok(())
}

#[test]
fn test_register_b_findings_are_mode_invariant_schema_valid_and_recursive() {
    const TARGET_PATH: &str = "0/0/0";
    const TARGET_PC: u64 = 1;
    let target = format!("proto:{TARGET_PATH}:pc:{TARGET_PC}");

    // The offending word is located through the public disassembler, not by re-parsing the
    // chunk here: the nested prototype and its register file are read off the document.
    let base = load_pinned(CLOSURES);
    let base_hash = sha256(&base);
    let document = disasm_bytes(&base);
    let (proto, instruction) = locate(&document, TARGET_PATH, TARGET_PC);
    let maxstacksize = proto_maxstacksize(proto).expect("the located prototype declares a stack");
    assert_eq!(
        (
            maxstacksize,
            instruction["mnemonic"].as_str(),
            instruction["opcode_num"].as_u64()
        ),
        (4, Some("TESTSET"), Some(u64::from(OP_TESTSET))),
        "{target} is the pinned ordinary TESTSET in a prototype of 4 registers: \
         proto={proto}\ninstruction={instruction}"
    );

    let word = instruction["raw_word"]
        .as_u64()
        .expect("the disassembler reports the raw word") as u32;
    let offset = reported_offset(instruction);
    assert_eq!(
        &base[offset..offset + 4],
        &word.to_le_bytes()[..],
        "the reported source offset {offset} must locate the reported word {word:#010x}"
    );
    assert!(
        u64::from(field_b(word)) < maxstacksize,
        "the located TESTSET must start out ordinary: B={} maxstacksize={maxstacksize}",
        field_b(word)
    );

    // Only `B` moves, and only to the first slot the register file does not have.
    let changed = (word & !B_MASK) | ((maxstacksize as u32) << 23);
    assert_eq!(
        (
            opcode(changed),
            changed & !B_MASK,
            u64::from(field_b(changed))
        ),
        (opcode(word), word & !B_MASK, maxstacksize),
        "only B changes, and it changes to maxstacksize"
    );
    let mut bytes = base.clone();
    bytes[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
    let evidence = format!(
        "recursive: base={base_hash} target={target} byte_offset={offset} \
         original_word={word:#010x} changed_b={} changed_word={changed:#010x} \
         maxstacksize={maxstacksize} result={}",
        field_b(changed),
        sha256(&bytes)
    );

    let expected = RegBTuple {
        code: REG_B_CODE.to_string(),
        target: target.clone(),
        byte_offset: offset,
        byte_length: 4,
        raw_hex: hex::encode(changed.to_le_bytes()),
        message: format!(
            "Register B ({}) exceeds maxstacksize ({maxstacksize}) at PC {TARGET_PC}",
            field_b(changed)
        ),
    };
    let observed: Vec<ModeObservation> = MODE_MATRIX
        .iter()
        .map(|&(selection, mode)| observe(&bytes, selection, mode))
        .collect();
    compare_modes(&observed, &expected)
        .unwrap_or_else(|rejection| panic!("{rejection}\n{evidence}"));

    // Killers: each removes exactly one property the comparator is supposed to enforce, and
    // must be rejected by that same comparator for that reason.
    let mut without_mode = observed.clone();
    without_mode.remove(1);
    let mut changed_tuple = observed.clone();
    for observation in changed_tuple.iter_mut() {
        observation.tuples[0].raw_hex = hex::encode(word.to_le_bytes());
    }
    let mut flattened_path = observed.clone();
    for observation in flattened_path.iter_mut() {
        observation.tuples[0].target = format!("proto:0:pc:{TARGET_PC}");
    }
    let mut divergent = observed.clone();
    divergent[0].tuples.clear();

    for (killer, mutated, reason) in [
        (
            "drops the automatic/strict combination",
            without_mode,
            "combination",
        ),
        (
            "changes one component of the frozen tuple",
            changed_tuple,
            "exactly one",
        ),
        (
            "omits the nested prototype path",
            flattened_path,
            "nested prototype path",
        ),
        (
            "lets automatic and explicit selection diverge",
            divergent,
            "diverge",
        ),
    ] {
        let rejection = compare_modes(&mutated, &expected).expect_err(&format!(
            "the comparator must reject a run that {killer}\n{evidence}"
        ));
        assert!(
            rejection.contains(reason),
            "rejecting a run that {killer} must name {reason:?}: {rejection}\n{evidence}"
        );
    }

    // The same four combinations over the untouched fixtures: a chunk whose B operands are
    // all in range is accepted, quietly, under every selection and mode.
    for (name, pin) in PINNED_FIXTURES {
        let clean = load_pinned(pin);
        for (selection, mode) in MODE_MATRIX {
            let observation = observe(&clean, selection, mode);
            assert_eq!(
                (observation.status, observation.stderr.as_str()),
                (Some(0), ""),
                "unmodified {name} must be accepted quietly under {selection:?}/{mode:?}"
            );
            assert!(
                observation.tuples.is_empty(),
                "unmodified {name} must carry no {REG_B_CODE} finding under \
                 {selection:?}/{mode:?}: {:?}",
                observation.tuples
            );
        }

        // The same clean chunk through the public disassembler, whose documents are checked
        // against the live disasm schema inside `run_bytes`. Selection decides how the chunk
        // reaches luad, never what luad reads out of it.
        let [automatic, explicit] = [Selection::Automatic, Selection::Explicit].map(|selection| {
            let run = run_bytes("disasm", &clean, selection, Mode::Permissive);
            assert_eq!(
                (run.status, run.stderr.as_str()),
                (Some(0), ""),
                "unmodified {name} must disassemble quietly under {selection:?}/permissive"
            );
            disasm_records(&run.stdout)
        });
        assert_eq!(
            automatic, explicit,
            "unmodified {name} must disassemble to the same instruction records under \
             automatic and explicit selection"
        );
    }
}

/// The fixed role of an opcode's `B` field in the official Lua 5.1.5 instruction set.
///
/// This enumeration is a test-local restatement of the PUC-Rio `lopcodes.h` operand
/// modes. It is deliberately independent of luad's own opcode metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BRole {
    /// `B` is always a register index and must be below `maxstacksize`.
    FixedRegister,
    /// `B` is an `RK` slot: a register while `B < 256`, otherwise a constant index.
    ConditionalRk,
    /// `B` indexes the prototype's upvalue array, never the register file.
    UpvalueRef,
    /// `B` is a scalar (count, size hint, or flag) or is unused by the opcode.
    ScalarOrUnused,
    /// The word has no `B` field at all (`iABx` / `iAsBx` layouts).
    NoBField,
}

impl BRole {
    /// Whether some encoding of `B` is dereferenced as a register, and so must be bounded
    /// by `maxstacksize` and reported under `L51-REG-002` when it is not.
    fn checked_as_register(self) -> bool {
        matches!(self, BRole::FixedRegister)
    }
}

/// One claimed row of the register-`B` authority table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BRow {
    op: u8,
    name: &'static str,
    role: BRole,
}

const fn row(op: u8, name: &'static str, role: BRole) -> BRow {
    BRow { op, name, role }
}

/// The authority: every official Lua 5.1.5 opcode, in enumeration order, with the fixed
/// role of its `B` field.
const OFFICIAL_B_ROLES: [BRow; OPCODE_COUNT as usize] = [
    row(0, "MOVE", BRole::FixedRegister),
    row(1, "LOADK", BRole::NoBField),
    row(2, "LOADBOOL", BRole::ScalarOrUnused),
    row(3, "LOADNIL", BRole::FixedRegister),
    row(4, "GETUPVAL", BRole::UpvalueRef),
    row(5, "GETGLOBAL", BRole::NoBField),
    row(6, "GETTABLE", BRole::FixedRegister),
    row(7, "SETGLOBAL", BRole::NoBField),
    row(8, "SETUPVAL", BRole::UpvalueRef),
    row(9, "SETTABLE", BRole::ConditionalRk),
    row(10, "NEWTABLE", BRole::ScalarOrUnused),
    row(11, "SELF", BRole::FixedRegister),
    row(12, "ADD", BRole::ConditionalRk),
    row(13, "SUB", BRole::ConditionalRk),
    row(14, "MUL", BRole::ConditionalRk),
    row(15, "DIV", BRole::ConditionalRk),
    row(16, "MOD", BRole::ConditionalRk),
    row(17, "POW", BRole::ConditionalRk),
    row(18, "UNM", BRole::FixedRegister),
    row(19, "NOT", BRole::FixedRegister),
    row(20, "LEN", BRole::FixedRegister),
    row(21, "CONCAT", BRole::FixedRegister),
    row(22, "JMP", BRole::NoBField),
    row(23, "EQ", BRole::ConditionalRk),
    row(24, "LT", BRole::ConditionalRk),
    row(25, "LE", BRole::ConditionalRk),
    row(26, "TEST", BRole::ScalarOrUnused),
    row(27, "TESTSET", BRole::FixedRegister),
    row(28, "CALL", BRole::ScalarOrUnused),
    row(29, "TAILCALL", BRole::ScalarOrUnused),
    row(30, "RETURN", BRole::ScalarOrUnused),
    row(31, "FORLOOP", BRole::NoBField),
    row(32, "FORPREP", BRole::NoBField),
    row(33, "TFORLOOP", BRole::ScalarOrUnused),
    row(34, "SETLIST", BRole::ScalarOrUnused),
    row(35, "CLOSE", BRole::ScalarOrUnused),
    row(36, "CLOSURE", BRole::NoBField),
    row(37, "VARARG", BRole::ScalarOrUnused),
];

/// The contract's role grouping, restated by name so the table cannot drift silently.
const EXPECTED_GROUPS: [(BRole, &[&str]); 5] = [
    (
        BRole::FixedRegister,
        &[
            "MOVE", "LOADNIL", "GETTABLE", "SELF", "UNM", "NOT", "LEN", "CONCAT", "TESTSET",
        ],
    ),
    (
        BRole::ConditionalRk,
        &[
            "SETTABLE", "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "EQ", "LT", "LE",
        ],
    ),
    (BRole::UpvalueRef, &["GETUPVAL", "SETUPVAL"]),
    (
        BRole::ScalarOrUnused,
        &[
            "LOADBOOL", "NEWTABLE", "TEST", "CALL", "TAILCALL", "RETURN", "TFORLOOP", "SETLIST",
            "CLOSE", "VARARG",
        ],
    ),
    (
        BRole::NoBField,
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

/// A typed reason the comparator refuses a claimed register-`B` authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BReject {
    /// An official opcode has no row.
    MissingRow { op: u8, name: &'static str },
    /// An official opcode has more than one row.
    DuplicateRow { op: u8, name: &'static str },
    /// A row names an opcode outside the official enumeration.
    UnknownOpcode { op: u8 },
    /// A row's mnemonic does not match the official enumeration.
    NameChanged {
        op: u8,
        claimed: &'static str,
        official: &'static str,
    },
    /// A row's role differs from the official role.
    RoleChanged {
        op: u8,
        name: &'static str,
        claimed: BRole,
        official: BRole,
    },
    /// A row claims `FixedRegister` for a `B` field that is not a register.
    NonRegisterMarkedFixed {
        op: u8,
        name: &'static str,
        official: BRole,
    },
}

/// The comparator: a pure audit of a claimed table's structure against the official
/// enumeration.
fn audit(rows: &[BRow]) -> Vec<BReject> {
    let mut rejects = Vec::new();
    let mut seen = [0_u8; OPCODE_COUNT as usize];

    for claimed in rows {
        let Some(official) = OFFICIAL_B_ROLES.iter().find(|row| row.op == claimed.op) else {
            rejects.push(BReject::UnknownOpcode { op: claimed.op });
            continue;
        };
        seen[official.op as usize] += 1;
        if seen[official.op as usize] > 1 {
            rejects.push(BReject::DuplicateRow {
                op: official.op,
                name: official.name,
            });
        }
        if claimed.name != official.name {
            rejects.push(BReject::NameChanged {
                op: official.op,
                claimed: claimed.name,
                official: official.name,
            });
        }
        if claimed.role != official.role {
            rejects.push(if claimed.role.checked_as_register() {
                BReject::NonRegisterMarkedFixed {
                    op: official.op,
                    name: official.name,
                    official: official.role,
                }
            } else {
                BReject::RoleChanged {
                    op: official.op,
                    name: official.name,
                    claimed: claimed.role,
                    official: official.role,
                }
            });
        }
    }

    for official in OFFICIAL_B_ROLES.iter() {
        if seen[official.op as usize] == 0 {
            rejects.push(BReject::MissingRow {
                op: official.op,
                name: official.name,
            });
        }
    }

    rejects
}

fn rows_with(edit: impl FnOnce(&mut Vec<BRow>)) -> Vec<BRow> {
    let mut rows = OFFICIAL_B_ROLES.to_vec();
    edit(&mut rows);
    rows
}

/// Every killer mutation goes through the same comparator as the positive case.
fn assert_killed(label: &str, rows: &[BRow], expected: &[BReject]) {
    let rejects = audit(rows);
    for reason in expected {
        assert!(
            rejects.contains(reason),
            "the comparator must reject this killer mutation: {label}\n\
             expected={reason:?}\nrejects={rejects:?}"
        );
    }
}

#[test]
fn test_lua51_b_role_table_is_exact_and_rejects_killer_mutations() {
    // The table is exactly the 38 official opcodes, each named once, in enumeration order.
    assert_eq!(
        OFFICIAL_B_ROLES.len(),
        OPCODE_COUNT as usize,
        "the authority covers every stock Lua 5.1.5 opcode"
    );
    let mut seen = [0_u8; OPCODE_COUNT as usize];
    for (index, entry) in OFFICIAL_B_ROLES.iter().enumerate() {
        assert_eq!(
            entry.op as usize, index,
            "rows follow the official opcode enumeration: {entry:?}"
        );
        seen[entry.op as usize] += 1;
    }
    assert!(
        seen.iter().all(|count| *count == 1),
        "each official opcode number appears exactly once: {seen:?}"
    );
    for (index, entry) in OFFICIAL_B_ROLES.iter().enumerate() {
        for other in &OFFICIAL_B_ROLES[index + 1..] {
            assert_ne!(
                entry.name, other.name,
                "opcode mnemonics are unique: {entry:?} vs {other:?}"
            );
        }
    }
    // Ties the table to the opcode numbers the first acceptance case already depends on.
    assert_eq!(OFFICIAL_B_ROLES[OP_SETUPVAL as usize].name, "SETUPVAL");
    assert_eq!(OFFICIAL_B_ROLES[OP_NEWTABLE as usize].name, "NEWTABLE");

    // The roles are exact: each group is precisely the opcodes the contract names.
    let names_with = |role: BRole| -> Vec<&'static str> {
        OFFICIAL_B_ROLES
            .iter()
            .filter(|entry| entry.role == role)
            .map(|entry| entry.name)
            .collect()
    };
    let mut grouped = 0;
    for &(role, expected) in EXPECTED_GROUPS.iter() {
        assert_eq!(
            names_with(role),
            expected,
            "the {role:?} group is exactly the opcodes named by the contract"
        );
        grouped += expected.len();
    }
    assert_eq!(
        grouped, OPCODE_COUNT as usize,
        "the five role groups partition all {OPCODE_COUNT} opcodes"
    );

    // Positive case: the exact table audits clean against the official enumeration.
    let clean = audit(&OFFICIAL_B_ROLES);
    assert!(
        clean.is_empty(),
        "the official table must audit clean: {clean:?}"
    );

    // Killer: a dropped row.
    assert_killed(
        "GETTABLE row removed",
        &rows_with(|rows| {
            rows.retain(|entry| entry.name != "GETTABLE");
        }),
        &[BReject::MissingRow {
            op: 6,
            name: "GETTABLE",
        }],
    );

    // Killer: a duplicated row that also changes the role.
    assert_killed(
        "MOVE duplicated as a scalar",
        &rows_with(|rows| rows.push(row(0, "MOVE", BRole::ScalarOrUnused))),
        &[
            BReject::DuplicateRow {
                op: 0,
                name: "MOVE",
            },
            BReject::RoleChanged {
                op: 0,
                name: "MOVE",
                claimed: BRole::ScalarOrUnused,
                official: BRole::FixedRegister,
            },
        ],
    );

    // Killer: a renamed row.
    assert_killed(
        "GETUPVAL row renamed",
        &rows_with(|rows| rows[4].name = "GETUPVALUE"),
        &[BReject::NameChanged {
            op: 4,
            claimed: "GETUPVALUE",
            official: "GETUPVAL",
        }],
    );

    // Killer: a register demoted to a scalar.
    assert_killed(
        "CONCAT.B demoted to a scalar",
        &rows_with(|rows| rows[21].role = BRole::ScalarOrUnused),
        &[BReject::RoleChanged {
            op: 21,
            name: "CONCAT",
            claimed: BRole::ScalarOrUnused,
            official: BRole::FixedRegister,
        }],
    );

    // Killer: a non-register promoted to a fixed register.
    assert_killed(
        "NEWTABLE.B array-size hint marked as a fixed register",
        &rows_with(|rows| rows[OP_NEWTABLE as usize].role = BRole::FixedRegister),
        &[BReject::NonRegisterMarkedFixed {
            op: OP_NEWTABLE,
            name: "NEWTABLE",
            official: BRole::ScalarOrUnused,
        }],
    );
}
