//! Independent public acceptance for the Lua 5.1 register-`A` authority.
//!
//! The chunk reader and instruction encoder below are test-local transcriptions of the
//! PUC-Rio Lua 5.1.5 chunk and opcode layouts. They deliberately do not call luad's
//! Lua 5.1 opcode, disassembly, or validation helpers.

use std::path::PathBuf;
use std::process::{Command, Output};

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::envelope::{MachineDocument, ValidationResponse};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

/// The pinned sprint fixture matrix: every entry is a clean Lua 5.1 chunk.
const FIXTURES: [(&str, &str); 3] = [
    (
        "tests/fixtures/precompiled/lua51/hello.luac",
        "d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f",
    ),
    (
        "tests/fixtures/precompiled/lua51/control_flow.luac",
        "d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40",
    ),
    (
        "tests/fixtures/precompiled/lua51/closures.luac",
        "62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e",
    ),
];

/// Base fixture the derived out-of-range case is built from.
const HELLO: (&str, &str) = FIXTURES[0];

/// Official sources the independent `A`-role reading is transcribed from.
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

/// `OP_CLOSE` position in the official Lua 5.1.5 opcode enumeration; `A` is the first
/// register of the closed stack span, so it is a direct register operand.
const OP_CLOSE: u8 = 35;
const REG_A_CODE: &str = "L51-REG-001";

/// Facts read from the base chunk by the test-local reader.
struct RootProto {
    path: String,
    maxstacksize: u8,
    pc: usize,
    byte_offset: usize,
    word: u32,
}

/// Reads the root prototype prologue and its first instruction word. Only the fields the
/// derived case needs are decoded; the tail of the chunk is not interpreted.
fn read_root_proto(bytes: &[u8]) -> RootProto {
    assert_eq!(&bytes[0..4], b"\x1bLua", "PUC chunk signature");
    assert_eq!(bytes[4], 0x51, "Lua 5.1 version byte");
    assert_eq!(bytes[6], 1, "little-endian fixture");
    assert_eq!(bytes[9], 4, "32-bit instruction words");
    let sizeof_int = bytes[7] as usize;
    let sizeof_sizet = bytes[8] as usize;

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

fn field_a(word: u32) -> u8 {
    ((word >> 6) & 0xff) as u8
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
    luad_oracle::luad_binary_path()
}

fn run_validate(path: &std::path::Path) -> Output {
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

#[test]
fn test_close_register_a_at_maxstacksize_has_exact_register_diagnostic() {
    for (name, hash) in AUTHORITY_HASHES {
        assert_eq!(hash.len(), 64, "authority hash is pinned: {name}");
    }

    let mut bytes = std::fs::read(root().join(HELLO.0)).expect("pinned base fixture");
    let base_hash = sha256(&bytes);
    assert_eq!(base_hash, HELLO.1, "base fixture hash: {}", HELLO.0);

    let proto = read_root_proto(&bytes);
    let observed_a = u16::from(proto.maxstacksize);
    let changed_word = iabc(OP_CLOSE, proto.maxstacksize, 0, 0);
    assert_eq!(opcode(changed_word), OP_CLOSE);
    assert_eq!(u16::from(field_a(changed_word)), observed_a);
    assert_ne!(
        proto.word, changed_word,
        "derived case changes the pinned word"
    );

    let range = proto.byte_offset..proto.byte_offset + 4;
    bytes[range].copy_from_slice(&changed_word.to_le_bytes());
    let derived_hash = sha256(&bytes);

    // Derived-case provenance: base hash, prototype path, PC, original word, changed A,
    // changed word, result hash.
    let provenance = format!(
        "base={base_hash} proto={} pc={} original_word={:#010x} changed_a={observed_a} \
         changed_word={changed_word:#010x} result={derived_hash}",
        proto.path, proto.pc, proto.word
    );
    assert_ne!(
        base_hash, derived_hash,
        "derived chunk differs: {provenance}"
    );

    let file = NamedTempFile::new().expect("temporary chunk");
    std::fs::write(file.path(), &bytes).expect("write derived chunk");
    let output = run_validate(file.path());

    assert!(
        output.stderr.is_empty(),
        "machine stderr must be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "out-of-range register A must fail validation: {provenance}"
    );

    let doc: MachineDocument<ValidationResponse> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| {
            panic!(
                "validate stdout is not JSON: {error}\nstdout={}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(doc.data.verdict, Verdict::Invalid, "{provenance}");

    let register_diagnostics: Vec<_> = doc
        .data
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == REG_A_CODE)
        .collect();
    assert_eq!(
        register_diagnostics.len(),
        1,
        "expected exactly one {REG_A_CODE} for CLOSE A={observed_a} \
         (maxstacksize {}): {provenance}\ndiagnostics={:?}",
        proto.maxstacksize,
        doc.data.diagnostics
    );

    let diagnostic = register_diagnostics[0];
    let source = diagnostic.source.as_ref().expect("diagnostic source word");
    let observed = (
        diagnostic.code.as_str(),
        diagnostic.severity,
        diagnostic.category,
        diagnostic.target.to_string(),
        diagnostic.message.as_str(),
        source.byte_offset,
        source.byte_length,
        source.raw_hex.as_str(),
    );
    let expected_message = format!(
        "Register A ({observed_a}) exceeds maxstacksize ({}) at PC {}",
        proto.maxstacksize, proto.pc
    );
    let expected_raw_hex = hex::encode(changed_word.to_le_bytes());
    let expected = (
        REG_A_CODE,
        Severity::Error,
        DiagnosticCategory::Instruction,
        format!("proto:{}:pc:{}", proto.path, proto.pc),
        expected_message.as_str(),
        proto.byte_offset,
        4_usize,
        expected_raw_hex.as_str(),
    );
    assert_eq!(observed, expected, "{provenance}");
}

// ---------------------------------------------------------------------------
// Independent Lua 5.1 opcode / `A`-role authority table.
// ---------------------------------------------------------------------------

/// Instruction word layout of an opcode in the official Lua 5.1.5 encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fmt {
    Abc,
    Abx,
    Asbx,
}

/// One row of the independent transcription of `luaP_opmodes` / `lvm.c` `A` usage.
#[derive(Debug, Clone, Copy)]
struct OpRow {
    code: u8,
    mnemonic: &'static str,
    fmt: Fmt,
    /// `true` when `A` names a stack slot `R(A)` and is therefore bounded by
    /// `maxstacksize`; `false` when `A` is an unused field or a plain flag.
    a_is_register: bool,
    a_role: &'static str,
}

const fn row(
    code: u8,
    mnemonic: &'static str,
    fmt: Fmt,
    a_is_register: bool,
    a_role: &'static str,
) -> OpRow {
    OpRow {
        code,
        mnemonic,
        fmt,
        a_is_register,
        a_role,
    }
}

/// The complete Lua 5.1.5 opcode enumeration (`OP_MOVE`..`OP_VARARG`), with the role
/// of field `A` read from the reference VM. Exactly four opcodes do not use `A` as a
/// register: `JMP` ignores it, and `EQ`/`LT`/`LE` compare their result against it.
const A_ROLES: [OpRow; 38] = [
    row(0, "MOVE", Fmt::Abc, true, "R(A) := R(B)"),
    row(1, "LOADK", Fmt::Abx, true, "R(A) := Kst(Bx)"),
    row(2, "LOADBOOL", Fmt::Abc, true, "R(A) := (Bool)B"),
    row(3, "LOADNIL", Fmt::Abc, true, "R(A)..R(B) := nil"),
    row(4, "GETUPVAL", Fmt::Abc, true, "R(A) := UpValue[B]"),
    row(5, "GETGLOBAL", Fmt::Abx, true, "R(A) := Gbl[Kst(Bx)]"),
    row(6, "GETTABLE", Fmt::Abc, true, "R(A) := R(B)[RK(C)]"),
    row(7, "SETGLOBAL", Fmt::Abx, true, "Gbl[Kst(Bx)] := R(A)"),
    row(8, "SETUPVAL", Fmt::Abc, true, "UpValue[B] := R(A)"),
    row(9, "SETTABLE", Fmt::Abc, true, "R(A)[RK(B)] := RK(C)"),
    row(10, "NEWTABLE", Fmt::Abc, true, "R(A) := {}"),
    row(
        11,
        "SELF",
        Fmt::Abc,
        true,
        "R(A+1) := R(B); R(A) := R(B)[RK(C)]",
    ),
    row(12, "ADD", Fmt::Abc, true, "R(A) := RK(B) + RK(C)"),
    row(13, "SUB", Fmt::Abc, true, "R(A) := RK(B) - RK(C)"),
    row(14, "MUL", Fmt::Abc, true, "R(A) := RK(B) * RK(C)"),
    row(15, "DIV", Fmt::Abc, true, "R(A) := RK(B) / RK(C)"),
    row(16, "MOD", Fmt::Abc, true, "R(A) := RK(B) % RK(C)"),
    row(17, "POW", Fmt::Abc, true, "R(A) := RK(B) ^ RK(C)"),
    row(18, "UNM", Fmt::Abc, true, "R(A) := -R(B)"),
    row(19, "NOT", Fmt::Abc, true, "R(A) := not R(B)"),
    row(20, "LEN", Fmt::Abc, true, "R(A) := length of R(B)"),
    row(21, "CONCAT", Fmt::Abc, true, "R(A) := R(B).. .. ..R(C)"),
    row(22, "JMP", Fmt::Asbx, false, "unused in 5.1; pc += sBx"),
    row(
        23,
        "EQ",
        Fmt::Abc,
        false,
        "boolean test flag: if ((RK(B)==RK(C)) ~= A)",
    ),
    row(
        24,
        "LT",
        Fmt::Abc,
        false,
        "boolean test flag: if ((RK(B)< RK(C)) ~= A)",
    ),
    row(
        25,
        "LE",
        Fmt::Abc,
        false,
        "boolean test flag: if ((RK(B)<=RK(C)) ~= A)",
    ),
    row(26, "TEST", Fmt::Abc, true, "if not (R(A) <=> C) then pc++"),
    row(
        27,
        "TESTSET",
        Fmt::Abc,
        true,
        "if (R(B) <=> C) then R(A) := R(B)",
    ),
    row(28, "CALL", Fmt::Abc, true, "R(A), ... := R(A)(R(A+1), ...)"),
    row(29, "TAILCALL", Fmt::Abc, true, "return R(A)(R(A+1), ...)"),
    row(30, "RETURN", Fmt::Abc, true, "return R(A), ... ,R(A+B-2)"),
    row(
        31,
        "FORLOOP",
        Fmt::Asbx,
        true,
        "R(A) += R(A+2); R(A+3) := R(A)",
    ),
    row(32, "FORPREP", Fmt::Asbx, true, "R(A) -= R(A+2); pc += sBx"),
    row(
        33,
        "TFORLOOP",
        Fmt::Abc,
        true,
        "R(A+3), ... := R(A)(R(A+1), R(A+2))",
    ),
    row(34, "SETLIST", Fmt::Abc, true, "R(A)[(C-1)*FPF+i] := R(A+i)"),
    row(35, "CLOSE", Fmt::Abc, true, "close upvalues >= R(A)"),
    row(36, "CLOSURE", Fmt::Abx, true, "R(A) := closure(KPROTO[Bx])"),
    row(37, "VARARG", Fmt::Abc, true, "R(A), R(A+1), ... := vararg"),
];

/// Opcodes whose `A` field is not a register, as read from the reference VM.
const NON_REGISTER_A: [&str; 4] = ["JMP", "EQ", "LT", "LE"];
const ABX_OPCODES: [&str; 4] = ["LOADK", "GETGLOBAL", "SETGLOBAL", "CLOSURE"];
const ASBX_OPCODES: [&str; 3] = ["JMP", "FORLOOP", "FORPREP"];

/// Returns the first way `rows` departs from the pinned authority reading, if any.
/// The killer-mutation test asserts that every seeded defect is reported here.
fn table_defect(rows: &[OpRow]) -> Option<String> {
    if rows.len() != 38 {
        return Some(format!("expected 38 opcodes, found {}", rows.len()));
    }
    for (index, row) in rows.iter().enumerate() {
        if usize::from(row.code) != index {
            return Some(format!("row {index} has code {}", row.code));
        }
        if row.mnemonic.is_empty() || row.a_role.is_empty() {
            return Some(format!("row {index} has an empty descriptor"));
        }
        if rows
            .iter()
            .filter(|other| other.mnemonic == row.mnemonic)
            .count()
            != 1
        {
            return Some(format!("mnemonic {} is not unique", row.mnemonic));
        }
    }
    let mut plain: Vec<&str> = rows
        .iter()
        .filter(|row| !row.a_is_register)
        .map(|row| row.mnemonic)
        .collect();
    plain.sort_unstable();
    let mut expected_plain = NON_REGISTER_A.to_vec();
    expected_plain.sort_unstable();
    if plain != expected_plain {
        return Some(format!("non-register A set is {plain:?}"));
    }
    for (fmt, expected) in [(Fmt::Abx, &ABX_OPCODES[..]), (Fmt::Asbx, &ASBX_OPCODES[..])] {
        let mut seen: Vec<&str> = rows
            .iter()
            .filter(|row| row.fmt == fmt)
            .map(|row| row.mnemonic)
            .collect();
        seen.sort_unstable();
        let mut want = expected.to_vec();
        want.sort_unstable();
        if seen != want {
            return Some(format!("{fmt:?} set is {seen:?}"));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Test-local encoders and chunk writer.
// ---------------------------------------------------------------------------

fn iabx(op: u8, a: u8, bx: u32) -> u32 {
    u32::from(op) | (u32::from(a) << 6) | (bx << 14)
}

fn iasbx(op: u8, a: u8, sbx: i32) -> u32 {
    // MAXARG_sBx = (2^18 - 1) / 2 in Lua 5.1.
    iabx(op, a, (sbx + 131_071) as u32)
}

/// Encodes `row` with the given `A` and inert operands that keep each probe
/// structurally independent of the following word.
fn probe(row: &OpRow, a: u8) -> u32 {
    match row.fmt {
        // SETLIST with C == 0 consumes the following physical word as data.
        // C == 1 keeps the opcode-matrix fixture a sequence of instructions.
        Fmt::Abc if row.code == 34 => iabc(row.code, a, 0, 1),
        Fmt::Abc => iabc(row.code, a, 0, 0),
        Fmt::Abx => iabx(row.code, a, 0),
        Fmt::Asbx => iasbx(row.code, a, 0),
    }
}

const PROBE_SOURCE: &str = "@register_a_probe.lua";
/// `RETURN 0 1`: the terminator appended to every synthesized code array. `A` is 0, so
/// it is in range for every `maxstacksize` used here and never contributes a finding.
const RETURN_0_1: u32 = 30 | (1 << 23);

/// A prototype to synthesize; `code` is written verbatim ahead of the terminator.
/// `nups` is the declared upvalue count, which sets how many binding descriptors follow
/// a `CLOSURE` that instantiates this prototype.
#[derive(Debug, Clone)]
struct ProtoSpec {
    nups: u8,
    maxstacksize: u8,
    code: Vec<u32>,
    children: Vec<ProtoSpec>,
}

impl ProtoSpec {
    fn new(maxstacksize: u8, code: Vec<u32>) -> Self {
        Self::with_nups(0, maxstacksize, code)
    }

    fn with_nups(nups: u8, maxstacksize: u8, code: Vec<u32>) -> Self {
        Self {
            nups,
            maxstacksize,
            code,
            children: Vec::new(),
        }
    }
}

fn write_int(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_string(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&((text.len() + 1) as u64).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

fn write_proto(out: &mut Vec<u8>, spec: &ProtoSpec) {
    write_string(out, PROBE_SOURCE);
    write_int(out, 0); // linedefined
    write_int(out, 0); // lastlinedefined
    out.push(spec.nups); // nups
    out.push(0); // numparams
    out.push(2); // is_vararg = VARARG_ISVARARG
    out.push(spec.maxstacksize);
    write_int(out, (spec.code.len() + 1) as u32);
    for word in &spec.code {
        write_int(out, *word);
    }
    write_int(out, RETURN_0_1);
    write_int(out, 0); // constants
    write_int(out, spec.children.len() as u32);
    for child in &spec.children {
        write_proto(out, child);
    }
    write_int(out, 0); // lineinfo
    write_int(out, 0); // locvars
    write_int(out, 0); // upvalues
}

/// Writes a complete little-endian 64-bit Lua 5.1 chunk around `root`.
fn build_chunk(root: &ProtoSpec) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1bLua");
    out.extend_from_slice(&[0x51, 0, 1, 4, 8, 4, 8, 0]);
    write_proto(&mut out, root);
    out
}

/// Byte offset of PC 0 in a synthesized chunk's root prototype, mirroring `write_proto`.
fn root_code_offset() -> usize {
    12 + (8 + PROBE_SOURCE.len() + 1) + 4 + 4 + 4 + 4
}

fn temp_chunk(bytes: &[u8]) -> NamedTempFile {
    let file = NamedTempFile::new().expect("temporary chunk");
    std::fs::write(file.path(), bytes).expect("write synthesized chunk");
    file
}

// ---------------------------------------------------------------------------
// Public-CLI helpers.
// ---------------------------------------------------------------------------

fn run_luad(args: &[&str]) -> Output {
    Command::new(luad_bin())
        .args(args)
        .output()
        .expect("run public luad CLI")
}

/// Runs `luad validate`. `dialect` is `None` for automatic dialect selection, which the
/// CLI expresses by omitting `--dialect` altogether rather than by any sentinel value.
fn run_validate_args(path: &std::path::Path, dialect: Option<&str>, extra: &[&str]) -> Output {
    let mut args = vec!["validate", path.to_str().expect("UTF-8 path")];
    if let Some(dialect) = dialect {
        args.extend_from_slice(&["--dialect", dialect]);
    }
    args.extend_from_slice(&["--format", "json"]);
    args.extend_from_slice(extra);
    run_luad(&args)
}

/// Validates `document` against the live published schema for `command`, as emitted by
/// the public `luad schema <command>` surface.
fn assert_matches_published_schema(command: &str, document: &Value) {
    let output = run_luad(&["schema", command]);
    assert!(
        output.status.success() && output.stderr.is_empty(),
        "luad schema {command} failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let schema: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "luad schema {command} stdout is not JSON: {error}\nstdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    let validator = jsonschema::validator_for(&schema)
        .unwrap_or_else(|error| panic!("published {command} schema does not compile: {error}"));
    let errors: Vec<String> = validator
        .iter_errors(document)
        .map(|error| format!("{}: {error}", error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{command} output violates the published schema: {errors:?}"
    );
}

fn parse_validation(output: &Output) -> MachineDocument<ValidationResponse> {
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

/// Runs the public validator over an in-memory chunk and returns the whole document,
/// after checking the emitted JSON against the published `validate` schema.
fn validate_bytes(
    bytes: &[u8],
    dialect: Option<&str>,
    extra: &[&str],
) -> MachineDocument<ValidationResponse> {
    let file = temp_chunk(bytes);
    let output = run_validate_args(file.path(), dialect, extra);
    let raw: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "validate stdout is not JSON: {error}\nstdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_matches_published_schema("validate", &raw);
    parse_validation(&output)
}

/// Findings are filtered to `L51-REG-001`: synthesized probe chunks intentionally carry
/// other defects (dangling RK operands, unreachable code) that this sprint does not own.
fn reg_a_findings(doc: &MachineDocument<ValidationResponse>) -> Vec<&Diagnostic> {
    doc.data
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == REG_A_CODE)
        .collect()
}

/// Splits `proto:<path>:pc:<pc>` into its prototype path and PC.
fn split_target(diagnostic: &Diagnostic) -> (String, usize) {
    let target = diagnostic.target.to_string();
    let (proto, pc) = target
        .rsplit_once(":pc:")
        .unwrap_or_else(|| panic!("unexpected diagnostic target: {target}"));
    (
        proto.to_string(),
        pc.parse()
            .unwrap_or_else(|_| panic!("unexpected PC in target: {target}")),
    )
}

fn reg_a_pcs(doc: &MachineDocument<ValidationResponse>) -> Vec<usize> {
    let mut pcs: Vec<usize> = reg_a_findings(doc)
        .iter()
        .map(|diagnostic| split_target(diagnostic).1)
        .collect();
    pcs.sort_unstable();
    pcs
}

// ---------------------------------------------------------------------------
// Acceptance.
// ---------------------------------------------------------------------------

#[test]
fn test_lua51_a_role_table_is_exact_and_rejects_killer_mutations() {
    assert_eq!(table_defect(&A_ROLES), None, "pinned table must be clean");
    assert_eq!(
        A_ROLES.iter().filter(|row| row.a_is_register).count(),
        34,
        "34 of 38 Lua 5.1 opcodes use A as a register"
    );

    let mut mutants: Vec<(&str, Vec<OpRow>)> = Vec::new();

    let mut truncated = A_ROLES.to_vec();
    truncated.pop();
    mutants.push(("dropped OP_VARARG", truncated));

    let mut swapped = A_ROLES.to_vec();
    swapped.swap(35, 36);
    mutants.push(("swapped CLOSE and CLOSURE", swapped));

    let mut close_demoted = A_ROLES.to_vec();
    close_demoted[35].a_is_register = false;
    mutants.push(("CLOSE A demoted to a flag", close_demoted));

    let mut jmp_promoted = A_ROLES.to_vec();
    jmp_promoted[22].a_is_register = true;
    mutants.push(("JMP A promoted to a register", jmp_promoted));

    let mut eq_promoted = A_ROLES.to_vec();
    eq_promoted[23].a_is_register = true;
    mutants.push(("EQ A promoted to a register", eq_promoted));

    let mut duplicated = A_ROLES.to_vec();
    duplicated[13].mnemonic = "ADD";
    mutants.push(("duplicated ADD mnemonic", duplicated));

    let mut reformatted = A_ROLES.to_vec();
    reformatted[1].fmt = Fmt::Abc;
    mutants.push(("LOADK re-encoded as iABC", reformatted));

    let mut blanked = A_ROLES.to_vec();
    blanked[0].a_role = "";
    mutants.push(("blanked MOVE descriptor", blanked));

    for (name, rows) in &mutants {
        assert!(
            table_defect(rows).is_some(),
            "killer mutation survived: {name}"
        );
    }
}

#[test]
fn test_public_disasm_types_register_a_against_the_authority_table() {
    // One in-range probe per opcode in a single prototype: PC i decodes row i.
    let words: Vec<u32> = A_ROLES.iter().map(|row| probe(row, 1)).collect();
    let bytes = build_chunk(&ProtoSpec::new(4, words));
    let file = temp_chunk(&bytes);
    let output = run_luad(&[
        "disasm",
        file.path().to_str().expect("UTF-8 path"),
        "--dialect",
        "lua5.1",
        "--format",
        "json",
    ]);
    assert!(
        output.stderr.is_empty(),
        "machine stderr must be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "disasm stdout is not JSON: {error}\nstdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_matches_published_schema("disasm", &document);

    // Located structurally so the assertion does not depend on envelope field names.
    fn collect(value: &Value, out: &mut Vec<Value>) {
        match value {
            Value::Object(map) => {
                if map.contains_key("opcode_num") && map.contains_key("encoded_operands") {
                    out.push(value.clone());
                }
                for nested in map.values() {
                    collect(nested, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| collect(item, out)),
            _ => {}
        }
    }
    let mut instructions = Vec::new();
    collect(&document, &mut instructions);
    instructions.sort_by_key(|instruction| instruction["pc"].as_u64().unwrap_or_default());
    assert_eq!(
        instructions.len(),
        A_ROLES.len() + 1,
        "one row per probe plus the RETURN terminator"
    );

    for (index, row) in A_ROLES.iter().enumerate() {
        let instruction = &instructions[index];
        let descriptor = (
            instruction["pc"].as_u64(),
            instruction["opcode_num"].as_u64(),
            instruction["mnemonic"].as_str(),
            instruction["encoded_operands"]["a"].as_u64(),
            instruction["raw_word"].as_u64(),
        );
        assert_eq!(
            descriptor,
            (
                Some(index as u64),
                Some(u64::from(row.code)),
                Some(row.mnemonic),
                Some(1),
                Some(u64::from(probe(row, 1)))
            ),
            "descriptor mismatch for {} ({})",
            row.mnemonic,
            row.a_role
        );

        let operand_a = instruction["operands"]
            .as_array()
            .expect("typed operand list")
            .iter()
            .find(|operand| operand["name"].as_str() == Some("A"));
        let typed_as_register = operand_a
            .map(|operand| {
                operand["kind"]["kind"].as_str() == Some("register")
                    && operand["kind"]["index"].as_u64() == Some(1)
            })
            .unwrap_or(false);
        assert_eq!(
            typed_as_register, row.a_is_register,
            "A typing mismatch for {}: {} (operand={operand_a:?})",
            row.mnemonic, row.a_role
        );
    }

    // Closure-binding descriptor words physically encode A but the VM ignores it.
    // Their contextual role must suppress both register typing and validation.
    let maxstacksize = 2_u8;
    let mut descriptor_root = ProtoSpec::new(
        maxstacksize,
        vec![
            iabx(36, 0, 0),
            iabc(0, maxstacksize, 0, 0),
            iabc(4, maxstacksize, 0, 0),
        ],
    );
    descriptor_root
        .children
        .push(ProtoSpec::with_nups(2, maxstacksize, Vec::new()));
    let descriptor_bytes = build_chunk(&descriptor_root);
    let descriptor_file = temp_chunk(&descriptor_bytes);
    let descriptor_output = run_luad(&[
        "disasm",
        descriptor_file.path().to_str().expect("UTF-8 path"),
        "--dialect",
        "lua5.1",
        "--format",
        "json",
    ]);
    assert!(descriptor_output.stderr.is_empty());
    let descriptor_document: Value =
        serde_json::from_slice(&descriptor_output.stdout).expect("descriptor disassembly JSON");
    assert_matches_published_schema("disasm", &descriptor_document);
    let mut descriptor_instructions = Vec::new();
    collect(&descriptor_document, &mut descriptor_instructions);
    let bindings: Vec<_> = descriptor_instructions
        .iter()
        .filter(|instruction| instruction["role"].as_str() == Some("closure_binding"))
        .collect();
    assert_eq!(
        bindings.len(),
        2,
        "two physical closure-binding descriptors"
    );
    for binding in bindings {
        assert_eq!(
            binding["encoded_operands"]["a"].as_u64(),
            Some(u64::from(maxstacksize))
        );
        let has_register_a = binding["operands"]
            .as_array()
            .expect("binding operands")
            .iter()
            .any(|operand| {
                operand["name"].as_str() == Some("A")
                    && operand["kind"]["kind"].as_str() == Some("register")
            });
        assert!(!has_register_a, "descriptor A is ignored: {binding:?}");
    }
    let descriptor_validation = validate_bytes(&descriptor_bytes, Some("lua5.1"), &[]);
    assert!(
        reg_a_findings(&descriptor_validation).is_empty(),
        "closure-binding descriptor A must not produce {REG_A_CODE}: {:?}",
        descriptor_validation.data.diagnostics
    );
}

#[test]
fn test_every_register_a_opcode_reports_reg_a_and_jmp_comparisons_do_not() {
    // A = maxstacksize is the first out-of-range slot for every register-bearing opcode.
    let maxstacksize = 2_u8;
    let words: Vec<u32> = A_ROLES.iter().map(|row| probe(row, maxstacksize)).collect();
    let doc = validate_bytes(
        &build_chunk(&ProtoSpec::new(maxstacksize, words)),
        Some("lua5.1"),
        &[],
    );
    assert_eq!(doc.data.verdict, Verdict::Invalid);

    let expected: Vec<usize> = A_ROLES
        .iter()
        .enumerate()
        .filter(|(_, row)| row.a_is_register)
        .map(|(index, _)| index)
        .collect();
    let observed = reg_a_pcs(&doc);
    let legend: Vec<(usize, &str, bool)> = A_ROLES
        .iter()
        .enumerate()
        .map(|(index, row)| (index, row.mnemonic, row.a_is_register))
        .collect();
    assert_eq!(
        observed, expected,
        "one {REG_A_CODE} per register-A opcode and none for {NON_REGISTER_A:?}\nlegend={legend:?}"
    );
}

#[test]
fn test_register_a_boundary_is_exact_at_maxstacksize() {
    let maxstacksize = 3_u8;
    let close = A_ROLES[usize::from(OP_CLOSE)];
    assert_eq!(close.mnemonic, "CLOSE");
    // PC 0 is the last legal slot; PCs 1 and 2 are the first illegal slot and the
    // maximum encodable A.
    let cases = [
        (0_usize, maxstacksize - 1, false),
        (1, maxstacksize, true),
        (2, 255, true),
    ];
    let words: Vec<u32> = cases.iter().map(|(_, a, _)| probe(&close, *a)).collect();
    let doc = validate_bytes(
        &build_chunk(&ProtoSpec::new(maxstacksize, words)),
        Some("lua5.1"),
        &[],
    );

    let findings = reg_a_findings(&doc);
    let observed: Vec<_> = findings
        .iter()
        .map(|diagnostic| {
            let source = diagnostic.source.as_ref().expect("diagnostic source word");
            (
                diagnostic.severity,
                diagnostic.category,
                diagnostic.target.to_string(),
                diagnostic.message.clone(),
                source.byte_offset,
                source.byte_length,
                source.raw_hex.clone(),
            )
        })
        .collect();
    let expected: Vec<_> = cases
        .iter()
        .filter(|(_, _, flagged)| *flagged)
        .map(|(pc, a, _)| {
            (
                Severity::Error,
                DiagnosticCategory::Instruction,
                format!("proto:0:pc:{pc}"),
                format!("Register A ({a}) exceeds maxstacksize ({maxstacksize}) at PC {pc}"),
                root_code_offset() + pc * 4,
                4_usize,
                hex::encode(probe(&close, *a).to_le_bytes()),
            )
        })
        .collect();
    assert_eq!(
        observed,
        expected,
        "A = {} must be clean while A >= {maxstacksize} is reported exactly once",
        maxstacksize - 1
    );
}

#[test]
fn test_register_a_authority_reaches_recursive_child_prototypes() {
    let maxstacksize = 2_u8;
    let close = A_ROLES[usize::from(OP_CLOSE)];
    // Each depth carries a distinct number of offending instructions, so the depths can
    // be told apart without pinning the prototype-path spelling.
    let offenders =
        |count: usize| -> Vec<u32> { (0..count).map(|_| probe(&close, maxstacksize)).collect() };
    let mut grandchild = ProtoSpec::new(maxstacksize, offenders(3));
    grandchild.code.insert(0, probe(&close, 0)); // in-range neighbour stays clean
    let mut child = ProtoSpec::new(maxstacksize, offenders(2));
    child.children.push(grandchild);
    let mut root_proto = ProtoSpec::new(maxstacksize, offenders(1));
    root_proto.children.push(child);

    let doc = validate_bytes(&build_chunk(&root_proto), Some("lua5.1"), &[]);
    assert_eq!(doc.data.verdict, Verdict::Invalid);

    let findings = reg_a_findings(&doc);
    let mut per_proto: Vec<(String, usize)> = Vec::new();
    for diagnostic in &findings {
        let (proto, _) = split_target(diagnostic);
        match per_proto.iter_mut().find(|(seen, _)| *seen == proto) {
            Some((_, count)) => *count += 1,
            None => per_proto.push((proto, 1)),
        }
    }
    let mut counts: Vec<usize> = per_proto.iter().map(|(_, count)| *count).collect();
    counts.sort_unstable();
    assert_eq!(
        counts,
        vec![1, 2, 3],
        "each of the three nested prototypes reports its own findings: {per_proto:?}"
    );
}

#[test]
fn test_clean_chunks_report_no_register_a_findings() {
    for (path, expected_hash) in FIXTURES {
        let bytes = std::fs::read(root().join(path)).expect("pinned fixture");
        assert_eq!(sha256(&bytes), expected_hash, "fixture hash: {path}");
        let pinned = validate_bytes(&bytes, Some("lua5.1"), &[]);
        assert_eq!(
            pinned.data.verdict,
            Verdict::ValidForParser,
            "pinned fixture is valid: {path}"
        );
        assert!(
            reg_a_findings(&pinned).is_empty(),
            "pinned fixture must be free of {REG_A_CODE}: {path}: {:?}",
            pinned.data.diagnostics
        );
    }

    // Every opcode at the highest in-range slot is also clean.
    let maxstacksize = 4_u8;
    let words: Vec<u32> = A_ROLES
        .iter()
        .map(|row| probe(row, maxstacksize - 1))
        .collect();
    let synthesized = validate_bytes(
        &build_chunk(&ProtoSpec::new(maxstacksize, words)),
        Some("lua5.1"),
        &[],
    );
    assert!(
        reg_a_findings(&synthesized).is_empty(),
        "A = maxstacksize - 1 is in range for every opcode: {:?}",
        synthesized.data.diagnostics
    );
}

#[test]
fn test_register_a_findings_are_mode_invariant_and_schema_valid() {
    let maxstacksize = 2_u8;
    let words: Vec<u32> = A_ROLES.iter().map(|row| probe(row, maxstacksize)).collect();
    let bytes = build_chunk(&ProtoSpec::new(maxstacksize, words));
    let file = temp_chunk(&bytes);

    let modes: [(Option<&str>, &[&str]); 4] = [
        (Some("lua5.1"), &[]),
        (None, &[]),
        (Some("lua5.1"), &["--strict"]),
        (None, &["--strict"]),
    ];
    let mut baseline: Option<Vec<(String, String)>> = None;
    for (dialect, extra) in modes {
        let output = run_validate_args(file.path(), dialect, extra);
        let doc = parse_validation(&output);

        // Live schema check: the published typed envelope round-trips the emitted
        // document byte-for-byte, so no field is undeclared, dropped, or retyped.
        let raw: Value = serde_json::from_slice(&output.stdout).expect("machine JSON");
        assert_matches_published_schema("validate", &raw);
        let typed = serde_json::to_value(&doc).expect("re-serialize typed document");
        assert_eq!(
            typed, raw,
            "document does not round-trip through the published schema \
             (dialect={dialect:?} extra={extra:?})"
        );

        let observed: Vec<(String, String)> = reg_a_findings(&doc)
            .iter()
            .map(|diagnostic| (diagnostic.target.to_string(), diagnostic.message.clone()))
            .collect();
        assert_eq!(
            observed.len(),
            A_ROLES.iter().filter(|row| row.a_is_register).count(),
            "dialect={dialect:?} extra={extra:?}"
        );
        match &baseline {
            None => baseline = Some(observed),
            Some(expected) => assert_eq!(
                &observed, expected,
                "{REG_A_CODE} must not depend on dialect selection or strictness \
                 (dialect={dialect:?} extra={extra:?})"
            ),
        }
    }
}
