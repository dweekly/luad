//! Independent public acceptance for the Lua 5.1 fixed-role register-`C` authority.
//!
//! This module holds acceptance slice A of the sprint, four dimensions:
//!
//! - no physical `C` field that the authority declines to class as a fixed direct
//!   register carries `L51-REG-003`, however large its nine-bit value is;
//! - the authority table itself is exact, proved by a pure comparator that rejects the
//!   killer mutations of that authority;
//! - the `CONCAT.C` register bound is exact at `maxstacksize`, with a frozen diagnostic
//!   identity;
//! - bit 8 of `CONCAT.C` is a register overflow, never an `RK` constant.
//!
//! Public typing of `C` operands, mode invariance across selections, recursive
//! prototypes, and the all-fixture sweep are slice B and are deliberately absent.
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

    /// Why this role is outside the fixed-role register claim. `ConditionalRk` is stated
    /// carefully: a `K`-clear `RK` slot *is* dereferenced as a register by the VM, but its
    /// meaning depends on bit 8, so `RK` authority owns it and this sprint does not.
    fn why_not_fixed(self) -> &'static str {
        match self {
            CRole::FixedRegister => "is the fixed direct register C",
            CRole::ConditionalRk => {
                "is an RK slot whose meaning depends on bit 8, so it lies outside the \
                 fixed-role register claim in either encoding"
            }
            CRole::Boolean => "is a control flag the VM compares, never an index",
            CRole::Count => "encodes a result or variable count, never an index",
            CRole::SizeHint => "is an encoded table size hint, never an index",
            CRole::ListBlockIndex => "is a list block index into the table being filled",
            CRole::Unused => "is never read by this opcode's VM arm",
            CRole::NoCField => "is not a physical C field at all",
        }
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

// ---------------------------------------------------------------------------
// The pure comparator over a claimed authority
// ---------------------------------------------------------------------------

/// A typed reason the comparator refuses a claimed register-`C` authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CReject {
    /// The claimed table does not state every official opcode exactly once.
    WrongRowCount { claimed: usize },
    /// A row names an opcode outside the official enumeration.
    UnknownOpcode { op: u8 },
    /// A row does not sit at its official opcode number.
    OutOfOrderRow { op: u8, index: usize },
    /// An official opcode has more than one row.
    DuplicateRow { op: u8, name: &'static str },
    /// An official opcode has no row.
    MissingRow { op: u8, name: &'static str },
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
        claimed: CRole,
        official: CRole,
    },
    /// A row claims `FixedRegister` for a `C` field that is not one.
    NonRegisterMarkedFixed {
        op: u8,
        name: &'static str,
        official: CRole,
    },
    /// A row's role disagrees with the category statement of the same authority.
    CategoryMismatch {
        name: &'static str,
        claimed: CRole,
        category: CRole,
    },
    /// A row is named by no category at all.
    Uncategorised { name: &'static str },
}

/// The expectation side: the frozen row statement. Never mutated.
fn official_row(op: u8) -> Option<&'static CRow> {
    OFFICIAL_C_ROLES.iter().find(|entry| entry.op == op)
}

/// The expectation side: the frozen category statement. Never mutated.
fn category_of(name: &str) -> Option<CRole> {
    CATEGORIES
        .iter()
        .find(|(_, names)| names.contains(&name))
        .map(|(role, _)| *role)
}

/// The comparator. Pure: it reads a claimed table and reports every way that table
/// disagrees with the frozen expectation, panicking at nothing and mutating nothing. The
/// positive case and every killer mutation are judged by this one function.
fn audit(rows: &[CRow]) -> Vec<CReject> {
    let mut rejects = Vec::new();
    if rows.len() != OPCODE_COUNT {
        rejects.push(CReject::WrongRowCount {
            claimed: rows.len(),
        });
    }

    let mut seen = [0_u8; OPCODE_COUNT];
    for (index, claimed) in rows.iter().enumerate() {
        let Some(official) = official_row(claimed.op) else {
            rejects.push(CReject::UnknownOpcode { op: claimed.op });
            continue;
        };
        if usize::from(claimed.op) != index {
            rejects.push(CReject::OutOfOrderRow {
                op: claimed.op,
                index,
            });
        }
        seen[usize::from(official.op)] += 1;
        if seen[usize::from(official.op)] > 1 {
            rejects.push(CReject::DuplicateRow {
                op: official.op,
                name: official.name,
            });
        }
        if claimed.name != official.name {
            rejects.push(CReject::NameChanged {
                op: official.op,
                claimed: claimed.name,
                official: official.name,
            });
        }
        if claimed.role != official.role {
            rejects.push(if claimed.role.checked_as_register() {
                CReject::NonRegisterMarkedFixed {
                    op: official.op,
                    name: official.name,
                    official: official.role,
                }
            } else {
                CReject::RoleChanged {
                    op: official.op,
                    name: official.name,
                    claimed: claimed.role,
                    official: official.role,
                }
            });
        }
        match category_of(claimed.name) {
            None => rejects.push(CReject::Uncategorised { name: claimed.name }),
            Some(category) if category != claimed.role => {
                rejects.push(CReject::CategoryMismatch {
                    name: claimed.name,
                    claimed: claimed.role,
                    category,
                });
            }
            Some(_) => {}
        }
    }

    for official in OFFICIAL_C_ROLES.iter() {
        if seen[usize::from(official.op)] == 0 {
            rejects.push(CReject::MissingRow {
                op: official.op,
                name: official.name,
            });
        }
    }

    rejects
}

/// The opcodes a claimed table declares to be fixed direct registers.
fn fixed_register_names(rows: &[CRow]) -> Vec<&'static str> {
    rows.iter()
        .filter(|entry| entry.role.checked_as_register())
        .map(|entry| entry.name)
        .collect()
}

/// Proves the authority is exact before any of it is used as evidence: it audits clean
/// against its own frozen statements, its categories partition the enumeration exactly
/// once, and `CONCAT` is the only fixed direct register `C`.
fn audit_authority() {
    let rejects = audit(&OFFICIAL_C_ROLES);
    assert!(
        rejects.is_empty(),
        "the authority must audit clean against its own frozen statements: {rejects:?}"
    );

    let mut named: Vec<&str> = CATEGORIES
        .iter()
        .flat_map(|(_, names)| names.iter().copied())
        .collect();
    let stated = named.len();
    named.sort_unstable();
    named.dedup();
    assert_eq!(
        (stated, named.len()),
        (OPCODE_COUNT, OPCODE_COUNT),
        "the categories must partition all {OPCODE_COUNT} opcodes exactly once"
    );

    assert_eq!(
        fixed_register_names(&OFFICIAL_C_ROLES),
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

/// Every row this sweep drives: each `iABC` opcode whose `C` the authority does not class
/// as a fixed direct register. That is all twelve `ConditionalRk` rows plus every boolean,
/// count, size hint, list block index and unused field.
///
/// `NoCField` rows are excluded on purpose: bits 14..=22 of an `iABx` or `iAsBx` word are
/// part of `Bx` or `sBx`, so there is no physical `C` there to mutate and no in-frame
/// baseline of "the same word with a smaller `C`" to compare against.
fn driven_rows() -> Vec<&'static CRow> {
    OFFICIAL_C_ROLES
        .iter()
        .filter(|entry| !matches!(entry.role, CRole::FixedRegister | CRole::NoCField))
        .collect()
}

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

    // The sweep is the authority's own non-fixed `iABC` rows, so it cannot silently shrink
    // to a hand-picked few, and it cannot grow to include a row the authority calls a
    // fixed register.
    let driven = driven_rows();
    assert_eq!(
        driven.len(),
        OPCODE_COUNT - 1 - 7,
        "every iABC row except CONCAT is driven; only the 7 NoCField rows are excluded: \
         driven={:?}",
        driven.iter().map(|entry| entry.name).collect::<Vec<_>>()
    );
    for role in [
        CRole::ConditionalRk,
        CRole::Boolean,
        CRole::Count,
        CRole::SizeHint,
        CRole::ListBlockIndex,
        CRole::Unused,
    ] {
        assert!(
            driven.iter().any(|entry| entry.role == role),
            "the sweep must drive at least one {role:?} row"
        );
    }

    // The cases. Each is one word differing from its own in-frame baseline in nothing but
    // the nine physical `C` bits.
    let mut false_positives: Vec<String> = Vec::new();
    for entry in driven.iter() {
        let (op, name, expected_role) = (entry.op, entry.name, entry.role);
        assert!(
            !expected_role.checked_as_register(),
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
                    "{name}.C {}, so the fixed-role authority does not class it as a direct \
                     register, yet C={HIGH_C} produced {} {REG_C_CODE} finding(s) under \
                     {mode:?}\n  {}\n  findings={:?}\n  all codes in document={:?}",
                    expected_role.why_not_fixed(),
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
        "a physical C field that the fixed-role authority does not class as a direct \
         register must not produce {REG_C_CODE} at any nine-bit value, whether the VM \
         ignores it, reads it as a scalar, or resolves it through RK; {} case/mode \
         combination(s) of {} did:\n\n{}",
        false_positives.len(),
        driven.len() * MODES.len(),
        false_positives.join("\n\n")
    );
}

// ---------------------------------------------------------------------------
// The authority, judged by the comparator
// ---------------------------------------------------------------------------

/// The opcodes whose *`B`* field the Lua 5.1.5 VM dereferences as a fixed register. Stated
/// here only so that a `C` authority produced by reusing the `B` classifier can be
/// rejected by name; nothing else in this module reads it.
const B_FIXED_REGISTER: [&str; 9] = [
    "MOVE", "LOADNIL", "GETTABLE", "SELF", "UNM", "NOT", "LEN", "CONCAT", "TESTSET",
];

/// Every killer mutation edits a fresh clone of the authority. The expectation the
/// comparator reads - the `OFFICIAL_C_ROLES` and `CATEGORIES` consts - is never touched,
/// so no mutation can move the expected and the observed statement together.
fn rows_with(edit: impl FnOnce(&mut Vec<CRow>)) -> Vec<CRow> {
    let mut rows = OFFICIAL_C_ROLES.to_vec();
    edit(&mut rows);
    rows
}

/// Judges one killer with the same comparator that judged the clean table.
fn assert_killed(label: &str, rows: &[CRow], expected: &[CReject]) {
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
fn test_lua51_c_role_table_is_exact_and_rejects_killer_mutations() {
    // Positive case: the authority audits clean, so every rejection below is caused by the
    // mutation and not by a comparator that refuses everything.
    let clean = audit(&OFFICIAL_C_ROLES);
    assert!(
        clean.is_empty(),
        "the official table must audit clean: {clean:?}"
    );
    audit_authority();

    // Killer: the one fixed-register row is dropped, which is how an authority silently
    // stops claiming anything at all.
    assert_killed(
        "CONCAT row omitted",
        &rows_with(|rows| rows.retain(|entry| entry.name != "CONCAT")),
        &[
            CReject::MissingRow {
                op: 21,
                name: "CONCAT",
            },
            CReject::WrongRowCount { claimed: 37 },
        ],
    );

    // Killer: a false fixed register, one row at a time. These are the three most
    // plausible: `MOVE.C` is unread, `GETTABLE.C` is an RK slot, `NEWTABLE.C` is a hint.
    for (op, name, official) in [
        (0_u8, "MOVE", CRole::Unused),
        (6, "GETTABLE", CRole::ConditionalRk),
        (10, "NEWTABLE", CRole::SizeHint),
    ] {
        assert_killed(
            &format!("{name}.C falsely marked as a fixed register"),
            &rows_with(|rows| rows[usize::from(op)].role = CRole::FixedRegister),
            &[CReject::NonRegisterMarkedFixed { op, name, official }],
        );
    }

    // Killer: the register-`B` authority transplanted wholesale onto `C`. `CONCAT` is a
    // fixed register in both fields, so a suite that reused the `B` classifier would still
    // pass a CONCAT-only check; the eight other `B` registers are what give it away.
    let b_substituted = rows_with(|rows| {
        for entry in rows.iter_mut() {
            entry.role = if B_FIXED_REGISTER.contains(&entry.name) {
                CRole::FixedRegister
            } else if entry.role.checked_as_register() {
                CRole::Unused
            } else {
                entry.role
            };
        }
    });
    assert_eq!(
        fixed_register_names(&b_substituted).len(),
        B_FIXED_REGISTER.len(),
        "the transplant really did install the B authority's nine fixed registers"
    );
    let transplanted: Vec<CReject> = [
        (0_u8, "MOVE", CRole::Unused),
        (3, "LOADNIL", CRole::Unused),
        (6, "GETTABLE", CRole::ConditionalRk),
        (11, "SELF", CRole::ConditionalRk),
        (18, "UNM", CRole::Unused),
        (19, "NOT", CRole::Unused),
        (20, "LEN", CRole::Unused),
        (27, "TESTSET", CRole::Boolean),
    ]
    .into_iter()
    .map(|(op, name, official)| CReject::NonRegisterMarkedFixed { op, name, official })
    .collect();
    assert_killed(
        "the register-B authority substituted for the register-C authority",
        &b_substituted,
        &transplanted,
    );

    // Killer: a duplicated row.
    assert_killed(
        "MOVE stated twice",
        &rows_with(|rows| rows.push(row(0, "MOVE", CRole::Unused))),
        &[CReject::DuplicateRow {
            op: 0,
            name: "MOVE",
        }],
    );

    // Killer: a missing row that is not the fixed-register one.
    assert_killed(
        "VARARG row missing",
        &rows_with(|rows| rows.retain(|entry| entry.name != "VARARG")),
        &[CReject::MissingRow {
            op: 37,
            name: "VARARG",
        }],
    );

    // Killer: a renamed opcode.
    assert_killed(
        "GETUPVAL renamed",
        &rows_with(|rows| rows[4].name = "GETUPVALUE"),
        &[
            CReject::NameChanged {
                op: 4,
                claimed: "GETUPVALUE",
                official: "GETUPVAL",
            },
            CReject::Uncategorised { name: "GETUPVALUE" },
        ],
    );

    // Killer: a plausible but wrong category. `SETLIST.C` is a block index, not a count,
    // and the category statement is what catches the difference.
    assert_killed(
        "SETLIST.C recategorised as a count",
        &rows_with(|rows| rows[34].role = CRole::Count),
        &[
            CReject::CategoryMismatch {
                name: "SETLIST",
                claimed: CRole::Count,
                category: CRole::ListBlockIndex,
            },
            CReject::RoleChanged {
                op: 34,
                name: "SETLIST",
                claimed: CRole::Count,
                official: CRole::ListBlockIndex,
            },
        ],
    );

    // The expectation never moved while the killers ran: the authority still audits clean
    // and still claims exactly one fixed direct register.
    assert!(
        audit(&OFFICIAL_C_ROLES).is_empty(),
        "no mutation may reach the frozen expectation: {:?}",
        audit(&OFFICIAL_C_ROLES)
    );
    assert_eq!(fixed_register_names(&OFFICIAL_C_ROLES), vec!["CONCAT"]);
}

// ---------------------------------------------------------------------------
// The one fixed direct register `C`
// ---------------------------------------------------------------------------

/// Owned by the constant contract. This sprint proves only that a register overflow is
/// never reported as one of these.
const CONST_C_CODE: &str = "L51-CONST-005";
/// The disassembler's out-of-bounds `RK` constant diagnostic, likewise not this sprint's,
/// and likewise never a substitute for a register overflow.
const DISASM_RK_CODE: &str = "L51-DISASM-002";
/// The `RK` marker bit of a nine-bit operand.
const BIT_EIGHT: u16 = 0x100;

/// One `L51-REG-003` finding reduced to the evidence this sprint freezes.
type RegCTuple = (String, usize, usize, String, String);

/// Every register-`C` finding in one document, as frozen tuples.
fn reg_c_tuples(doc: &MachineDocument<ValidationResponse>) -> Vec<RegCTuple> {
    findings(doc, REG_C_CODE)
        .iter()
        .map(|diagnostic| {
            let source = diagnostic
                .source
                .as_ref()
                .expect("a register finding carries its source word");
            (
                diagnostic.target.to_string(),
                source.byte_offset,
                source.byte_length,
                source.raw_hex.clone(),
                diagnostic.message.clone(),
            )
        })
        .collect()
}

/// The single finding a `CONCAT` whose `C` is out of frame must carry.
fn expected_tuple(proto: &RootProto, word: u32, c: u16) -> RegCTuple {
    (
        format!("proto:{}:pc:{}", proto.path, proto.pc),
        proto.byte_offset,
        4,
        hex::encode(word.to_le_bytes()),
        format!(
            "Register C ({c}) exceeds maxstacksize ({}) at PC {}",
            proto.maxstacksize, proto.pc
        ),
    )
}

/// Every diagnostic code appearing anywhere in a document, located by key so no assertion
/// depends on where the boundary chooses to attach it.
fn codes_in(value: &Json) -> Vec<String> {
    fn walk(value: &Json, out: &mut Vec<String>) {
        match value {
            Json::Object(map) => {
                if let Some(Json::String(code)) = map.get("code") {
                    out.push(code.clone());
                }
                map.values().for_each(|nested| walk(nested, out));
            }
            Json::Array(items) => items.iter().for_each(|item| walk(item, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

#[test]
fn test_concat_register_c_boundary_is_exact_at_maxstacksize() {
    audit_authority();
    assert_eq!(
        role_of(OP_CONCAT),
        CRole::FixedRegister,
        "CONCAT.C is the register whose bound this test fixes"
    );

    let (base, base_hash, proto) = pinned_base();
    let file = NamedTempFile::new().expect("temporary chunk");
    let path = file.path();
    let maxstacksize = u16::from(proto.maxstacksize);
    assert!(
        maxstacksize >= 2,
        "the base prototype must have a register file to straddle: maxstacksize={maxstacksize}"
    );

    // `maxstacksize - 1` is the last slot the frame has and `maxstacksize` the first it does
    // not, so the two neighbours straddle the bound in one derived chunk each.
    for (c, flagged) in [(maxstacksize - 1, false), (maxstacksize, true)] {
        // `A` and `B` are held at register 0, which every prototype has, so `C` is the only
        // operand that can be at fault.
        let word = iabc(OP_CONCAT, 0, 0, c);
        assert_eq!(field_c(word), c, "the encoded word carries the driven C");
        let case = derive(
            &base,
            &base_hash,
            &proto,
            word,
            &format!("boundary: CONCAT A=0 B=0 C={c} against maxstacksize={maxstacksize}"),
        );
        assert_word_reached_disasm(&case, &proto, OP_CONCAT, path);

        for mode in MODES {
            let doc = validate_bytes(&case.bytes, mode, path);
            let expected: Vec<RegCTuple> = flagged
                .then(|| expected_tuple(&proto, word, c))
                .into_iter()
                .collect();
            assert_eq!(
                reg_c_tuples(&doc),
                expected,
                "CONCAT.C at {c} must carry exactly the frozen {REG_C_CODE} evidence for \
                 maxstacksize {maxstacksize} ({mode:?})\n{}\ncodes={:?}",
                case.evidence,
                all_codes(&doc)
            );

            // `A` and `B` were held in frame, so no register-A or register-B finding can be
            // standing in for the register-C claim.
            for code in ["L51-REG-001", "L51-REG-002"] {
                assert!(
                    findings(&doc, code).is_empty(),
                    "A and B are register 0, so {code} must not fire ({mode:?})\n{}\ncodes={:?}",
                    case.evidence,
                    all_codes(&doc)
                );
            }
        }
    }
}

#[test]
fn test_concat_c_bit_eight_is_a_register_overflow_not_a_constant() {
    audit_authority();

    let (base, base_hash, proto) = pinned_base();
    let file = NamedTempFile::new().expect("temporary chunk");
    let path = file.path();
    let maxstacksize = u16::from(proto.maxstacksize);

    // 256 is bit 8 alone; 511 is bit 8 with every other C bit set. `CONCAT.C` is a fixed
    // register, so neither value has an RK meaning: both are simply registers the frame
    // does not have.
    for c in [BIT_EIGHT, 0x1ff] {
        assert_ne!(c & BIT_EIGHT, 0, "the probe sets the RK marker bit");
        assert!(c > maxstacksize, "the probe is out of frame");
        let word = iabc(OP_CONCAT, 0, 0, c);
        assert_eq!(
            field_c(word),
            c,
            "all nine C bits survive encoding, including bit 8"
        );
        let case = derive(
            &base,
            &base_hash,
            &proto,
            word,
            &format!("bit 8: CONCAT A=0 B=0 C={c} against maxstacksize={maxstacksize}"),
        );
        assert_word_reached_disasm(&case, &proto, OP_CONCAT, path);

        // The disassembly of the same word must not raise an RK constant diagnostic either:
        // there is no RK operand here to resolve.
        let document = disasm_bytes(&case.bytes, path);
        let disasm_codes = codes_in(&document);
        assert!(
            !disasm_codes.iter().any(|code| code == DISASM_RK_CODE),
            "CONCAT.C is not an RK operand, so bit 8 must not raise {DISASM_RK_CODE}\n{}\n\
             codes={disasm_codes:?}",
            case.evidence
        );

        for mode in MODES {
            let doc = validate_bytes(&case.bytes, mode, path);
            assert_eq!(
                reg_c_tuples(&doc),
                vec![expected_tuple(&proto, word, c)],
                "bit 8 of a fixed-register C is part of the register index, so C={c} must \
                 carry exactly one {REG_C_CODE} naming the full nine-bit value \
                 ({mode:?})\n{}\ncodes={:?}",
                case.evidence,
                all_codes(&doc)
            );
            for code in [CONST_C_CODE, DISASM_RK_CODE] {
                assert!(
                    findings(&doc, code).is_empty(),
                    "a fixed-register C overflow must never be reported as {code} \
                     ({mode:?})\n{}\ncodes={:?}",
                    case.evidence,
                    all_codes(&doc)
                );
            }
        }
    }
}
