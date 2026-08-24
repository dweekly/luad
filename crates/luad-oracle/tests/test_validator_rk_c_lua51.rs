//! Independent public acceptance for the Lua 5.1 conditional `RK` operand `C`.
//!
//! This is the sprint's first authoring checkpoint, so it holds exactly two dimensions:
//!
//! - the independent `(opcode -> C role)` authority is exact, proved by a pure comparator
//!   that first accepts the unmutated table and then rejects a false `RK` addition and an
//!   omission;
//! - for every one of the twelve `RK`-`C` opcodes, a bit-8-clear `C` is a register index
//!   bounded by the owning prototype's `maxstacksize`: `maxstacksize - 1` is clean and
//!   `maxstacksize` is exactly one `L51-REG-003` for field `C`.
//!
//! The 38-row authority below is a test-local transcription of PUC-Rio Lua 5.1.5
//! `lopcodes.h`, `lopcodes.c` and `lvm.c`: a row is `ConditionalRk` only where the VM arm
//! reaches `C` through `RKC()`, so bit 8 selects between a register and a constant. So is
//! the chunk reader, which follows the `lundump.c` layout, and the instruction encoder,
//! which follows the `lopcodes.h` field layout. Nothing here calls luad's Lua 5.1 opcode,
//! disassembly, or validation helpers: the live CLI is the system under test, and only
//! neutral plumbing (`find_workspace_root`, the published envelope types) is reused.
//!
//! Every case is one single-word replacement of the pinned `control_flow` fixture at the
//! root prototype's PC 0, and records its full provenance: base hash, prototype path, PC,
//! byte offset, original word, driven `C`, changed word, and result hash.
//!
//! Scope note: schema validation, the selection/mode matrix, determinism, recursion, the
//! constant half of the domain, and the non-`RK` control sweep belong to the later
//! expansion and are deliberately absent here.

use std::path::{Path, PathBuf};
use std::process::Command;

use luad_core::diagnostic::Diagnostic;
use luad_core::envelope::{MachineDocument, ValidationResponse};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

/// A machine document read structurally, so no assertion depends on envelope field names.
type Json = serde_json::Value;

/// The pinned maintained fixture every derivation in this checkpoint is built from.
const CONTROL_FLOW: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/control_flow.luac",
    "d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40",
);

/// Total number of stock Lua 5.1.5 opcodes.
const OPCODE_COUNT: usize = 38;

/// The register-domain diagnostic this checkpoint claims for a bit-8-clear `RK`-`C`.
const REG_C_CODE: &str = "L51-REG-003";

/// The constant-domain diagnostic for field `C`. A bit-8-clear operand is a register, so
/// this code must never stand in for the claim above.
const CONST_C_CODE: &str = "L51-CONST-005";

/// Every operand-domain diagnostic other than the register-`C` one under test. `A` and `B`
/// are held at legal values in every probe, and `C` never sets bit 8, so none of these may
/// fire at either boundary; if one does, the case is not isolating field `C`.
const OTHER_OPERAND_CODES: [&str; 4] = [
    "L51-REG-001",
    "L51-REG-002",
    "L51-CONST-004",
    "L51-BOOL-001",
];

/// The `RK` marker bit of a nine-bit operand.
const BIT_EIGHT: u16 = 0x100;

// ---------------------------------------------------------------------------
// The independent authority
// ---------------------------------------------------------------------------

/// What the Lua 5.1.5 VM does with the nine physical `C` bits of one opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CRole {
    /// `C` is an `RK` slot: bit 8 clear is a register index, bit 8 set is a constant index.
    ConditionalRk,
    /// `C` is always a direct register index, bit 8 included.
    FixedRegister,
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

/// One row of the authority table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CRow {
    op: u8,
    name: &'static str,
    role: CRole,
}

const fn row(op: u8, name: &'static str, role: CRole) -> CRow {
    CRow { op, name, role }
}

/// The authority: every official Lua 5.1.5 opcode, in enumeration order, with the role of
/// its physical `C` field.
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

/// The sprint's claim stated as a set: exactly these opcodes reach `C` through `RKC()`.
/// The audit requires the table's own `ConditionalRk` rows to be exactly this list, in
/// enumeration order, so neither statement can drift alone.
const RK_C_NAMES: [&str; 12] = [
    "GETTABLE", "SETTABLE", "SELF", "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "EQ", "LT", "LE",
];

// ---------------------------------------------------------------------------
// The pure comparator over a claimed authority
// ---------------------------------------------------------------------------

/// A typed reason the comparator refuses a claimed `C`-role authority.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Reject {
    /// The claimed table does not state every official opcode exactly once.
    WrongRowCount { claimed: usize },
    /// A row names an opcode outside the official enumeration.
    UnknownOpcode { op: u8 },
    /// A row does not sit at its official opcode number, so the enumeration order moved.
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
    /// A row claims `ConditionalRk` for a `C` field that is not an `RK` slot.
    NonRkClaimedRk {
        op: u8,
        name: &'static str,
        official: CRole,
    },
    /// The claimed `RK`-`C` set is not the exact twelve-opcode set.
    RkSetChanged {
        claimed: Vec<&'static str>,
        official: Vec<&'static str>,
    },
}

/// The expectation side: the frozen row statement. Never mutated.
fn official_row(op: u8) -> Option<&'static CRow> {
    OFFICIAL_C_ROLES.iter().find(|entry| entry.op == op)
}

/// The opcodes a claimed table declares to be conditional `RK` slots, in claimed order.
fn rk_names(rows: &[CRow]) -> Vec<&'static str> {
    rows.iter()
        .filter(|entry| entry.role == CRole::ConditionalRk)
        .map(|entry| entry.name)
        .collect()
}

/// The comparator. Pure: it reads a claimed table and reports every way that table
/// disagrees with the frozen expectation, panicking at nothing and mutating nothing. The
/// unmutated table and every killer mutation are judged by this one function.
fn audit(rows: &[CRow]) -> Vec<Reject> {
    let mut rejects = Vec::new();
    if rows.len() != OPCODE_COUNT {
        rejects.push(Reject::WrongRowCount {
            claimed: rows.len(),
        });
    }

    let mut seen = [0_u8; OPCODE_COUNT];
    for (index, claimed) in rows.iter().enumerate() {
        let Some(official) = official_row(claimed.op) else {
            rejects.push(Reject::UnknownOpcode { op: claimed.op });
            continue;
        };
        if usize::from(claimed.op) != index {
            rejects.push(Reject::OutOfOrderRow {
                op: claimed.op,
                index,
            });
        }
        seen[usize::from(official.op)] += 1;
        if seen[usize::from(official.op)] > 1 {
            rejects.push(Reject::DuplicateRow {
                op: official.op,
                name: official.name,
            });
        }
        if claimed.name != official.name {
            rejects.push(Reject::NameChanged {
                op: official.op,
                claimed: claimed.name,
                official: official.name,
            });
        }
        if claimed.role != official.role {
            rejects.push(if claimed.role == CRole::ConditionalRk {
                Reject::NonRkClaimedRk {
                    op: official.op,
                    name: official.name,
                    official: official.role,
                }
            } else {
                Reject::RoleChanged {
                    op: official.op,
                    name: official.name,
                    claimed: claimed.role,
                    official: official.role,
                }
            });
        }
    }

    for official in OFFICIAL_C_ROLES.iter() {
        if seen[usize::from(official.op)] == 0 {
            rejects.push(Reject::MissingRow {
                op: official.op,
                name: official.name,
            });
        }
    }

    let claimed_rk = rk_names(rows);
    if claimed_rk != RK_C_NAMES.to_vec() {
        rejects.push(Reject::RkSetChanged {
            claimed: claimed_rk,
            official: RK_C_NAMES.to_vec(),
        });
    }

    rejects
}

/// Proves the authority is exact before any of it is used as evidence.
fn audit_authority() {
    let rejects = audit(&OFFICIAL_C_ROLES);
    assert!(
        rejects.is_empty(),
        "the authority must audit clean against its own frozen statement: {rejects:?}"
    );
    assert_eq!(
        rk_names(&OFFICIAL_C_ROLES),
        RK_C_NAMES.to_vec(),
        "exactly twelve opcodes reach C through RKC()"
    );
}

/// Every killer mutation edits a fresh clone of the authority. The expectation the
/// comparator reads - `OFFICIAL_C_ROLES` and `RK_C_NAMES` - is never touched, so no
/// mutation can move the expected and the observed statement together.
fn rows_with(edit: impl FnOnce(&mut Vec<CRow>)) -> Vec<CRow> {
    let mut rows = OFFICIAL_C_ROLES.to_vec();
    edit(&mut rows);
    rows
}

/// Judges one killer with the same comparator that judged the unmutated table.
fn assert_killed(label: &str, rows: &[CRow], expected: &[Reject]) {
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
fn test_lua51_rk_c_authority_is_exact_and_rejects_killer_mutations() {
    // Positive case first: the unmutated table audits clean, so every rejection below is
    // caused by its mutation and not by a comparator that refuses everything.
    audit_authority();

    // Every opcode number is stated exactly once, in enumeration order, with its official
    // mnemonic. `audit` already reports any drift; this states the shape directly too.
    let mut numbers: Vec<u8> = OFFICIAL_C_ROLES.iter().map(|entry| entry.op).collect();
    assert_eq!(
        numbers,
        (0..OPCODE_COUNT as u8).collect::<Vec<_>>(),
        "the 38 rows must be numbered 0..38 in enumeration order"
    );
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), OPCODE_COUNT, "no opcode number may repeat");

    // Killer: a false addition. `CONCAT.C` is a fixed direct register that never consults
    // bit 8, so an authority that calls it `RK` would hand it constant resolution.
    assert_killed(
        "CONCAT.C falsely claimed as an RK slot",
        &rows_with(|rows| rows[21].role = CRole::ConditionalRk),
        &[Reject::NonRkClaimedRk {
            op: 21,
            name: "CONCAT",
            official: CRole::FixedRegister,
        }],
    );

    // Killer: a false addition that is merely plausible. `NEWTABLE.C` is a size hint whose
    // high bit is part of the floating-point byte encoding, not an `RK` marker.
    assert_killed(
        "NEWTABLE.C falsely claimed as an RK slot",
        &rows_with(|rows| rows[10].role = CRole::ConditionalRk),
        &[Reject::NonRkClaimedRk {
            op: 10,
            name: "NEWTABLE",
            official: CRole::SizeHint,
        }],
    );

    // Killer: an omission. Dropping the last comparison row is how an `RK` authority
    // silently stops covering an opcode.
    assert_killed(
        "LE row omitted",
        &rows_with(|rows| rows.retain(|entry| entry.name != "LE")),
        &[
            Reject::MissingRow { op: 25, name: "LE" },
            Reject::WrongRowCount { claimed: 37 },
        ],
    );

    // Killer: an omission that keeps the row but demotes it out of the `RK` set.
    assert_killed(
        "SELF.C demoted out of the RK set",
        &rows_with(|rows| rows[11].role = CRole::Unused),
        &[Reject::RoleChanged {
            op: 11,
            name: "SELF",
            claimed: CRole::Unused,
            official: CRole::ConditionalRk,
        }],
    );

    // Killer: a duplicated row, and a renamed opcode.
    assert_killed(
        "MOVE stated twice",
        &rows_with(|rows| rows.push(row(0, "MOVE", CRole::Unused))),
        &[Reject::DuplicateRow {
            op: 0,
            name: "MOVE",
        }],
    );
    assert_killed(
        "GETUPVAL renamed",
        &rows_with(|rows| rows[4].name = "GETUPVALUE"),
        &[Reject::NameChanged {
            op: 4,
            claimed: "GETUPVALUE",
            official: "GETUPVAL",
        }],
    );

    // Each of the four mutations that changes membership must also be caught by the set
    // statement itself, not only row by row.
    for (label, rows) in [
        (
            "CONCAT added to the RK set",
            rows_with(|rows| rows[21].role = CRole::ConditionalRk),
        ),
        (
            "LE removed from the table",
            rows_with(|rows| rows.retain(|entry| entry.name != "LE")),
        ),
        (
            "SELF demoted out of the RK set",
            rows_with(|rows| rows[11].role = CRole::Unused),
        ),
    ] {
        let rejects = audit(&rows);
        assert!(
            rejects
                .iter()
                .any(|reject| matches!(reject, Reject::RkSetChanged { .. })),
            "the twelve-opcode RK set must itself reject: {label}\nrejects={rejects:?}"
        );
    }

    // The expectation never moved while the killers ran.
    audit_authority();
}

// ---------------------------------------------------------------------------
// Test-local chunk reading and encoding
// ---------------------------------------------------------------------------

/// The root prototype facts every derived case is built from.
struct RootProto {
    path: String,
    maxstacksize: u8,
    pc: usize,
    byte_offset: usize,
    word: u32,
}

/// Reads the root prototype prologue and its first instruction word, following the
/// PUC-Rio `lundump.c` layout. Only the fields the derived cases need are decoded.
fn read_root_proto(bytes: &[u8]) -> RootProto {
    assert_eq!(&bytes[0..4], b"\x1bLua", "PUC chunk signature");
    assert_eq!(bytes[4], 0x51, "Lua 5.1 version byte");
    assert_eq!(bytes[6], 1, "little-endian fixture");
    assert_eq!(bytes[9], 4, "32-bit instruction words");
    let sizeof_int = bytes[7] as usize;
    let sizeof_sizet = bytes[8] as usize;
    assert_eq!((sizeof_int, sizeof_sizet), (4, 8), "stock 64-bit layout");

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

/// The `iABC` field layout of `lopcodes.h`.
fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    u32::from(op) | (u32::from(a) << 6) | (u32::from(c) << 14) | (u32::from(b) << 23)
}

/// One probe word: the opcode under test with the driven `C`, and `A`/`B` controls chosen
/// so `C` is the only operand that can be at fault.
///
/// `A = 0` is a register every prototype has and is also inside the `0..=1` comparison
/// boolean domain that `EQ`, `LT` and `LE` require of `A`. `B = 0` is simultaneously a
/// legal fixed direct register and a legal bit-8-clear `RK` register, so it is valid for
/// all twelve rows. A probe that happened to equal the fixture's own word would make its
/// derivation a no-op, so that collision is resolved by moving `A` to register 1, which is
/// equally legal in both domains.
fn probe(op: u8, c: u16, proto: &RootProto) -> u32 {
    let word = iabc(op, 0, 0, c);
    if word != proto.word {
        return word;
    }
    let alternate = iabc(op, 1, 0, c);
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

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn luad_bin() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path.into();
    }
    let workspace = luad_oracle::find_workspace_root();
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

/// Runs one public machine boundary over an in-memory chunk under explicit `lua5.1`
/// selection and returns its stdout as JSON.
fn run_public(command: &str, bytes: &[u8], path: &Path) -> Json {
    std::fs::write(path, bytes).expect("write derived chunk");
    let output = Command::new(luad_bin())
        .args([
            command,
            path.to_str().expect("UTF-8 path"),
            "--dialect",
            "lua5.1",
            "--format",
            "json",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run public {command} CLI: {error}"));
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command} stdout is not JSON: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Runs the public `validate` boundary over an in-memory chunk.
fn validate_bytes(bytes: &[u8], path: &Path) -> MachineDocument<ValidationResponse> {
    let document = run_public("validate", bytes, path);
    serde_json::from_value(document).expect("validate stdout is a machine document")
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
/// other than the ones asserted on never satisfy or defeat an assertion here; they are
/// printed so a red is never mistaken for a different contract's finding.
fn all_codes(doc: &MachineDocument<ValidationResponse>) -> Vec<String> {
    doc.data
        .diagnostics
        .iter()
        .map(|diagnostic| format!("{}@{}", diagnostic.code, diagnostic.target))
        .collect()
}

/// One `L51-REG-003` finding reduced to the evidence this sprint freezes: owning target,
/// source word location and bytes, and exact message.
type RegCTuple = (String, usize, usize, String, String);

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

/// The single finding a bit-8-clear `RK`-`C` at `maxstacksize` must carry.
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

/// Whether a value is a disassembled instruction, judged by its own shape.
fn is_instruction(value: &Json) -> bool {
    value.get("opcode_num").is_some() && value.get("encoded_operands").is_some()
}

/// The instruction a disassembly lists at one PC, located by shape so no assertion depends
/// on where the boundary attaches it.
fn instruction_at(document: &Json, pc: usize) -> Option<Json> {
    fn walk(value: &Json, out: &mut Vec<Json>) {
        match value {
            Json::Object(map) => {
                if is_instruction(value) {
                    out.push(value.clone());
                }
                map.values().for_each(|nested| walk(nested, out));
            }
            Json::Array(items) => items.iter().for_each(|item| walk(item, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(document, &mut out);
    out.into_iter()
        .find(|instruction| instruction["pc"].as_u64() == Some(pc as u64))
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/// A chunk derived by replacing exactly one instruction word of the pinned base, with the
/// provenance the sprint requires of every derived case.
struct Derived {
    bytes: Vec<u8>,
    word: u32,
    evidence: String,
}

fn derive(base: &[u8], base_hash: &str, proto: &RootProto, word: u32, note: &str) -> Derived {
    let mut bytes = base.to_vec();
    bytes[proto.byte_offset..proto.byte_offset + 4].copy_from_slice(&word.to_le_bytes());
    let result = sha256(&bytes);
    let evidence = format!(
        "{note}: base={base_hash} proto={} pc={} byte_offset={} original_word={:#010x} \
         driven_c={} changed_word={word:#010x} maxstacksize={} result={result}",
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

/// Reads the pinned fixture and refuses to hand back bytes that do not hash to its pin.
fn pinned_base() -> (Vec<u8>, String, RootProto) {
    let (relative, expected) = CONTROL_FLOW;
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative),
        luad_oracle::find_workspace_root().join(relative),
    ];
    let path = candidates
        .iter()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| panic!("pinned fixture {relative} must exist: tried {candidates:?}"));
    let base = std::fs::read(path).unwrap_or_else(|error| panic!("read {relative}: {error}"));
    let base_hash = sha256(&base);
    assert_eq!(
        base_hash, expected,
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
        (2..=250).contains(&proto.maxstacksize),
        "the base prototype must have a register file to straddle, inside Lua's own cap: \
         maxstacksize={}",
        proto.maxstacksize
    );
    (base, base_hash, proto)
}

// ---------------------------------------------------------------------------
// The register half of the RK domain
// ---------------------------------------------------------------------------

/// The two neighbours of the register bound: the last slot the frame has, and the first it
/// does not.
fn boundaries(maxstacksize: u8) -> [(u16, bool); 2] {
    let max = u16::from(maxstacksize);
    [(max - 1, false), (max, true)]
}

#[test]
fn test_rk_c_register_domain_is_bounded_by_maxstacksize() {
    audit_authority();

    let (base, base_hash, proto) = pinned_base();
    let file = NamedTempFile::new().expect("temporary chunk");
    let path = file.path();

    // The sweep is the authority's own `RK` rows, so it cannot silently shrink to a
    // hand-picked few or grow past the claim.
    let driven: Vec<&CRow> = OFFICIAL_C_ROLES
        .iter()
        .filter(|entry| entry.role == CRole::ConditionalRk)
        .collect();
    assert_eq!(
        driven.iter().map(|entry| entry.name).collect::<Vec<_>>(),
        RK_C_NAMES.to_vec(),
        "all twelve RK-C opcodes are driven"
    );

    let mut problems: Vec<String> = Vec::new();
    for entry in driven.iter() {
        let (op, name) = (entry.op, entry.name);
        for (c, invalid) in boundaries(proto.maxstacksize) {
            assert_eq!(c & BIT_EIGHT, 0, "{name}: the probe leaves bit 8 clear");
            let word = probe(op, c, &proto);
            assert_eq!(
                field_c(word),
                c,
                "{name}: the encoded word carries the driven C"
            );
            let case = derive(
                &base,
                &base_hash,
                &proto,
                word,
                &format!(
                    "{name}.C={c} ({}) against maxstacksize={}",
                    if invalid { "out of frame" } else { "in frame" },
                    proto.maxstacksize
                ),
            );

            // Vacuity, before any validation is judged: the derived word must reach public
            // disassembly as this opcode at this PC, and its `C` must be typed as the
            // register the bit-8-clear encoding says it is. An absent finding below can
            // then not be an artefact of a chunk the boundary decoded some other way.
            let document = run_public("disasm", &case.bytes, path);
            let Some(instruction) = instruction_at(&document, proto.pc) else {
                problems.push(format!(
                    "{name}.C={c}: the disassembly lists no instruction at PC {}\n  {}",
                    proto.pc, case.evidence
                ));
                continue;
            };
            let seen = (
                instruction["opcode_num"].as_u64(),
                instruction["mnemonic"].as_str().map(str::to_string),
                instruction["raw_word"].as_u64(),
            );
            let intended = (
                Some(u64::from(op)),
                Some(name.to_string()),
                Some(u64::from(case.word)),
            );
            if seen != intended {
                problems.push(format!(
                    "{name}.C={c}: the derived word did not reach public disassembly as \
                     intended\n  seen={seen:?} intended={intended:?}\n  {}",
                    case.evidence
                ));
                continue;
            }
            let typed_c = instruction["operands"].as_array().and_then(|operands| {
                operands
                    .iter()
                    .find(|operand| operand["name"].as_str() == Some("C"))
                    .cloned()
            });
            let typed_as_register = typed_c.as_ref().is_some_and(|operand| {
                operand["kind"]["kind"].as_str() == Some("register")
                    && operand["kind"]["index"].as_u64() == Some(u64::from(c))
            });
            if !typed_as_register {
                problems.push(format!(
                    "{name}.C={c}: bit 8 is clear, so public disassembly must type C as \
                     register {c}\n  operand={}\n  {}",
                    typed_c.unwrap_or(Json::Null),
                    case.evidence
                ));
                continue;
            }

            // The claim. `C` is the only operand that can be at fault, so the register
            // bound decides the whole document's operand-domain content.
            let doc = validate_bytes(&case.bytes, path);
            let expected: Vec<RegCTuple> = invalid
                .then(|| expected_tuple(&proto, case.word, c))
                .into_iter()
                .collect();
            let observed = reg_c_tuples(&doc);
            if observed != expected {
                problems.push(format!(
                    "{name}.C={c} against maxstacksize={}: expected {} {REG_C_CODE} finding(s) \
                     for field C, observed {}\n  expected={expected:#?}\n  observed={observed:#?}\
                     \n  {}\n  all codes={:?}",
                    proto.maxstacksize,
                    expected.len(),
                    observed.len(),
                    case.evidence,
                    all_codes(&doc)
                ));
            }

            // A bit-8-clear operand is a register in either direction, so the constant
            // diagnostic may never stand in for it, and no other operand domain may fire
            // while `A` and `B` are held legal.
            for code in std::iter::once(CONST_C_CODE).chain(OTHER_OPERAND_CODES) {
                let stray = findings(&doc, code);
                if !stray.is_empty() {
                    problems.push(format!(
                        "{name}.C={c}: bit 8 is clear and A/B are legal, so {code} must not \
                         fire; observed {}\n  findings={:?}\n  {}",
                        stray.len(),
                        stray
                            .iter()
                            .map(|diagnostic| format!(
                                "{}@{}: {}",
                                diagnostic.code, diagnostic.target, diagnostic.message
                            ))
                            .collect::<Vec<_>>(),
                        case.evidence
                    ));
                }
            }
        }
    }

    assert!(
        problems.is_empty(),
        "a conditional RK operand C with bit 8 clear is a register index bounded by the \
         owning prototype's maxstacksize: C at maxstacksize-1 must be clean and C at \
         maxstacksize must be exactly one {REG_C_CODE} for field C. {} of {} case(s) \
         across {} RK-C opcode(s) disagree:\n\n{}",
        problems.len(),
        driven.len() * 2,
        driven.len(),
        problems.join("\n\n")
    );
}
