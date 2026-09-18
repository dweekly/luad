//! Independent public acceptance for the Lua 5.1 conditional `RK` operand `C`.
//!
//! This module holds four acceptance dimensions, all of them driven over the exact
//! twelve-opcode `RK`-`C` set the independent authority states:
//!
//! - the independent `(opcode -> C role)` authority is exact, proved by a pure comparator
//!   that first accepts the unmutated table and then rejects a false `RK` addition and an
//!   omission;
//! - a bit-8-clear `C` is a register index bounded by the owning prototype's
//!   `maxstacksize`: `maxstacksize - 1` is clean and `maxstacksize` is exactly one
//!   `L51-REG-003` for field `C`;
//! - a bit-8-set `C` is a constant index bounded by the owning prototype's constant table:
//!   the last index is clean and one past the end is exactly one `L51-CONST-005` for field
//!   `C`, never a register diagnostic;
//! - public disassembly types the operand by that same bit: bit 8 clear is a register with
//!   no resolved constant, bit 8 set is a visible constant selection that carries the
//!   resolved constant when the index exists and carries `L51-DISASM-002` instead when it
//!   does not.
//!
//! The 38-row authority below is a test-local transcription of PUC-Rio Lua 5.1.5
//! `lopcodes.h`, `lopcodes.c` and `lvm.c`: a row is `ConditionalRk` only where the VM arm
//! reaches `C` through `RKC()`, so bit 8 selects between a register and a constant. So is
//! the chunk reader, which follows the `lundump.c` layout, and the instruction encoder,
//! which follows the `lopcodes.h` field layout. Nothing here calls luad's Lua 5.1 opcode,
//! disassembly, or validation helpers: the live CLI is the system under test, and only
//! neutral plumbing (`find_workspace_root`, the published envelope types) is reused.
//!
//! Every case is one single-word replacement at the root prototype's PC 0, and records its
//! full provenance: base hash, prototype path, PC, byte offset, original word, driven `C`,
//! changed word, and result hash. Two owners are derived from the pinned `control_flow`
//! fixture: the fixture itself, and one whose root constant table has been emptied by the
//! same test-local machinery, so the zero-length rule - index `0` is the first invalid
//! selected constant - is exercised on a real owning prototype.
//!
//! Scope note: schema validation, the selection/mode matrix, determinism, recursion into
//! child prototypes, and the non-`RK` control sweep belong to the later expansion and are
//! deliberately absent here.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

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

/// The constant-domain diagnostic this checkpoint claims for a bit-8-set `RK`-`C` whose
/// selected index the owning constant table does not have. The two codes are exclusive: a
/// bit-8-clear operand is a register and may never be reported under this code, and a
/// bit-8-set operand is a constant selection and may never be reported under `REG_C_CODE`.
const CONST_C_CODE: &str = "L51-CONST-005";

/// The disassembler's own out-of-bounds selected-constant diagnostic. It is attached to the
/// disassembled instruction, not to the validator's finding list, and is asserted only
/// there, so the two boundaries' diagnostics are never conflated.
const DISASM_RK_CODE: &str = "L51-DISASM-002";

/// Every operand-domain diagnostic that field `C` does not own. `A` and `B` are held at
/// legal values in every probe, so none of these may fire at the instruction under test;
/// if one does, the case is not isolating field `C`.
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

    // Each mutation that changes membership must also be caught by the twelve-name set
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

/// The root prototype facts every derived case is built from: the register file and the
/// constant table that bound field `C`, and the location of the word the cases replace.
struct RootProto {
    path: String,
    maxstacksize: u8,
    pc: usize,
    byte_offset: usize,
    word: u32,
    /// Number of entries in this prototype's own constant table.
    constants_len: usize,
    /// Byte offset of the `sizek` counter that precedes the constant table.
    constants_count_offset: usize,
    /// Byte span of the constant table's payload, after that counter.
    constants_payload: (usize, usize),
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
    let sizeof_number = bytes[10] as usize;
    assert_eq!(
        (sizeof_int, sizeof_sizet, sizeof_number),
        (4, 8, 8),
        "stock 64-bit layout with double numbers"
    );

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
    let code_offset = pos;
    assert!(
        code_offset + 4 * instruction_count <= bytes.len(),
        "code array lies inside the chunk"
    );

    // The constant table follows the code array: a counter, then one tag-dispatched payload
    // per entry, exactly as `lundump.c` writes them.
    let constants_count_offset = code_offset + 4 * instruction_count;
    let constants_len = uint(constants_count_offset, sizeof_int);
    let payload_start = constants_count_offset + sizeof_int;
    let mut walk = payload_start;
    for index in 0..constants_len {
        assert!(walk < bytes.len(), "constant {index} lies inside the chunk");
        let tag = bytes[walk];
        walk += 1;
        walk += match tag {
            0 => 0,                                       // nil carries no payload
            1 => 1,                                       // boolean
            3 => sizeof_number,                           // number
            4 => sizeof_sizet + uint(walk, sizeof_sizet), // string: length then bytes
            other => panic!("unknown constant tag {other} for constant {index} at byte {walk}"),
        };
    }
    assert!(
        walk <= bytes.len(),
        "the constant table lies inside the chunk"
    );

    RootProto {
        path: "0".to_string(),
        maxstacksize,
        pc: 0,
        byte_offset: code_offset,
        word: u32::from_le_bytes(
            bytes[code_offset..code_offset + 4]
                .try_into()
                .expect("instruction word"),
        ),
        constants_len,
        constants_count_offset,
        constants_payload: (payload_start, walk),
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

/// The CLI under test, located once: the many probes below all drive the same binary.
fn luad_bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(luad_oracle::luad_binary_path).as_path()
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

/// One validator finding reduced to the evidence this sprint freezes: owning target,
/// source word location and bytes, and message.
type FindingTuple = (String, usize, usize, String, String);

/// Every finding carrying one code, as frozen tuples.
fn finding_tuples(doc: &MachineDocument<ValidationResponse>, code: &str) -> Vec<FindingTuple> {
    findings(doc, code)
        .iter()
        .map(|diagnostic| {
            let source = diagnostic
                .source
                .as_ref()
                .expect("an operand-domain finding carries its source word");
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

/// Every `L51-REG-003` finding anywhere in the document.
fn reg_c_tuples(doc: &MachineDocument<ValidationResponse>) -> Vec<FindingTuple> {
    finding_tuples(doc, REG_C_CODE)
}

/// The findings carrying one code that name one owning instruction. The `RK`-`C` claim is
/// about the instruction that encodes the operand, so a derived chunk whose other
/// instructions have their own problems cannot satisfy or defeat it.
fn tuples_at(
    doc: &MachineDocument<ValidationResponse>,
    code: &str,
    target: &str,
) -> Vec<FindingTuple> {
    finding_tuples(doc, code)
        .into_iter()
        .filter(|tuple| tuple.0 == target)
        .collect()
}

/// The single finding a bit-8-clear `RK`-`C` at `maxstacksize` must carry.
fn expected_tuple(proto: &RootProto, word: u32, c: u16) -> FindingTuple {
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

/// The diagnostic codes public disassembly attached to one instruction. These are the
/// disassembler's own findings and are never read as validator findings.
fn instruction_codes(instruction: &Json) -> Vec<String> {
    instruction
        .get("diagnostics")
        .and_then(Json::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Disassembles a derived chunk and returns the instruction at the derived PC, having
/// required it to be the opcode and the exact word the case intended. Every case runs this
/// guard before its claim is judged, so no absence below can be an artefact of a chunk the
/// boundary decoded some other way.
fn observed_instruction(
    case: &Derived,
    proto: &RootProto,
    op: u8,
    name: &str,
    path: &Path,
) -> Result<Json, String> {
    let document = run_public("disasm", &case.bytes, path);
    let Some(instruction) = instruction_at(&document, proto.pc) else {
        return Err(format!(
            "{name}: the disassembly lists no instruction at PC {}\n  {}",
            proto.pc, case.evidence
        ));
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
        return Err(format!(
            "{name}: the derived word did not reach public disassembly as intended\n  \
             seen={seen:?} intended={intended:?}\n  {}",
            case.evidence
        ));
    }
    Ok(instruction)
}

// ---------------------------------------------------------------------------
// How public disassembly published the `C` operand
// ---------------------------------------------------------------------------

/// The published form of one instruction's `C` operand, read structurally.
#[derive(Clone, Debug, PartialEq, Eq)]
enum COperand {
    /// A typed register index. `resolved` records whether a resolved fact was attached,
    /// which a register may never carry.
    Register { index: u64, resolved: bool },
    /// A visible constant selection: the published value keeps all nine bits, including the
    /// selection bit, and the display marks the selection. `resolved` carries the resolved
    /// constant's index when the owning table has it.
    SelectedConstant {
        value: u64,
        display: String,
        resolved: Option<u64>,
    },
    /// Anything else, including an absent operand or an unexpected typed kind.
    Other(String),
}

/// What the `RK` rule says the `C` operand of one probe must look like.
#[derive(Clone, Debug, PartialEq, Eq)]
enum CExpectation {
    /// Bit 8 clear: the register at this index, with no resolved constant.
    Register { index: u64 },
    /// Bit 8 set: the selection of this constant index, published with the full nine-bit
    /// value, resolved exactly when the owning table has that index.
    Constant {
        value: u64,
        index: u64,
        resolved: bool,
    },
}

fn classify_c(instruction: &Json) -> COperand {
    let Some(operand) = instruction["operands"].as_array().and_then(|operands| {
        operands
            .iter()
            .find(|operand| operand["name"].as_str() == Some("C"))
    }) else {
        return COperand::Other("the instruction publishes no operand named C".to_string());
    };
    let resolved = operand.get("resolved").filter(|fact| !fact.is_null());
    match operand["kind"]["kind"].as_str() {
        Some("register") => match operand["kind"]["index"].as_u64() {
            Some(index) => COperand::Register {
                index,
                resolved: resolved.is_some(),
            },
            None => COperand::Other(format!("a register C carrying no index: {operand}")),
        },
        Some("immediate-unsigned") => {
            let Some(value) = operand["kind"]["value"].as_u64() else {
                return COperand::Other(format!("a selected C carrying no value: {operand}"));
            };
            let resolved_index = match resolved {
                None => None,
                Some(fact) if fact["type"].as_str() == Some("constant") => {
                    match fact["index"].as_u64() {
                        Some(index) => Some(index),
                        None => {
                            return COperand::Other(format!(
                                "a resolved constant carrying no index: {fact}"
                            ));
                        }
                    }
                }
                Some(fact) => {
                    return COperand::Other(format!("C resolved to a non-constant fact: {fact}"));
                }
            };
            COperand::SelectedConstant {
                value,
                display: operand["display"].as_str().unwrap_or_default().to_string(),
                resolved: resolved_index,
            }
        }
        other => COperand::Other(format!("C typed as {other:?}: {operand}")),
    }
}

/// The comparator over one published `C` operand. Pure, so the killer controls in the
/// disassembly test drive it with synthetic observations and prove it is live.
fn judge_c_operand(expected: &CExpectation, observed: &COperand) -> Option<String> {
    match (expected, observed) {
        (
            CExpectation::Register { index },
            COperand::Register {
                index: seen,
                resolved,
            },
        ) => {
            if seen != index {
                Some(format!(
                    "expected register {index}, observed register {seen}"
                ))
            } else if *resolved {
                Some("a register operand must carry no resolved constant".to_string())
            } else {
                None
            }
        }
        (
            CExpectation::Constant {
                value,
                index,
                resolved,
            },
            COperand::SelectedConstant {
                value: seen_value,
                display,
                resolved: seen_resolved,
            },
        ) => {
            if seen_value != value {
                Some(format!(
                    "expected the published nine-bit selection {value}, observed {seen_value}"
                ))
            } else if !display.starts_with("K(") {
                Some(format!(
                    "expected the display to mark a constant selection, observed {display:?}"
                ))
            } else {
                match (*resolved, seen_resolved) {
                    (true, Some(seen)) if seen == index => None,
                    (true, Some(seen)) => Some(format!(
                        "expected the resolved constant index {index}, observed {seen}"
                    )),
                    (true, None) => Some(format!(
                        "expected the resolved constant at index {index}, observed none"
                    )),
                    (false, None) => None,
                    (false, Some(seen)) => Some(format!(
                        "expected no resolved constant, observed one at index {seen}"
                    )),
                }
            }
        }
        (CExpectation::Register { index }, observed) => {
            Some(format!("expected register {index}, observed {observed:?}"))
        }
        (CExpectation::Constant { index, .. }, observed) => Some(format!(
            "expected the selection of constant {index}, observed {observed:?}"
        )),
    }
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
    assert!(
        (1..256).contains(&proto.constants_len),
        "the base prototype must have a constant table to straddle, and its one-past-the-end \
         index must still fit the eight index bits of an RK operand: constants={}",
        proto.constants_len
    );
    (base, base_hash, proto)
}

/// The pinned base with the root prototype's constant table emptied, so the zero-length
/// rule - index `0` is the first invalid selected constant - has a real owning prototype.
///
/// Only the constant table is touched: its counter becomes zero and its payload bytes are
/// removed, which is exactly what `lundump.c` writes for a constant-free prototype. The
/// code array precedes it, so every instruction, byte offset and source word this module
/// derives is unchanged, and the reader re-reads the result to prove it. The root's other
/// instructions keep their own constant references and will have their own findings; every
/// assertion below names the owning instruction, so that noise can neither satisfy nor
/// defeat the claim.
fn zero_constant_owner(base: &[u8], proto: &RootProto) -> (Vec<u8>, String, RootProto) {
    let (start, end) = proto.constants_payload;
    let counter = proto.constants_count_offset;
    let mut bytes = base.to_vec();
    bytes[counter..counter + 4].copy_from_slice(&0_u32.to_le_bytes());
    bytes.drain(start..end);

    let hash = sha256(&bytes);
    let derived = read_root_proto(&bytes);
    assert_eq!(
        derived.constants_len, 0,
        "the derived owner must declare an empty constant table"
    );
    assert_eq!(
        (
            derived.byte_offset,
            derived.word,
            derived.maxstacksize,
            derived.pc
        ),
        (proto.byte_offset, proto.word, proto.maxstacksize, proto.pc),
        "emptying the constant table must leave the code array and its offsets untouched"
    );
    (bytes, hash, derived)
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

/// The rows every sweep in this module drives: the authority's own `RK` rows, so no sweep
/// can silently shrink to a hand-picked few or grow past the twelve-opcode claim.
fn rk_rows() -> Vec<&'static CRow> {
    let driven: Vec<&CRow> = OFFICIAL_C_ROLES
        .iter()
        .filter(|entry| entry.role == CRole::ConditionalRk)
        .collect();
    assert_eq!(
        driven.iter().map(|entry| entry.name).collect::<Vec<_>>(),
        RK_C_NAMES.to_vec(),
        "all twelve RK-C opcodes are driven"
    );
    driven
}

#[test]
fn test_rk_c_register_domain_is_bounded_by_maxstacksize() {
    audit_authority();

    let (base, base_hash, proto) = pinned_base();
    let file = NamedTempFile::new().expect("temporary chunk");
    let path = file.path();

    let driven = rk_rows();
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
            let instruction = match observed_instruction(&case, &proto, op, name, path) {
                Ok(instruction) => instruction,
                Err(problem) => {
                    problems.push(problem);
                    continue;
                }
            };
            let observed_c = classify_c(&instruction);
            if let Some(reason) = judge_c_operand(
                &CExpectation::Register {
                    index: u64::from(c),
                },
                &observed_c,
            ) {
                problems.push(format!(
                    "{name}.C={c}: bit 8 is clear, so public disassembly must type C as a \
                     register: {reason}\n  {}",
                    case.evidence
                ));
                continue;
            }

            // The claim. `C` is the only operand that can be at fault, so the register
            // bound decides the whole document's operand-domain content.
            let doc = validate_bytes(&case.bytes, path);
            let expected: Vec<FindingTuple> = invalid
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

// ---------------------------------------------------------------------------
// The constant half of the RK domain
// ---------------------------------------------------------------------------

/// One driven selected constant: the low eight-bit index, and whether the owning constant
/// table has it.
struct ConstCase {
    index: usize,
    valid: bool,
}

/// The two neighbours of the constant bound for one owning table: its last index, and the
/// first index it does not have. A zero-length table has no valid neighbour, so index `0`
/// is its first invalid selected constant.
fn constant_cases(constants_len: usize) -> Vec<ConstCase> {
    let mut cases = Vec::new();
    if constants_len > 0 {
        cases.push(ConstCase {
            index: constants_len - 1,
            valid: true,
        });
    }
    cases.push(ConstCase {
        index: constants_len,
        valid: false,
    });
    cases
}

/// The identity a finding must carry to be the owning instruction's: its target, and the
/// byte location and bytes of the source word.
type Identity = (String, usize, usize, String);

fn identity_of(proto: &RootProto, word: u32) -> Identity {
    (
        format!("proto:{}:pc:{}", proto.path, proto.pc),
        proto.byte_offset,
        4,
        hex::encode(word.to_le_bytes()),
    )
}

/// The comparator over one constant-domain case, judged from the validator's findings for
/// the owning instruction alone. Pure, so the killer controls below drive it with synthetic
/// findings and prove it is live.
fn judge_constant_case(
    case: &ConstCase,
    identity: &Identity,
    total: usize,
    const_findings: &[FindingTuple],
    reg_findings: &[FindingTuple],
) -> Vec<String> {
    let mut problems = Vec::new();
    let index = case.index;
    if !reg_findings.is_empty() {
        problems.push(format!(
            "bit 8 is set, so C selects a constant and may never be reported under \
             {REG_C_CODE}; observed {reg_findings:#?}"
        ));
    }

    if case.valid {
        if !const_findings.is_empty() {
            problems.push(format!(
                "constant index {index} is inside a table of {total}, so field C must be \
                 clean; observed {const_findings:#?}"
            ));
        }
        return problems;
    }

    let [finding] = const_findings else {
        problems.push(format!(
            "constant index {index} is one past a table of {total}, so field C must carry \
             exactly one {CONST_C_CODE}; observed {} finding(s): {const_findings:#?}",
            const_findings.len()
        ));
        return problems;
    };
    let seen = (finding.0.clone(), finding.1, finding.2, finding.3.clone());
    if &seen != identity {
        problems.push(format!(
            "the {CONST_C_CODE} must name the owning instruction and its source word: \
             expected {identity:?}, observed {seen:?}"
        ));
    }
    let message = &finding.4;
    if !message.contains(&index.to_string()) || !message.contains(&total.to_string()) {
        problems.push(format!(
            "the {CONST_C_CODE} message must name the selected constant index {index} and \
             the size {total} of the owning table: {message:?}"
        ));
    }
    if message.contains("maxstacksize") {
        problems.push(format!(
            "the {CONST_C_CODE} message must report a constant bound, not a register frame: \
             {message:?}"
        ));
    }
    problems
}

/// Drives the pure constant-domain comparator with synthetic evidence: it accepts exactly
/// the expected observation and rejects each way a boundary could appear to satisfy the
/// claim without doing so.
fn assert_constant_comparator_is_live() {
    let identity: Identity = ("proto:0:pc:0".to_string(), 64, 4, "0a0b0c0d".to_string());
    let valid = ConstCase {
        index: 2,
        valid: true,
    };
    let invalid = ConstCase {
        index: 3,
        valid: false,
    };
    let expected = vec![(
        identity.0.clone(),
        identity.1,
        identity.2,
        identity.3.clone(),
        "RK operand C constant index 3 out of bounds (total constants: 3)".to_string(),
    )];
    let register_finding = vec![(
        identity.0.clone(),
        identity.1,
        identity.2,
        identity.3.clone(),
        "Register C (3) exceeds maxstacksize (2) at PC 0".to_string(),
    )];

    // Positive: the comparator accepts both sides of the bound when the evidence is exact.
    for (label, case, const_findings) in [
        ("the last valid index is clean", &valid, Vec::new()),
        ("one past the end is reported", &invalid, expected.clone()),
    ] {
        let problems = judge_constant_case(case, &identity, 3, &const_findings, &[]);
        assert!(
            problems.is_empty(),
            "the comparator must accept the exact expected evidence: {label}\n{problems:#?}"
        );
    }

    // Killers, each judged by that same comparator.
    let mut wrong_owner = expected.clone();
    wrong_owner[0].0 = "proto:0/0:pc:4".to_string();
    let mut wrong_word = expected.clone();
    wrong_word[0].3 = "ffffffff".to_string();
    let mut wrong_bound = expected.clone();
    wrong_bound[0].4 =
        "RK operand C constant index 9 out of bounds (total constants: 9)".to_string();
    let mut register_message = expected.clone();
    register_message[0].4 = "Register C (259) exceeds maxstacksize (3) at PC 0".to_string();
    for (label, case, const_findings, reg_findings) in [
        (
            "the invalid selection produced nothing at all",
            &invalid,
            Vec::new(),
            Vec::new(),
        ),
        (
            "a register diagnostic was substituted for the constant one",
            &invalid,
            Vec::new(),
            register_finding.clone(),
        ),
        (
            "a register diagnostic accompanied the constant one",
            &invalid,
            expected.clone(),
            register_finding,
        ),
        (
            "the finding named another instruction",
            &invalid,
            wrong_owner,
            Vec::new(),
        ),
        (
            "the finding named another source word",
            &invalid,
            wrong_word,
            Vec::new(),
        ),
        (
            "the finding named another bound",
            &invalid,
            wrong_bound,
            Vec::new(),
        ),
        (
            "the finding reported a register frame instead of a constant table",
            &invalid,
            register_message,
            Vec::new(),
        ),
        (
            "the same finding was reported twice",
            &invalid,
            [expected.clone(), expected.clone()].concat(),
            Vec::new(),
        ),
        (
            "the last valid index was reported as out of bounds",
            &valid,
            expected,
            Vec::new(),
        ),
    ] {
        let problems = judge_constant_case(case, &identity, 3, &const_findings, &reg_findings);
        assert!(
            !problems.is_empty(),
            "the comparator must reject this killer: {label}"
        );
    }
}

#[test]
fn test_rk_c_constant_domain_is_bounded_by_the_owning_constant_table() {
    audit_authority();
    assert_constant_comparator_is_live();

    let (pinned, pinned_hash, pinned_proto) = pinned_base();
    let (empty, empty_hash, empty_proto) = zero_constant_owner(&pinned, &pinned_proto);
    let file = NamedTempFile::new().expect("temporary chunk");
    let path = file.path();

    // Two owning prototypes: the pinned fixture's own constant table, and one emptied by
    // this module so the zero-length rule is exercised on a real owner.
    let owners = [
        ("pinned", &pinned, pinned_hash.as_str(), &pinned_proto),
        ("zero-constant", &empty, empty_hash.as_str(), &empty_proto),
    ];
    assert_ne!(
        pinned_proto.constants_len, empty_proto.constants_len,
        "the two owners must impose different constant bounds"
    );

    let driven = rk_rows();
    let mut problems: Vec<String> = Vec::new();
    let mut cases = 0_usize;
    for (owner, base, base_hash, proto) in owners {
        let total = proto.constants_len;
        for entry in driven.iter() {
            let (op, name) = (entry.op, entry.name);
            for case in constant_cases(total) {
                cases += 1;
                let index = case.index;
                let c = BIT_EIGHT | u16::try_from(index).expect("a selected index fits nine bits");
                assert_eq!(
                    c & BIT_EIGHT,
                    BIT_EIGHT,
                    "{name}: the probe sets the RK selection bit"
                );
                let word = probe(op, c, proto);
                assert_eq!(
                    field_c(word),
                    c,
                    "{name}: the encoded word carries the driven C"
                );
                let derived = derive(
                    base,
                    base_hash,
                    proto,
                    word,
                    &format!(
                        "{owner} owner: {name}.C=K({index}) ({}) against a constant table of \
                         {total}",
                        if case.valid { "present" } else { "absent" }
                    ),
                );

                // Vacuity: the word reached public disassembly as this opcode, and its `C`
                // is visibly a constant selection rather than a register. Which constant it
                // resolves to is the disassembly test's claim; here it is enough that the
                // boundary is not reading a register.
                let instruction = match observed_instruction(&derived, proto, op, name, path) {
                    Ok(instruction) => instruction,
                    Err(problem) => {
                        problems.push(problem);
                        continue;
                    }
                };
                let observed_c = classify_c(&instruction);
                if let Some(reason) = judge_c_operand(
                    &CExpectation::Constant {
                        value: u64::from(c),
                        index: index as u64,
                        resolved: case.valid,
                    },
                    &observed_c,
                ) {
                    problems.push(format!(
                        "{owner} owner: {name}.C=K({index}): bit 8 is set, so public \
                         disassembly must publish a constant selection: {reason}\n  {}",
                        derived.evidence
                    ));
                    continue;
                }

                // The claim, judged from the validator's findings for this instruction.
                let doc = validate_bytes(&derived.bytes, path);
                let identity = identity_of(proto, derived.word);
                let reported = judge_constant_case(
                    &case,
                    &identity,
                    total,
                    &tuples_at(&doc, CONST_C_CODE, &identity.0),
                    &tuples_at(&doc, REG_C_CODE, &identity.0),
                );
                for problem in reported {
                    problems.push(format!(
                        "{owner} owner: {name}.C=K({index}) against a constant table of \
                         {total}: {problem}\n  {}\n  all codes={:?}",
                        derived.evidence,
                        all_codes(&doc)
                    ));
                }

                // `A` and `B` are legal for every row, so no other operand domain may fire
                // at this instruction.
                for code in OTHER_OPERAND_CODES {
                    let stray = tuples_at(&doc, code, &identity.0);
                    if !stray.is_empty() {
                        problems.push(format!(
                            "{owner} owner: {name}.C=K({index}): A and B are legal, so {code} \
                             must not fire at this instruction; observed {stray:#?}\n  {}",
                            derived.evidence
                        ));
                    }
                }
            }
        }
    }

    assert!(
        problems.is_empty(),
        "a conditional RK operand C with bit 8 set is a constant index bounded by the owning \
         prototype's constant table: the last index must be clean and the first index the \
         table does not have must be exactly one {CONST_C_CODE} for field C, never a \
         register diagnostic. {} of {cases} case(s) across {} RK-C opcode(s) and two owners \
         disagree:\n\n{}",
        problems.len(),
        driven.len(),
        problems.join("\n\n")
    );
}

// ---------------------------------------------------------------------------
// How public disassembly types `C`
// ---------------------------------------------------------------------------

/// Drives the pure operand comparator with synthetic observations: it accepts exactly the
/// published form each encoding requires and rejects the domain swaps, lost resolutions and
/// off-by-one indexes that would otherwise pass unnoticed.
fn assert_operand_comparator_is_live() {
    let register = CExpectation::Register { index: 3 };
    let resolved = CExpectation::Constant {
        value: 0x103,
        index: 3,
        resolved: true,
    };
    let unresolved = CExpectation::Constant {
        value: 0x104,
        index: 4,
        resolved: false,
    };
    let selection = |value: u64, index: Option<u64>| COperand::SelectedConstant {
        value,
        display: format!("K({})", value & 0xff),
        resolved: index,
    };

    for (label, expected, observed) in [
        (
            "a bit-8-clear operand published as that register",
            &register,
            COperand::Register {
                index: 3,
                resolved: false,
            },
        ),
        (
            "a resolvable selection published with its constant",
            &resolved,
            selection(0x103, Some(3)),
        ),
        (
            "an unresolvable selection published without one",
            &unresolved,
            selection(0x104, None),
        ),
    ] {
        assert!(
            judge_c_operand(expected, &observed).is_none(),
            "the comparator must accept the published form the RK rule requires: {label}"
        );
    }

    for (label, expected, observed) in [
        (
            "the register domain published as a constant selection",
            &register,
            selection(3, Some(3)),
        ),
        (
            "the constant domain published as a register, the selection bit dropped",
            &resolved,
            COperand::Register {
                index: 3,
                resolved: false,
            },
        ),
        (
            "a register carrying a resolved constant",
            &register,
            COperand::Register {
                index: 3,
                resolved: true,
            },
        ),
        (
            "a register at the neighbouring index",
            &register,
            COperand::Register {
                index: 4,
                resolved: false,
            },
        ),
        (
            "a selection that lost its resolved constant",
            &resolved,
            selection(0x103, None),
        ),
        (
            "a selection resolved to the neighbouring constant",
            &resolved,
            selection(0x103, Some(2)),
        ),
        (
            "an out-of-bounds selection resolved anyway",
            &unresolved,
            selection(0x104, Some(4)),
        ),
        (
            "a selection whose published value lost the selection bit",
            &resolved,
            selection(3, Some(3)),
        ),
        (
            "a selection displayed as a register",
            &resolved,
            COperand::SelectedConstant {
                value: 0x103,
                display: "R(3)".to_string(),
                resolved: Some(3),
            },
        ),
        (
            "no C operand published at all",
            &resolved,
            COperand::Other("the instruction publishes no operand named C".to_string()),
        ),
    ] {
        assert!(
            judge_c_operand(expected, &observed).is_some(),
            "the comparator must reject this killer: {label}"
        );
    }
}

#[test]
fn test_public_disasm_types_rk_c_by_bit_eight_with_resolved_constants() {
    audit_authority();
    assert_operand_comparator_is_live();

    let (base, base_hash, proto) = pinned_base();
    let file = NamedTempFile::new().expect("temporary chunk");
    let path = file.path();
    let total = proto.constants_len;

    // One probe per encoding the bit selects. The two valid indexes are driven so that the
    // resolved fact must track the driven index rather than being a fixed attachment; when
    // the pinned table holds a single constant they coincide and are driven once.
    let mut probes: Vec<(u16, CExpectation, bool)> = vec![(
        u16::from(proto.maxstacksize) - 1,
        CExpectation::Register {
            index: u64::from(proto.maxstacksize) - 1,
        },
        false,
    )];
    let mut valid_indexes = vec![0_usize, total - 1];
    valid_indexes.dedup();
    for index in valid_indexes.into_iter().chain(std::iter::once(total)) {
        let resolvable = index < total;
        let c = BIT_EIGHT | u16::try_from(index).expect("a selected index fits nine bits");
        probes.push((
            c,
            CExpectation::Constant {
                value: u64::from(c),
                index: index as u64,
                resolved: resolvable,
            },
            !resolvable,
        ));
    }

    let driven = rk_rows();
    let mut problems: Vec<String> = Vec::new();
    for entry in driven.iter() {
        let (op, name) = (entry.op, entry.name);
        for (c, expected, expect_disasm_diagnostic) in probes.iter() {
            let word = probe(op, *c, &proto);
            assert_eq!(
                field_c(word),
                *c,
                "{name}: the encoded word carries the driven C"
            );
            let derived = derive(
                &base,
                &base_hash,
                &proto,
                word,
                &format!(
                    "{name}.C={c} ({}) against maxstacksize={} and a constant table of {total}",
                    if c & BIT_EIGHT == 0 {
                        "bit 8 clear".to_string()
                    } else {
                        format!("bit 8 set, K({})", c & 0xff)
                    },
                    proto.maxstacksize
                ),
            );

            let instruction = match observed_instruction(&derived, &proto, op, name, path) {
                Ok(instruction) => instruction,
                Err(problem) => {
                    problems.push(problem);
                    continue;
                }
            };

            let observed_c = classify_c(&instruction);
            if let Some(reason) = judge_c_operand(expected, &observed_c) {
                problems.push(format!(
                    "{name}.C={c}: {reason}\n  {}\n  instruction={instruction}",
                    derived.evidence
                ));
            }

            // The disassembler's own diagnostic, read from the instruction it belongs to. An
            // unresolvable selection must carry exactly one; every resolvable operand, in
            // either domain, must carry none.
            let codes = instruction_codes(&instruction);
            let observed = codes
                .iter()
                .filter(|code| code.as_str() == DISASM_RK_CODE)
                .count();
            let wanted = usize::from(*expect_disasm_diagnostic);
            if observed != wanted {
                problems.push(format!(
                    "{name}.C={c}: expected {wanted} {DISASM_RK_CODE} on this instruction, \
                     observed {observed}\n  {}\n  instruction codes={codes:?}",
                    derived.evidence
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "public disassembly must type a conditional RK operand C by bit 8: a register with \
         no resolved constant when the bit is clear, and a visible constant selection when \
         it is set - resolved to the selected constant when the owning table has it, and \
         unresolved with exactly one {DISASM_RK_CODE} when it does not. {} of {} case(s) \
         across {} RK-C opcode(s) disagree:\n\n{}",
        problems.len(),
        driven.len() * probes.len(),
        driven.len(),
        problems.join("\n\n")
    );
}
