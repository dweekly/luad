//! Independent acceptance for the Lua 5.1 physical companion-word contract.
//!
//! This file covers the *physical-role* half of `docs/NEXT-SPRINT.md`: `SETLIST C == 0`
//! owns exactly one non-executable `setlist_extra` word, `CLOSURE` owns exactly its
//! child's declared binding descriptors, a claimed companion is never reconsidered as an
//! owner, and no companion word may create effects, branches, calls, or explanations.
//!
//! The chunk writer, instruction encoders, physical-role enumerator, control-transfer
//! model, and basic-block model below are test-local transcriptions of the PUC-Rio Lua
//! 5.1.5 chunk format and reference VM. They deliberately do not call luad's Lua 5.1
//! disassembly, lifter, validator, or role discovery to decide which PCs are executable;
//! production output is only ever *observed* and compared against this independent model.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Output};

use luad_analysis::{
    analyze_chunk_call_relations, analyze_chunk_callees,
    analyze_chunk_callees_with_mutation_budget, analyze_chunk_origins,
    analyze_chunk_prototype_identities, analyze_chunk_prototype_identities_v1,
    lift_proto_for_dialect, CallArgumentWindow, CallRelationResolution,
    CallRelationUnresolvedReason, CalleeResolution, CalleeUnresolvedReason, ControlFlowGraph,
    OriginExpressionKind, OriginUnknownReason, XrefIndex, XrefRelation,
    PROTOTYPE_IDENTITY_SCHEME_V1,
};
use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::model::Chunk;
use luad_core::reader::SafeReader;
use luad_core::{ImplicitEffect, OperandKind, SemanticInstruction, TypedOperand};
use serde_json::Value;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Independent Lua 5.1.5 opcode transcription.
// ---------------------------------------------------------------------------

const OP_MOVE: u8 = 0;
const OP_LOADK: u8 = 1;
const OP_LOADBOOL: u8 = 2;
const OP_LOADNIL: u8 = 3;
const OP_GETUPVAL: u8 = 4;
const OP_SETUPVAL: u8 = 8;
const OP_NEWTABLE: u8 = 10;
const OP_JMP: u8 = 22;
const OP_EQ: u8 = 23;
const OP_LT: u8 = 24;
const OP_LE: u8 = 25;
const OP_TEST: u8 = 26;
const OP_TESTSET: u8 = 27;
const OP_CALL: u8 = 28;
const OP_TAILCALL: u8 = 29;
const OP_RETURN: u8 = 30;
const OP_FORLOOP: u8 = 31;
const OP_FORPREP: u8 = 32;
const OP_TFORLOOP: u8 = 33;
const OP_SETLIST: u8 = 34;
const OP_CLOSURE: u8 = 36;
const OP_VARARG: u8 = 37;

/// The complete Lua 5.1.5 mnemonic set, in opcode order. A companion word must never be
/// rendered as one of these, because it is data rather than a program instruction.
const LUA51_MNEMONICS: [&str; 38] = [
    "MOVE",
    "LOADK",
    "LOADBOOL",
    "LOADNIL",
    "GETUPVAL",
    "GETGLOBAL",
    "GETTABLE",
    "SETGLOBAL",
    "SETUPVAL",
    "SETTABLE",
    "NEWTABLE",
    "SELF",
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "MOD",
    "POW",
    "UNM",
    "NOT",
    "LEN",
    "CONCAT",
    "JMP",
    "EQ",
    "LT",
    "LE",
    "TEST",
    "TESTSET",
    "CALL",
    "TAILCALL",
    "RETURN",
    "FORLOOP",
    "FORPREP",
    "TFORLOOP",
    "SETLIST",
    "CLOSE",
    "CLOSURE",
    "VARARG",
];

/// Physical role names published by the production disassembler.
const ROLE_INSTRUCTION: &str = "instruction";
const ROLE_CLOSURE_BINDING: &str = "closure_binding";
const ROLE_SETLIST_EXTRA: &str = "setlist_extra";

/// The current identity scheme demanded of recursive export for corrected companion
/// roles. Spelled locally on purpose: acceptance must not import a production constant
/// that does not exist yet.
const IDENTITY_SCHEME_V2: &str = "luad-prototype-v2";

/// The frozen `luad-prototype-v1` canonical vector for the pinned `hello` fixture.
const HELLO_V1_ROOT_DIGEST: &str =
    "sha256:c5c865906c6cb306ef43694f504a01a191e588a04f595b6c5c1ba964be27da29";
const HELLO_FIXTURE: &str = "tests/fixtures/precompiled/lua51/hello.luac";

const fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    (op as u32) | ((a as u32) << 6) | ((c as u32) << 14) | ((b as u32) << 23)
}

const fn iabx(op: u8, a: u8, bx: u32) -> u32 {
    (op as u32) | ((a as u32) << 6) | (bx << 14)
}

const fn iasbx(op: u8, a: u8, sbx: i32) -> u32 {
    // MAXARG_sBx = (2^18 - 1) / 2 in Lua 5.1.
    iabx(op, a, (sbx + 131_071) as u32)
}

const fn opcode_of(word: u32) -> u8 {
    (word & 0x3f) as u8
}

const fn field_a(word: u32) -> u8 {
    ((word >> 6) & 0xff) as u8
}

const fn field_b(word: u32) -> u16 {
    ((word >> 23) & 0x1ff) as u16
}

const fn field_c(word: u32) -> u16 {
    ((word >> 14) & 0x1ff) as u16
}

const fn field_bx(word: u32) -> u32 {
    (word >> 14) & 0x3ffff
}

fn field_sbx(word: u32) -> i32 {
    field_bx(word) as i32 - 131_071
}

// ---------------------------------------------------------------------------
// Independent physical-role enumerator.
// ---------------------------------------------------------------------------

/// The physical role of one raw word, decided only from the raw code vector and the
/// declared upvalue counts of the prototype's children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhysicalRole {
    /// The word is executed by the VM.
    Executable,
    /// The word is a `CLOSURE` upvalue binding descriptor.
    ClosureBinding { owner_pc: usize, slot: usize },
    /// The word is the raw list-batch operand of a `SETLIST` with `C == 0`.
    SetlistExtra { owner_pc: usize },
}

impl PhysicalRole {
    fn role_name(self) -> &'static str {
        match self {
            Self::Executable => ROLE_INSTRUCTION,
            Self::ClosureBinding { .. } => ROLE_CLOSURE_BINDING,
            Self::SetlistExtra { .. } => ROLE_SETLIST_EXTRA,
        }
    }

    fn owner_pc(self) -> Option<usize> {
        match self {
            Self::Executable => None,
            Self::ClosureBinding { owner_pc, .. } | Self::SetlistExtra { owner_pc } => {
                Some(owner_pc)
            }
        }
    }

    fn is_executable(self) -> bool {
        matches!(self, Self::Executable)
    }
}

/// How an executable word transfers control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TransferKind {
    /// `JMP`, `FORLOOP`, `FORPREP`: an sBx-relative destination.
    ExplicitJump,
    /// The `pc + 2` destination of a conditional-skip instruction.
    ConditionalSkip,
}

/// A physical-layout defect that the contract requires the validator to report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RoleFault {
    /// A companion range reaches past the end of the code vector.
    TruncatedCompanionRange {
        owner_pc: usize,
        declared: usize,
        available: usize,
    },
    /// An executable control transfer lands on a non-executable companion word.
    ControlTransferIntoCompanion {
        from_pc: usize,
        target_pc: usize,
        kind: TransferKind,
    },
}

impl RoleFault {
    /// The PC whose word is defective, and therefore the diagnostic target the public
    /// validator must name.
    fn target_pc(&self) -> usize {
        match self {
            Self::TruncatedCompanionRange { owner_pc, .. } => *owner_pc,
            Self::ControlTransferIntoCompanion { from_pc, .. } => *from_pc,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoleMap {
    roles: Vec<PhysicalRole>,
    faults: Vec<RoleFault>,
}

impl RoleMap {
    fn executable_pcs(&self) -> Vec<usize> {
        (0..self.roles.len())
            .filter(|pc| self.roles[*pc].is_executable())
            .collect()
    }

    fn next_executable(&self, after: usize) -> Option<usize> {
        (after + 1..self.roles.len()).find(|pc| self.roles[*pc].is_executable())
    }
}

/// How many companion words the word at `pc` declares, given the child upvalue counts.
fn declared_companions(word: u32, child_nups: &[usize]) -> usize {
    match opcode_of(word) {
        OP_CLOSURE => child_nups
            .get(field_bx(word) as usize)
            .copied()
            .unwrap_or(0),
        OP_SETLIST if field_c(word) == 0 => 1,
        _ => 0,
    }
}

/// The destinations an executable word transfers control to, per the reference VM.
fn transfer_targets(word: u32, pc: usize) -> Vec<(usize, TransferKind)> {
    let relative = |sbx: i32| -> Option<usize> {
        let target = pc as i64 + 1 + i64::from(sbx);
        (target >= 0).then_some(target as usize)
    };
    match opcode_of(word) {
        OP_JMP | OP_FORLOOP | OP_FORPREP => relative(field_sbx(word))
            .map(|target| vec![(target, TransferKind::ExplicitJump)])
            .unwrap_or_default(),
        // `if (...) then pc++`: the skipped word is `pc + 1`, so control resumes at
        // `pc + 2` without ever executing the intervening word.
        OP_EQ | OP_LT | OP_LE | OP_TEST | OP_TESTSET | OP_TFORLOOP => {
            vec![(pc + 2, TransferKind::ConditionalSkip)]
        }
        // `LOADBOOL A B C`: a non-zero C skips the following word.
        OP_LOADBOOL if field_c(word) != 0 => vec![(pc + 2, TransferKind::ConditionalSkip)],
        _ => Vec::new(),
    }
}

/// Enumerate physical roles with one forward pass in ascending physical-PC order. The
/// first unclaimed executable owner claims its complete companion range; a claimed word
/// is never reconsidered as an owner, whatever its opcode bits resemble.
fn enumerate_roles(words: &[u32], child_nups: &[usize]) -> RoleMap {
    enumerate_roles_with(words, child_nups, EnumeratorFlags::REFERENCE)
}

/// Switches used only by the killer-mutation harness, so that each seeded defect is a
/// single-flag departure from the reference enumerator above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EnumeratorFlags {
    /// Honour `SETLIST C == 0` companion ownership.
    setlist_extras: bool,
    /// Refuse to let an already-claimed companion own further companions.
    first_owner_precedence: bool,
    /// Report companion ranges that reach past the code vector.
    report_truncation: bool,
    /// Report explicit jumps into companions.
    report_jump_transfers: bool,
    /// Report conditional-skip transfers into companions.
    report_skip_transfers: bool,
}

impl EnumeratorFlags {
    const REFERENCE: Self = Self {
        setlist_extras: true,
        first_owner_precedence: true,
        report_truncation: true,
        report_jump_transfers: true,
        report_skip_transfers: true,
    };
}

fn enumerate_roles_with(words: &[u32], child_nups: &[usize], flags: EnumeratorFlags) -> RoleMap {
    let count = words.len();
    let mut claimed: Vec<Option<PhysicalRole>> = vec![None; count];
    let mut faults: Vec<RoleFault> = Vec::new();

    for pc in 0..count {
        if flags.first_owner_precedence && claimed[pc].is_some() {
            // Already a companion: it can never own companions of its own.
            continue;
        }
        if claimed[pc].is_none() {
            claimed[pc] = Some(PhysicalRole::Executable);
        }
        let word = words[pc];
        let mut declared = declared_companions(word, child_nups);
        if !flags.setlist_extras && opcode_of(word) == OP_SETLIST {
            declared = 0;
        }
        if declared == 0 {
            continue;
        }
        let available = declared.min(count.saturating_sub(pc + 1));
        if available < declared && flags.report_truncation {
            faults.push(RoleFault::TruncatedCompanionRange {
                owner_pc: pc,
                declared,
                available,
            });
        }
        for slot in 0..available {
            claimed[pc + 1 + slot] = Some(if opcode_of(word) == OP_CLOSURE {
                PhysicalRole::ClosureBinding { owner_pc: pc, slot }
            } else {
                PhysicalRole::SetlistExtra { owner_pc: pc }
            });
        }
    }

    let roles: Vec<PhysicalRole> = claimed
        .into_iter()
        .map(|role| role.unwrap_or(PhysicalRole::Executable))
        .collect();

    for pc in 0..count {
        if !roles[pc].is_executable() {
            continue;
        }
        for (target, kind) in transfer_targets(words[pc], pc) {
            let reported = match kind {
                TransferKind::ExplicitJump => flags.report_jump_transfers,
                TransferKind::ConditionalSkip => flags.report_skip_transfers,
            };
            if reported && target < count && !roles[target].is_executable() {
                faults.push(RoleFault::ControlTransferIntoCompanion {
                    from_pc: pc,
                    target_pc: target,
                    kind,
                });
            }
        }
    }

    faults.sort();
    RoleMap { roles, faults }
}

// ---------------------------------------------------------------------------
// Independent basic-block model.
// ---------------------------------------------------------------------------

/// The physically auditable block shape the contract requires: physical `start_pc` and
/// `end_pc` bounds, executable-only `instruction_pcs`, and edges from the last executable
/// PC in the block.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockShape {
    start_pc: usize,
    end_pc: usize,
    instruction_pcs: Vec<usize>,
    is_exit: bool,
    is_reachable: bool,
    successor_start_pcs: BTreeSet<usize>,
}

fn expected_block_shapes(words: &[u32], map: &RoleMap) -> Vec<BlockShape> {
    let count = words.len();
    if count == 0 {
        return Vec::new();
    }

    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(0);
    for (pc, word) in words.iter().copied().enumerate() {
        if !map.roles[pc].is_executable() {
            continue;
        }
        let targets = transfer_targets(word, pc);
        if !targets.is_empty() {
            for (target, _) in &targets {
                if *target < count {
                    leaders.insert(*target);
                }
            }
            if pc + 1 < count {
                leaders.insert(pc + 1);
            }
        }
        if opcode_of(word) == OP_RETURN && pc + 1 < count {
            leaders.insert(pc + 1);
        }
    }
    // Companions are never leaders: every leader above is derived from an executable
    // branch destination or from the word after an executable branch or return, and no
    // owner is a branch or a return.
    for leader in &leaders {
        assert!(
            map.roles[*leader].is_executable(),
            "independent model produced a companion leader at PC {leader}"
        );
    }

    let leader_list: Vec<usize> = leaders.iter().copied().collect();
    let mut shapes: Vec<BlockShape> = Vec::with_capacity(leader_list.len());
    for (index, start_pc) in leader_list.iter().copied().enumerate() {
        let end_pc = if index + 1 < leader_list.len() {
            leader_list[index + 1] - 1
        } else {
            count - 1
        };
        let instruction_pcs: Vec<usize> = (start_pc..=end_pc)
            .filter(|pc| map.roles[*pc].is_executable())
            .collect();
        let terminator = *instruction_pcs
            .last()
            .expect("every block starts at an executable leader");
        shapes.push(BlockShape {
            start_pc,
            end_pc,
            instruction_pcs,
            is_exit: opcode_of(words[terminator]) == OP_RETURN,
            is_reachable: false,
            successor_start_pcs: BTreeSet::new(),
        });
    }

    let start_to_block: BTreeMap<usize, usize> = shapes
        .iter()
        .enumerate()
        .map(|(index, shape)| (shape.start_pc, index))
        .collect();

    for shape in &mut shapes {
        let terminator = *shape.instruction_pcs.last().expect("non-empty block");
        let word = words[terminator];
        let mut successors: BTreeSet<usize> = BTreeSet::new();
        let opcode = opcode_of(word);
        let transfers = transfer_targets(word, terminator);
        let is_terminal = opcode == OP_RETURN || opcode == OP_TAILCALL;
        // `JMP` and `FORPREP` always transfer; they have no fallthrough successor.
        let is_unconditional_jump = opcode == OP_JMP || opcode == OP_FORPREP;
        for (target, _) in &transfers {
            if *target < count {
                successors.insert(*target);
            }
        }
        if !is_terminal && !is_unconditional_jump {
            if let Some(next) = map.next_executable(terminator) {
                successors.insert(next);
            }
        }
        shape.successor_start_pcs = successors;
    }

    // Successor PCs are block leaders by construction; map them to block starts.
    for shape in &mut shapes {
        let mapped: BTreeSet<usize> = shape
            .successor_start_pcs
            .iter()
            .map(|pc| {
                assert!(
                    start_to_block.contains_key(pc),
                    "independent successor PC {pc} is not a block leader"
                );
                *pc
            })
            .collect();
        shape.successor_start_pcs = mapped;
    }

    let mut reachable: BTreeSet<usize> = BTreeSet::new();
    let mut queue = vec![0usize];
    while let Some(index) = queue.pop() {
        if !reachable.insert(index) {
            continue;
        }
        let successors: Vec<usize> = shapes[index]
            .successor_start_pcs
            .iter()
            .map(|pc| start_to_block[pc])
            .collect();
        queue.extend(successors);
    }
    for (index, shape) in shapes.iter_mut().enumerate() {
        shape.is_reachable = reachable.contains(&index);
    }

    shapes
}

fn observed_block_shapes(cfg: &ControlFlowGraph) -> Vec<BlockShape> {
    cfg.blocks
        .iter()
        .map(|block| BlockShape {
            start_pc: block.start_pc,
            end_pc: block.end_pc,
            instruction_pcs: block.instruction_pcs.clone(),
            is_exit: block.is_exit,
            is_reachable: block.is_reachable,
            successor_start_pcs: block
                .successors
                .iter()
                .map(|edge| cfg.blocks[edge.to_block].start_pc)
                .collect(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Pure comparator over observed physical roles.
// ---------------------------------------------------------------------------

/// The production role facts this suite compares against the independent model.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedRole {
    role: String,
    companion_pc: Option<usize>,
}

/// Returns every way `observed` departs from the independently enumerated roles. An empty
/// result is the only accepting outcome.
fn role_mismatches(expected: &RoleMap, observed: &[ObservedRole]) -> Vec<String> {
    let mut mismatches = Vec::new();
    if expected.roles.len() != observed.len() {
        mismatches.push(format!(
            "word count {} but {} observed roles",
            expected.roles.len(),
            observed.len()
        ));
        return mismatches;
    }
    for (pc, role) in expected.roles.iter().enumerate() {
        let seen = &observed[pc];
        if seen.role != role.role_name() {
            mismatches.push(format!(
                "PC {pc}: expected role {} but observed {}",
                role.role_name(),
                seen.role
            ));
        }
        if let Some(owner) = role.owner_pc() {
            if seen.companion_pc != Some(owner) {
                mismatches.push(format!(
                    "PC {pc}: expected companion owner {owner} but observed {:?}",
                    seen.companion_pc
                ));
            }
        }
    }
    mismatches
}

fn observed_roles(proto: &luad_core::Prototype) -> Vec<ObservedRole> {
    luad_dialect_lua51::disassemble_proto_lua51(proto)
        .instructions
        .iter()
        .map(|instruction| ObservedRole {
            role: instruction.role.clone(),
            companion_pc: instruction.companion_pc,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Test-local Lua 5.1 chunk writer.
// ---------------------------------------------------------------------------

const PROBE_SOURCE: &str = "@semantic_safety_probe.lua";

/// A prototype to synthesize. `code` is written verbatim: no terminator is appended, so
/// truncated companion ranges at the end of a code vector are expressible.
#[derive(Debug, Clone)]
struct ProtoSpec {
    nups: u8,
    numparams: u8,
    is_vararg: u8,
    maxstacksize: u8,
    code: Vec<u32>,
    strings: Vec<&'static str>,
    children: Vec<ProtoSpec>,
}

impl ProtoSpec {
    fn root(maxstacksize: u8, code: Vec<u32>) -> Self {
        Self {
            nups: 0,
            numparams: 0,
            is_vararg: 2, // VARARG_ISVARARG
            maxstacksize,
            code,
            strings: vec!["probe"],
            children: Vec::new(),
        }
    }

    fn leaf_child(nups: u8) -> Self {
        Self::child(nups, vec![iabc(OP_RETURN, 0, 1, 0)])
    }

    fn child(nups: u8, code: Vec<u32>) -> Self {
        Self {
            nups,
            numparams: 0,
            is_vararg: 0,
            maxstacksize: 2,
            code,
            strings: Vec::new(),
            children: Vec::new(),
        }
    }

    fn with_child(mut self, child: ProtoSpec) -> Self {
        self.children.push(child);
        self
    }

    fn child_nups(&self) -> Vec<usize> {
        self.children
            .iter()
            .map(|child| usize::from(child.nups))
            .collect()
    }
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_string(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&((text.len() + 1) as u64).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

fn write_proto(out: &mut Vec<u8>, spec: &ProtoSpec) {
    write_string(out, PROBE_SOURCE);
    write_u32(out, 0); // linedefined
    write_u32(out, 0); // lastlinedefined
    out.push(spec.nups);
    out.push(spec.numparams);
    out.push(spec.is_vararg);
    out.push(spec.maxstacksize);
    write_u32(out, spec.code.len() as u32);
    for word in &spec.code {
        write_u32(out, *word);
    }
    write_u32(out, spec.strings.len() as u32);
    for text in &spec.strings {
        out.push(4); // LUA_TSTRING
        write_string(out, text);
    }
    write_u32(out, spec.children.len() as u32);
    for child in &spec.children {
        write_proto(out, child);
    }
    write_u32(out, 0); // lineinfo
    write_u32(out, 0); // locvars
    write_u32(out, 0); // upvalue names
}

/// Writes a complete little-endian 64-bit stock Lua 5.1 chunk around `root`.
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

fn parse_chunk(bytes: &[u8]) -> Chunk {
    let mut reader = SafeReader::new(bytes);
    luad_dialect_lua51::decode_chunk_lua51(&mut reader)
        .unwrap_or_else(|error| panic!("synthesized chunk must decode: {error:?}"))
}

fn temp_chunk(bytes: &[u8]) -> NamedTempFile {
    let file = NamedTempFile::new().expect("temporary chunk");
    std::fs::write(file.path(), bytes).expect("write synthesized chunk");
    file
}

fn workspace_root() -> PathBuf {
    luad_oracle::find_workspace_root()
}

// ---------------------------------------------------------------------------
// Public CLI helpers.
// ---------------------------------------------------------------------------

fn luad_bin() -> PathBuf {
    luad_oracle::luad_binary_path()
}

fn run_luad(args: &[&str]) -> Output {
    Command::new(luad_bin())
        .args(args)
        .output()
        .expect("run public luad CLI")
}

fn run_luad_ok(args: &[&str]) -> String {
    let output = run_luad(args);
    assert!(
        output.status.success(),
        "luad {args:?} failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn run_luad_json(args: &[&str]) -> Value {
    let stdout = run_luad_ok(args);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("luad {args:?} stdout is not JSON: {error}\n{stdout}"))
}

/// Runs `luad explain` for one instruction. The target is passed as a flag, falling back
/// to a positional argument if this build spells it that way; the fallback only concerns
/// how the tool is invoked, never what is asserted about its answer.
fn run_explain(path: &str, target: &str, format: &str) -> String {
    let flagged = run_luad(&["explain", path, "--target", target, "--format", format]);
    if flagged.status.success() {
        return String::from_utf8_lossy(&flagged.stdout).into_owned();
    }
    let positional = run_luad(&["explain", path, target, "--format", format]);
    assert!(
        positional.status.success(),
        "luad explain rejected both invocations for {target}: {} / {}",
        String::from_utf8_lossy(&flagged.stderr),
        String::from_utf8_lossy(&positional.stderr)
    );
    String::from_utf8_lossy(&positional.stdout).into_owned()
}

fn jsonl_records(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("JSONL record"))
        .collect()
}

/// Collects every JSON object that looks like a disassembled instruction record, without
/// depending on envelope field names.
fn collect_instruction_objects(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            if map.contains_key("pc") && map.contains_key("role") && map.contains_key("raw_word") {
                out.push(value.clone());
            }
            for nested in map.values() {
                collect_instruction_objects(nested, out);
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_instruction_objects(item, out)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Synthesized physical-word programs.
// ---------------------------------------------------------------------------

/// One opcode-shaped `setlist_extra` payload from the sprint matrix.
#[derive(Debug, Clone, Copy)]
struct ExtraShape {
    name: &'static str,
    resembles: &'static str,
    word: u32,
}

const EXTRA_SHAPES: [ExtraShape; 7] = [
    ExtraShape {
        name: "call-shaped",
        resembles: "CALL",
        word: iabc(OP_CALL, 0, 2, 1),
    },
    ExtraShape {
        name: "tailcall-shaped",
        resembles: "TAILCALL",
        word: iabc(OP_TAILCALL, 0, 2, 0),
    },
    ExtraShape {
        name: "jmp-shaped",
        resembles: "JMP",
        word: iasbx(OP_JMP, 0, -3),
    },
    ExtraShape {
        name: "return-shaped",
        resembles: "RETURN",
        word: iabc(OP_RETURN, 0, 1, 0),
    },
    ExtraShape {
        name: "closure-shaped",
        resembles: "CLOSURE",
        word: iabx(OP_CLOSURE, 0, 0),
    },
    ExtraShape {
        name: "setlist-shaped",
        resembles: "SETLIST",
        word: iabc(OP_SETLIST, 0, 1, 0),
    },
    ExtraShape {
        name: "unknown-opcode-shaped",
        resembles: "UNKNOWN_0x3e",
        word: 0x0000003e,
    },
];

/// PC of the owning `SETLIST` and of its extra word in [`extra_shape_root`].
const EXTRA_OWNER_PC: usize = 2;
const EXTRA_WORD_PC: usize = 3;

/// The shared physical-word program for the extra-value matrix.
///
/// ```text
/// 0  NEWTABLE R0 0 0
/// 1  LOADK    R1 K0
/// 2  SETLIST  R0 1 0   ; C == 0, owns exactly PC 3
/// 3  <opcode-shaped raw list-batch operand>
/// 4  LOADK    R1 K0    ; the real instruction after the extra word
/// 5  RETURN   R0 2
/// ```
///
/// The unused child prototype declares two upvalues, so a `CLOSURE`-shaped extra word
/// would consume PCs 4 and 5 as binding descriptors if it were ever treated as an owner.
fn extra_shape_root(extra: u32) -> ProtoSpec {
    ProtoSpec::root(
        2,
        vec![
            iabc(OP_NEWTABLE, 0, 0, 0),
            iabx(OP_LOADK, 1, 0),
            iabc(OP_SETLIST, 0, 1, 0),
            extra,
            iabx(OP_LOADK, 1, 0),
            iabc(OP_RETURN, 0, 2, 0),
        ],
    )
    .with_child(ProtoSpec::leaf_child(2))
}

/// A row of the companion-precedence and block-shape matrix.
struct ShapeRow {
    name: &'static str,
    root: ProtoSpec,
    /// The chunk is expected to carry no error diagnostics at all.
    expect_clean: bool,
    /// PCs that must never be named by any diagnostic, because they were never claimed.
    unclaimed_pcs: &'static [usize],
    /// A `SETLIST` whose `B == 0` open value window must survive companion handling.
    open_window_pc: Option<usize>,
}

fn shape_rows() -> Vec<ShapeRow> {
    vec![
        // A binding descriptor whose bits resemble `SETLIST C == 0` is already claimed by
        // its `CLOSURE`, so it must not consume the word after it.
        ShapeRow {
            name: "binding-descriptor-resembles-setlist-c0",
            root: ProtoSpec::root(
                2,
                vec![
                    iabx(OP_CLOSURE, 0, 0),
                    iabc(OP_SETLIST, 0, 1, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(1)),
            // The malformed descriptor is a pre-existing, separately owned finding.
            expect_clean: false,
            unclaimed_pcs: &[2],
            open_window_pc: None,
        },
        // `SETLIST A 0 0`: an open value window that still owns exactly one extra word.
        ShapeRow {
            name: "setlist-a-0-0-open-window",
            root: ProtoSpec::root(
                2,
                vec![
                    iabc(OP_NEWTABLE, 0, 0, 0),
                    iabc(OP_VARARG, 1, 0, 0),
                    iabc(OP_SETLIST, 0, 0, 0),
                    iabc(OP_CALL, 0, 2, 1),
                    iabc(OP_RETURN, 0, 2, 0),
                ],
            ),
            expect_clean: true,
            unclaimed_pcs: &[],
            open_window_pc: Some(2),
        },
        // Two owners in one prototype: a `CLOSURE` range followed by a `SETLIST` range,
        // where the second extra word resembles `CLOSURE` and must not cascade.
        ShapeRow {
            name: "consecutive-owners-no-cascade",
            root: ProtoSpec::root(
                2,
                vec![
                    iabx(OP_CLOSURE, 0, 0),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabc(OP_NEWTABLE, 0, 0, 0),
                    iabx(OP_LOADK, 1, 0),
                    iabc(OP_SETLIST, 0, 1, 0),
                    iabx(OP_CLOSURE, 0, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(1)),
            expect_clean: true,
            unclaimed_pcs: &[6],
            open_window_pc: None,
        },
        // A conditional skip that steps over the real instruction after a companion pair:
        // the containing block keeps physical bounds with noncontiguous executable PCs.
        ShapeRow {
            name: "conditional-skip-past-companion-pair",
            root: ProtoSpec::root(
                2,
                vec![
                    iabc(OP_NEWTABLE, 0, 0, 0),
                    iabx(OP_LOADK, 1, 0),
                    iabc(OP_SETLIST, 0, 1, 0),
                    iabc(OP_CALL, 0, 2, 1),
                    iabc(OP_LOADBOOL, 0, 0, 1),
                    iabx(OP_LOADK, 1, 0),
                    iabc(OP_RETURN, 0, 2, 0),
                ],
            ),
            expect_clean: true,
            unclaimed_pcs: &[],
            open_window_pc: None,
        },
    ]
}

/// A row of the companion-range and control-transfer validation matrix.
struct FaultRow {
    name: &'static str,
    root: ProtoSpec,
    fault: RoleFault,
    category: DiagnosticCategory,
}

fn fault_rows() -> Vec<FaultRow> {
    vec![
        FaultRow {
            name: "setlist-c0-range-past-code-vector",
            root: ProtoSpec::root(
                2,
                vec![
                    iabc(OP_NEWTABLE, 0, 0, 0),
                    iabx(OP_LOADK, 1, 0),
                    iabc(OP_SETLIST, 0, 1, 0),
                ],
            ),
            fault: RoleFault::TruncatedCompanionRange {
                owner_pc: 2,
                declared: 1,
                available: 0,
            },
            category: DiagnosticCategory::Instruction,
        },
        FaultRow {
            name: "closure-range-past-code-vector",
            root: ProtoSpec::root(2, vec![iabx(OP_CLOSURE, 0, 0), iabc(OP_MOVE, 0, 0, 0)])
                .with_child(ProtoSpec::leaf_child(2)),
            fault: RoleFault::TruncatedCompanionRange {
                owner_pc: 0,
                declared: 2,
                available: 1,
            },
            category: DiagnosticCategory::Instruction,
        },
        FaultRow {
            name: "explicit-jump-into-setlist-extra",
            root: ProtoSpec::root(
                2,
                vec![
                    iasbx(OP_JMP, 0, 3),
                    iabc(OP_NEWTABLE, 0, 0, 0),
                    iabx(OP_LOADK, 1, 0),
                    iabc(OP_SETLIST, 0, 1, 0),
                    iabc(OP_CALL, 0, 2, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            ),
            fault: RoleFault::ControlTransferIntoCompanion {
                from_pc: 0,
                target_pc: 4,
                kind: TransferKind::ExplicitJump,
            },
            category: DiagnosticCategory::ControlFlow,
        },
        FaultRow {
            name: "explicit-jump-into-closure-binding",
            root: ProtoSpec::root(
                2,
                vec![
                    iasbx(OP_JMP, 0, 1),
                    iabx(OP_CLOSURE, 0, 0),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(1)),
            fault: RoleFault::ControlTransferIntoCompanion {
                from_pc: 0,
                target_pc: 2,
                kind: TransferKind::ExplicitJump,
            },
            category: DiagnosticCategory::ControlFlow,
        },
        FaultRow {
            name: "comparison-skip-into-setlist-extra",
            root: ProtoSpec::root(
                2,
                vec![
                    iabc(OP_NEWTABLE, 0, 0, 0),
                    iabx(OP_LOADK, 1, 0),
                    iabc(OP_EQ, 0, 0, 0),
                    iabc(OP_SETLIST, 0, 1, 0),
                    iabc(OP_CALL, 0, 2, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            ),
            fault: RoleFault::ControlTransferIntoCompanion {
                from_pc: 2,
                target_pc: 4,
                kind: TransferKind::ConditionalSkip,
            },
            category: DiagnosticCategory::ControlFlow,
        },
        FaultRow {
            name: "loadbool-skip-into-closure-binding",
            root: ProtoSpec::root(
                2,
                vec![
                    iabc(OP_LOADBOOL, 0, 0, 1),
                    iabx(OP_CLOSURE, 0, 0),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(1)),
            fault: RoleFault::ControlTransferIntoCompanion {
                from_pc: 0,
                target_pc: 2,
                kind: TransferKind::ConditionalSkip,
            },
            category: DiagnosticCategory::ControlFlow,
        },
    ]
}

// ---------------------------------------------------------------------------
// Shared assertions.
// ---------------------------------------------------------------------------

fn error_diagnostics(chunk: &Chunk) -> Vec<&Diagnostic> {
    chunk
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == Severity::Error)
        .collect()
}

/// Asserts that the production roles for `root` agree with the independent enumeration,
/// and returns the independently enumerated map for further checks.
fn assert_roles_agree(label: &str, root: &ProtoSpec, chunk: &Chunk) -> RoleMap {
    let expected = enumerate_roles(&root.code, &root.child_nups());
    let observed = observed_roles(&chunk.main_proto);
    let mismatches = role_mismatches(&expected, &observed);
    assert!(
        mismatches.is_empty(),
        "{label}: physical roles disagree with the independent enumeration: {mismatches:?}\n\
         expected={:?}\nobserved={observed:?}",
        expected.roles
    );
    expected
}

fn assert_companion_is_inert(
    label: &str,
    lifted: &SemanticInstruction,
    owner_pc: usize,
    word: u32,
) {
    assert!(
        lifted.reads.is_empty(),
        "{label}: companion word must have no executable reads: {:?}",
        lifted.reads
    );
    assert!(
        lifted.writes.is_empty(),
        "{label}: companion word must have no executable writes: {:?}",
        lifted.writes
    );
    assert_eq!(
        lifted.jump_target, None,
        "{label}: companion word must have no jump target"
    );
    assert!(
        lifted.metamethod_fallbacks.is_empty(),
        "{label}: companion word must have no metamethod fallbacks: {:?}",
        lifted.metamethod_fallbacks
    );
    assert!(
        !lifted.implicit_effects.iter().any(|effect| matches!(
            effect,
            ImplicitEffect::ConditionalSkip { .. }
                | ImplicitEffect::SetStackTop { .. }
                | ImplicitEffect::Multireturn { .. }
                | ImplicitEffect::CloseUpvalues { .. }
                | ImplicitEffect::CaptureUpvalue { .. }
        )),
        "{label}: companion word must have no executable implicit effects: {:?}",
        lifted.implicit_effects
    );
    assert_eq!(
        lifted.companion_pc,
        Some(owner_pc),
        "{label}: companion word must link to its owner"
    );
    assert!(
        lifted.implicit_effects.iter().any(
            |effect| matches!(effect, ImplicitEffect::CompanionPair { companion_pc, companion_role }
                if *companion_pc == owner_pc && companion_role == ROLE_SETLIST_EXTRA)
        ),
        "{label}: companion word must carry a setlist_extra companion pair to PC {owner_pc}: {:?}",
        lifted.implicit_effects
    );
    assert!(
        lifted
            .operands
            .iter()
            .any(|operand| matches!(operand, TypedOperand::ExtraArg { value } if *value == word)),
        "{label}: companion word must expose its complete raw value as data: {:?}",
        lifted.operands
    );
    assert!(
        !LUA51_MNEMONICS.contains(&lifted.mnemonic.as_str()),
        "{label}: companion word must not carry a standalone opcode mnemonic, got {:?}",
        lifted.mnemonic
    );
}

// ---------------------------------------------------------------------------
// 1. The independent enumerator, comparator, and their killers.
// ---------------------------------------------------------------------------

#[test]
fn test_physical_role_enumerator_and_comparator_reject_killer_mutations() {
    // A corpus that exercises every claim rule at once, with the roles stated by hand.
    struct Case {
        name: &'static str,
        words: Vec<u32>,
        child_nups: Vec<usize>,
        roles: Vec<PhysicalRole>,
        faults: Vec<RoleFault>,
    }

    let cases = vec![
        Case {
            name: "setlist c0 owns exactly one word",
            words: vec![
                iabc(OP_NEWTABLE, 0, 0, 0),
                iabc(OP_SETLIST, 0, 1, 0),
                iabc(OP_CALL, 0, 2, 1),
                iabc(OP_RETURN, 0, 1, 0),
            ],
            child_nups: vec![],
            roles: vec![
                PhysicalRole::Executable,
                PhysicalRole::Executable,
                PhysicalRole::SetlistExtra { owner_pc: 1 },
                PhysicalRole::Executable,
            ],
            faults: vec![],
        },
        Case {
            name: "setlist c non-zero owns nothing",
            words: vec![
                iabc(OP_SETLIST, 0, 1, 1),
                iabc(OP_CALL, 0, 2, 1),
                iabc(OP_RETURN, 0, 1, 0),
            ],
            child_nups: vec![],
            roles: vec![
                PhysicalRole::Executable,
                PhysicalRole::Executable,
                PhysicalRole::Executable,
            ],
            faults: vec![],
        },
        Case {
            name: "claimed companion never owns companions",
            words: vec![
                iabx(OP_CLOSURE, 0, 0),
                iabc(OP_SETLIST, 0, 1, 0),
                iabc(OP_RETURN, 0, 1, 0),
            ],
            child_nups: vec![1],
            roles: vec![
                PhysicalRole::Executable,
                PhysicalRole::ClosureBinding {
                    owner_pc: 0,
                    slot: 0,
                },
                PhysicalRole::Executable,
            ],
            faults: vec![],
        },
        Case {
            name: "setlist extra resembling closure does not cascade",
            words: vec![
                iabc(OP_SETLIST, 0, 1, 0),
                iabx(OP_CLOSURE, 0, 0),
                iabc(OP_MOVE, 0, 0, 0),
                iabc(OP_RETURN, 0, 1, 0),
            ],
            child_nups: vec![2],
            roles: vec![
                PhysicalRole::Executable,
                PhysicalRole::SetlistExtra { owner_pc: 0 },
                PhysicalRole::Executable,
                PhysicalRole::Executable,
            ],
            faults: vec![],
        },
        Case {
            name: "closure owns exactly the declared descriptor count",
            words: vec![
                iabx(OP_CLOSURE, 0, 0),
                iabc(OP_MOVE, 0, 0, 0),
                iabc(OP_MOVE, 0, 1, 0),
                iabc(OP_RETURN, 0, 1, 0),
            ],
            child_nups: vec![2],
            roles: vec![
                PhysicalRole::Executable,
                PhysicalRole::ClosureBinding {
                    owner_pc: 0,
                    slot: 0,
                },
                PhysicalRole::ClosureBinding {
                    owner_pc: 0,
                    slot: 1,
                },
                PhysicalRole::Executable,
            ],
            faults: vec![],
        },
        Case {
            name: "truncated setlist range",
            words: vec![iabc(OP_NEWTABLE, 0, 0, 0), iabc(OP_SETLIST, 0, 1, 0)],
            child_nups: vec![],
            roles: vec![PhysicalRole::Executable, PhysicalRole::Executable],
            faults: vec![RoleFault::TruncatedCompanionRange {
                owner_pc: 1,
                declared: 1,
                available: 0,
            }],
        },
        Case {
            name: "explicit jump into a setlist extra",
            words: vec![
                // Lua 5.1 jumps to `pc + 1 + sBx`, so sBx = 1 targets PC 2.
                iasbx(OP_JMP, 0, 1),
                iabc(OP_SETLIST, 0, 1, 0),
                iabc(OP_CALL, 0, 2, 1),
                iabc(OP_RETURN, 0, 1, 0),
            ],
            child_nups: vec![],
            roles: vec![
                PhysicalRole::Executable,
                PhysicalRole::Executable,
                PhysicalRole::SetlistExtra { owner_pc: 1 },
                PhysicalRole::Executable,
            ],
            faults: vec![RoleFault::ControlTransferIntoCompanion {
                from_pc: 0,
                target_pc: 2,
                kind: TransferKind::ExplicitJump,
            }],
        },
        Case {
            name: "conditional skip into a closure binding",
            words: vec![
                iabc(OP_LOADBOOL, 0, 0, 1),
                iabx(OP_CLOSURE, 0, 0),
                iabc(OP_MOVE, 0, 0, 0),
                iabc(OP_RETURN, 0, 1, 0),
            ],
            child_nups: vec![1],
            roles: vec![
                PhysicalRole::Executable,
                PhysicalRole::Executable,
                PhysicalRole::ClosureBinding {
                    owner_pc: 1,
                    slot: 0,
                },
                PhysicalRole::Executable,
            ],
            faults: vec![RoleFault::ControlTransferIntoCompanion {
                from_pc: 0,
                target_pc: 2,
                kind: TransferKind::ConditionalSkip,
            }],
        },
    ];

    for case in &cases {
        let map = enumerate_roles(&case.words, &case.child_nups);
        assert_eq!(map.roles, case.roles, "roles for '{}'", case.name);
        assert_eq!(map.faults, case.faults, "faults for '{}'", case.name);
    }

    // Killer mutations of the enumerator itself: every seeded defect must change the
    // enumeration of at least one corpus case, so no rule above is inert.
    let mutants: [(&str, EnumeratorFlags); 5] = [
        (
            "dropped SETLIST C == 0 ownership",
            EnumeratorFlags {
                setlist_extras: false,
                ..EnumeratorFlags::REFERENCE
            },
        ),
        (
            "companion data allowed to own companions",
            EnumeratorFlags {
                first_owner_precedence: false,
                ..EnumeratorFlags::REFERENCE
            },
        ),
        (
            "dropped truncated-range detection",
            EnumeratorFlags {
                report_truncation: false,
                ..EnumeratorFlags::REFERENCE
            },
        ),
        (
            "dropped explicit-jump transfer detection",
            EnumeratorFlags {
                report_jump_transfers: false,
                ..EnumeratorFlags::REFERENCE
            },
        ),
        (
            "dropped conditional-skip transfer detection",
            EnumeratorFlags {
                report_skip_transfers: false,
                ..EnumeratorFlags::REFERENCE
            },
        ),
    ];
    for (name, flags) in mutants {
        let differs = cases.iter().any(|case| {
            let mutated = enumerate_roles_with(&case.words, &case.child_nups, flags);
            mutated.roles != case.roles || mutated.faults != case.faults
        });
        assert!(differs, "enumerator killer mutation survived: {name}");
    }

    // Killer mutations of the comparator: every plausible production defect must be
    // reported, and the clean observation must be accepted.
    let reference = &cases[0];
    let expected = enumerate_roles(&reference.words, &reference.child_nups);
    let clean: Vec<ObservedRole> = expected
        .roles
        .iter()
        .map(|role| ObservedRole {
            role: role.role_name().to_string(),
            companion_pc: role.owner_pc(),
        })
        .collect();
    assert!(
        role_mismatches(&expected, &clean).is_empty(),
        "the comparator must accept a faithful observation"
    );

    let mut executed = clean.clone();
    executed[2].role = ROLE_INSTRUCTION.to_string();
    executed[2].companion_pc = None;

    let mut wrong_role = clean.clone();
    wrong_role[2].role = ROLE_CLOSURE_BINDING.to_string();

    let mut unlinked = clean.clone();
    unlinked[2].companion_pc = None;

    let mut misowned = clean.clone();
    misowned[2].companion_pc = Some(0);

    let mut swallowed = clean.clone();
    swallowed.pop();

    let mut shifted = clean.clone();
    shifted.swap(1, 2);

    for (name, observation) in [
        ("extra word executed as an instruction", executed),
        ("extra word retyped as a closure binding", wrong_role),
        ("extra word not linked to its owner", unlinked),
        ("extra word attributed to the wrong owner", misowned),
        ("companion range swallowed a real word", swallowed),
        ("owner and companion transposed", shifted),
    ] {
        assert!(
            !role_mismatches(&expected, &observation).is_empty(),
            "comparator killer mutation survived: {name}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Opcode-shaped extra words are data, not program.
// ---------------------------------------------------------------------------

#[test]
fn test_setlist_extra_matrix_is_data_not_program() {
    for shape in EXTRA_SHAPES {
        let label = shape.name;
        let root = extra_shape_root(shape.word);
        let bytes = build_chunk(&root);
        let chunk = parse_chunk(&bytes);

        let map = assert_roles_agree(label, &root, &chunk);
        assert!(
            map.faults.is_empty(),
            "{label}: this program is physically well formed: {:?}",
            map.faults
        );
        assert_eq!(
            map.roles[EXTRA_WORD_PC],
            PhysicalRole::SetlistExtra {
                owner_pc: EXTRA_OWNER_PC
            },
            "{label}: the extra word is owned by the SETLIST at PC {EXTRA_OWNER_PC}"
        );

        // Exactly one companion word, at the expected physical PC, with its raw bytes and
        // physical location preserved.
        let disassembly = luad_dialect_lua51::disassemble_proto_lua51(&chunk.main_proto);
        let extras: Vec<usize> = disassembly
            .instructions
            .iter()
            .filter(|instruction| instruction.role == ROLE_SETLIST_EXTRA)
            .map(|instruction| instruction.pc)
            .collect();
        assert_eq!(
            extras,
            vec![EXTRA_WORD_PC],
            "{label}: exactly one setlist_extra role at PC {EXTRA_WORD_PC}"
        );
        let extra_instruction = &disassembly.instructions[EXTRA_WORD_PC];
        assert_eq!(extra_instruction.raw_word, shape.word, "{label}: raw word");
        assert_eq!(
            extra_instruction.raw_hex,
            format!("0x{:08x}", shape.word),
            "{label}: numeric raw word"
        );
        assert_eq!(
            extra_instruction.companion_pc,
            Some(EXTRA_OWNER_PC),
            "{label}: owner link"
        );
        assert!(
            !LUA51_MNEMONICS.contains(&extra_instruction.mnemonic.as_str()),
            "{label}: rendered as the ordinary mnemonic {:?} for {}",
            extra_instruction.mnemonic,
            shape.resembles
        );
        assert!(
            extra_instruction.operands.iter().any(|operand| matches!(
                operand.kind,
                OperandKind::Raw { value } | OperandKind::ImmediateUnsigned { value }
                    if value == u64::from(shape.word)
            )),
            "{label}: the complete raw u32 must be exposed as data: {:?}",
            extra_instruction.operands
        );
        assert!(
            !extra_instruction
                .operands
                .iter()
                .any(|operand| matches!(operand.kind, OperandKind::Register { .. })),
            "{label}: a data word has no register operands: {:?}",
            extra_instruction.operands
        );

        let word_source = &chunk.main_proto.instructions[EXTRA_WORD_PC].source;
        assert_eq!(
            (word_source.byte_offset, word_source.byte_length),
            (root_code_offset() + EXTRA_WORD_PC * 4, 4),
            "{label}: physical byte span preserved"
        );

        // The lifted companion has no executable behaviour at all.
        let lifted = lift_proto_for_dialect(&chunk.dialect, &chunk.main_proto);
        assert_companion_is_inert(label, &lifted[EXTRA_WORD_PC], EXTRA_OWNER_PC, shape.word);

        // The real instruction after the extra word still executes normally.
        assert_eq!(
            disassembly.instructions[4].role, ROLE_INSTRUCTION,
            "{label}: PC 4 remains executable"
        );
        assert_eq!(
            disassembly.instructions[4].mnemonic, "LOADK",
            "{label}: PC 4 keeps its own opcode"
        );

        // A physically well-formed companion program is valid.
        assert_eq!(
            chunk.verdict,
            Verdict::ValidForParser,
            "{label}: companion data must not invent a validation failure: {:?}",
            error_diagnostics(&chunk)
        );

        // No invented leader, successor, exit, or unreachable region.
        let cfg = ControlFlowGraph::build(&chunk.main_proto, &lifted);
        assert_eq!(
            observed_block_shapes(&cfg),
            expected_block_shapes(&root.code, &map),
            "{label}: control-flow shape disagrees with the independent model"
        );

        // No invented call, origin, relation, or cross-reference.
        let callees = analyze_chunk_callees(&chunk);
        let call_facts: usize = callees
            .prototypes
            .iter()
            .map(|prototype| prototype.calls.len())
            .sum();
        assert_eq!(
            call_facts, 0,
            "{label}: companion data must not create callee facts"
        );
        let origins = analyze_chunk_origins(&chunk);
        let origin_facts: usize = origins
            .prototypes
            .iter()
            .map(|prototype| prototype.calls.len())
            .sum();
        assert_eq!(
            origin_facts, 0,
            "{label}: companion data must not create origin facts"
        );
        let relations = analyze_chunk_call_relations(&chunk);
        let relation_facts: usize = relations
            .prototypes
            .iter()
            .map(|prototype| prototype.calls.len())
            .sum();
        assert_eq!(
            relation_facts, 0,
            "{label}: companion data must not create call relations"
        );

        let xrefs = XrefIndex::build(&chunk);
        let from_extra: Vec<String> = xrefs
            .entries
            .iter()
            .filter(|entry| entry.source.to_string() == "proto:0:pc:3")
            .map(|entry| format!("{:?} -> {}", entry.relation, entry.target))
            .collect();
        assert!(
            from_extra.is_empty(),
            "{label}: companion data must not source cross-references: {from_extra:?}"
        );
        assert!(
            !xrefs
                .entries
                .iter()
                .any(|entry| entry.relation == XrefRelation::Calls),
            "{label}: companion data must not produce a calls xref"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. First-owner precedence, open windows, and block shape.
// ---------------------------------------------------------------------------

#[test]
fn test_companion_precedence_open_window_and_block_shape_matrix() {
    for row in shape_rows() {
        let label = row.name;
        let bytes = build_chunk(&row.root);
        let chunk = parse_chunk(&bytes);

        let map = assert_roles_agree(label, &row.root, &chunk);
        assert!(
            map.faults.is_empty(),
            "{label}: this program is physically well formed: {:?}",
            map.faults
        );

        let lifted = lift_proto_for_dialect(&chunk.dialect, &chunk.main_proto);
        let cfg = ControlFlowGraph::build(&chunk.main_proto, &lifted);
        assert_eq!(
            observed_block_shapes(&cfg),
            expected_block_shapes(&row.root.code, &map),
            "{label}: control-flow shape disagrees with the independent model"
        );

        // Reachability and dataflow operate only on executable instructions.
        let block_pcs: Vec<usize> = cfg
            .blocks
            .iter()
            .flat_map(|block| block.instruction_pcs.clone())
            .collect();
        assert_eq!(
            block_pcs,
            map.executable_pcs(),
            "{label}: blocks must enumerate exactly the executable PCs, in order"
        );
        for block in &cfg.blocks {
            assert!(
                map.roles[block.start_pc].is_executable(),
                "{label}: PC {} is a companion and must never lead a block",
                block.start_pc
            );
        }

        if row.expect_clean {
            assert_eq!(
                chunk.verdict,
                Verdict::ValidForParser,
                "{label}: expected a clean chunk, got {:?}",
                error_diagnostics(&chunk)
            );
        }
        for pc in row.unclaimed_pcs {
            let target = format!("proto:0:pc:{pc}");
            assert!(
                !chunk
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.target.to_string() == target),
                "{label}: PC {pc} was never claimed as a companion and must not be reported: {:?}",
                chunk.diagnostics
            );
            assert!(
                map.roles[*pc].is_executable(),
                "{label}: PC {pc} must remain executable"
            );
        }

        if let Some(pc) = row.open_window_pc {
            // `SETLIST A 0 0` keeps its open value window while owning exactly one word.
            assert!(
                lifted[pc].operands.iter().any(|operand| matches!(
                    operand,
                    TypedOperand::Count {
                        value: 0,
                        is_variable: true
                    }
                )),
                "{label}: SETLIST B == 0 must remain an open value window: {:?}",
                lifted[pc].operands
            );
            let owned: Vec<usize> = (0..map.roles.len())
                .filter(|candidate| map.roles[*candidate].owner_pc() == Some(pc))
                .collect();
            assert_eq!(
                owned,
                vec![pc + 1],
                "{label}: SETLIST A 0 0 owns exactly one extra word"
            );
            assert_companion_is_inert(label, &lifted[pc + 1], pc, row.root.code[pc + 1]);
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Companion-range and control-transfer validation.
// ---------------------------------------------------------------------------

#[test]
fn test_companion_range_and_control_transfer_validation_matrix() {
    let mut transfer_codes: BTreeSet<String> = BTreeSet::new();

    for row in fault_rows() {
        let label = row.name;
        let bytes = build_chunk(&row.root);
        let chunk = parse_chunk(&bytes);

        // The independent model names exactly the expected defect.
        let map = enumerate_roles(&row.root.code, &row.root.child_nups());
        assert_eq!(
            map.faults,
            vec![row.fault.clone()],
            "{label}: independent fault enumeration"
        );

        assert_eq!(
            chunk.verdict,
            Verdict::Invalid,
            "{label}: a companion defect must fail validation; diagnostics={:?}",
            chunk.diagnostics
        );

        let target = format!("proto:0:pc:{}", row.fault.target_pc());
        let matching: Vec<&Diagnostic> = error_diagnostics(&chunk)
            .into_iter()
            .filter(|diagnostic| diagnostic.target.to_string() == target)
            .collect();
        assert!(
            !matching.is_empty(),
            "{label}: expected an error naming {target}, got {:?}",
            chunk.diagnostics
        );
        let diagnostic = matching[0];
        assert_eq!(
            diagnostic.category, row.category,
            "{label}: diagnostic category for {target}"
        );
        // The contract fixes the rule, not a spelling: require a code that is registered
        // in the public catalog rather than inventing one here.
        assert!(
            luad_core::lookup_diagnostic(&diagnostic.code).is_some(),
            "{label}: diagnostic code {:?} must be published in the diagnostic catalog",
            diagnostic.code
        );
        let source = diagnostic
            .source
            .as_ref()
            .unwrap_or_else(|| panic!("{label}: diagnostic must cite the offending word"));
        let offending_pc = row.fault.target_pc();
        assert_eq!(
            (
                source.byte_offset,
                source.byte_length,
                source.raw_hex.as_str()
            ),
            (
                root_code_offset() + offending_pc * 4,
                4,
                hex::encode(row.root.code[offending_pc].to_le_bytes()).as_str()
            ),
            "{label}: diagnostic must cite the exact physical word"
        );

        // Stability: the same input must produce the same finding on re-validation.
        let repeated = parse_chunk(&bytes);
        let repeated_codes: Vec<&str> = error_diagnostics(&repeated)
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        let first_codes: Vec<&str> = error_diagnostics(&chunk)
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        assert_eq!(
            repeated_codes, first_codes,
            "{label}: companion diagnostics must be deterministic"
        );

        if matches!(row.fault, RoleFault::ControlTransferIntoCompanion { .. }) {
            transfer_codes.insert(diagnostic.code.clone());
        }
    }

    assert_eq!(
        transfer_codes.len(),
        1,
        "one rule forbids executable control transfer into a companion, so one stable \
         diagnostic code must cover explicit jumps and conditional skips alike: \
         {transfer_codes:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. Public surfaces agree on the same physical role.
// ---------------------------------------------------------------------------

#[test]
fn test_public_companion_surfaces_agree_matrix() {
    let shape = EXTRA_SHAPES[0];
    let root = extra_shape_root(shape.word);
    let bytes = build_chunk(&root);
    let file = temp_chunk(&bytes);
    let path = file.path().to_str().expect("UTF-8 path").to_string();
    let map = enumerate_roles(&root.code, &root.child_nups());
    let expected_executable = map.executable_pcs();
    let extra_target = format!("proto:0:pc:{EXTRA_WORD_PC}");

    for surface in [
        "disasm-json",
        "disasm-jsonl",
        "text",
        "explain",
        "cfg",
        "export",
    ] {
        match surface {
            "disasm-json" | "disasm-jsonl" => {
                let format = if surface == "disasm-json" {
                    "json"
                } else {
                    "jsonl"
                };
                let stdout =
                    run_luad_ok(&["disasm", &path, "--dialect", "lua5.1", "--format", format]);
                let documents: Vec<Value> = if format == "json" {
                    vec![serde_json::from_str(&stdout).expect("disasm JSON")]
                } else {
                    jsonl_records(&stdout)
                };
                let mut instructions = Vec::new();
                for document in &documents {
                    collect_instruction_objects(document, &mut instructions);
                }
                let root_instructions: Vec<&Value> = instructions
                    .iter()
                    .filter(|instruction| {
                        instruction["id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with("proto:0:pc:"))
                    })
                    .collect();
                assert_eq!(
                    root_instructions.len(),
                    root.code.len(),
                    "{surface}: one record per physical word"
                );
                let extra = root_instructions
                    .iter()
                    .find(|instruction| instruction["pc"].as_u64() == Some(EXTRA_WORD_PC as u64))
                    .unwrap_or_else(|| panic!("{surface}: no record for PC {EXTRA_WORD_PC}"));
                assert_eq!(
                    extra["role"].as_str(),
                    Some(ROLE_SETLIST_EXTRA),
                    "{surface}: role for the extra word"
                );
                assert_eq!(
                    extra["companion_pc"].as_u64(),
                    Some(EXTRA_OWNER_PC as u64),
                    "{surface}: owner link for the extra word"
                );
                assert_eq!(
                    extra["raw_word"].as_u64(),
                    Some(u64::from(shape.word)),
                    "{surface}: raw word preserved"
                );
            }
            "text" => {
                let stdout =
                    run_luad_ok(&["disasm", &path, "--dialect", "lua5.1", "--format", "text"]);
                let pc_token = EXTRA_WORD_PC.to_string();
                let line = stdout
                    .lines()
                    .find(|line| line.split_whitespace().next() == Some(pc_token.as_str()))
                    .unwrap_or_else(|| {
                        panic!("text disassembly must list PC {EXTRA_WORD_PC}:\n{stdout}")
                    })
                    .to_string();
                let mnemonic_token = line
                    .split_whitespace()
                    .find(|token| LUA51_MNEMONICS.contains(token));
                assert_eq!(
                    mnemonic_token, None,
                    "text: the extra word must render as a data continuation, not an \
                     ordinary mnemonic: {line:?}"
                );
                let decimal = shape.word.to_string();
                let hex_form = format!("0x{:08x}", shape.word);
                assert!(
                    line.contains(&decimal) || line.contains(&hex_form),
                    "text: the extra word must render its raw list-batch value: {line:?}"
                );
                assert!(
                    stdout.lines().any(|line| {
                        line.split_whitespace().next() == Some("4") && line.contains("LOADK")
                    }),
                    "text: the real instruction after the extra word must still render:\n{stdout}"
                );
            }
            "explain" => {
                let json = run_explain(&path, &extra_target, "json");
                let explained: Value =
                    serde_json::from_str(&json).expect("explain JSON is a semantic instruction");
                assert_eq!(
                    explained["companion_pc"].as_u64(),
                    Some(EXTRA_OWNER_PC as u64),
                    "explain: must identify the owning SETLIST"
                );
                assert_eq!(
                    explained["writes"].as_array().map(Vec::len).unwrap_or(0),
                    0,
                    "explain: a companion word writes nothing"
                );
                assert_eq!(
                    explained["reads"].as_array().map(Vec::len).unwrap_or(0),
                    0,
                    "explain: a companion word reads nothing"
                );
                assert!(
                    explained["jump_target"].is_null(),
                    "explain: a companion word has no jump target"
                );
                let text = run_explain(&path, &extra_target, "text");
                assert!(
                    text.contains(ROLE_SETLIST_EXTRA),
                    "explain: text must name the non-executable role:\n{text}"
                );
            }
            "cfg" => {
                let document =
                    run_luad_json(&["cfg", &path, "--dialect", "lua5.1", "--format", "json"]);
                let mut blocks = Vec::new();
                collect_cfg_blocks(&document, &mut blocks);
                assert!(!blocks.is_empty(), "cfg: no blocks emitted");
                let listed: Vec<usize> = blocks
                    .iter()
                    .flat_map(|block| {
                        block["instruction_pcs"]
                            .as_array()
                            .expect("instruction_pcs")
                            .iter()
                            .map(|pc| pc.as_u64().expect("pc") as usize)
                            .collect::<Vec<_>>()
                    })
                    .collect();
                assert_eq!(
                    listed, expected_executable,
                    "cfg: instruction_pcs must contain executable PCs only"
                );
                assert!(
                    blocks
                        .iter()
                        .all(|block| { block["start_pc"].as_u64() != Some(EXTRA_WORD_PC as u64) }),
                    "cfg: a companion word must never be a block leader"
                );
            }
            "export" => {
                let stdout = run_luad_ok(&["export", &path, "--format", "jsonl"]);
                let records = jsonl_records(&stdout);
                for kind in ["callee", "origin", "call_relation"] {
                    assert!(
                        !records.iter().any(|record| record["record_type"] == kind),
                        "export: companion data must not produce {kind} records"
                    );
                }
                assert!(
                    !records.iter().any(|record| {
                        record["record_type"] == "xref" && record["data"]["relation"] == "calls"
                    }),
                    "export: companion data must not produce a calls xref"
                );
                let instruction = records
                    .iter()
                    .filter(|record| record["record_type"] == "instruction")
                    .find(|record| record["data"]["id"].as_str() == Some(extra_target.as_str()))
                    .unwrap_or_else(|| panic!("export: no instruction record for {extra_target}"));
                assert_eq!(
                    instruction["data"]["role"].as_str(),
                    Some(ROLE_SETLIST_EXTRA),
                    "export: recursive export must agree on the physical role"
                );
            }
            other => panic!("unhandled surface {other}"),
        }
    }
}

fn collect_cfg_blocks(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            if map.contains_key("instruction_pcs") && map.contains_key("start_pc") {
                out.push(value.clone());
            }
            for nested in map.values() {
                collect_cfg_blocks(nested, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_cfg_blocks(item, out)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// 6. Frozen v1 identity, current v2 identity.
// ---------------------------------------------------------------------------

#[test]
fn test_prototype_identity_v1_frozen_and_v2_current_matrix() {
    // The compatibility definition is byte-for-byte frozen.
    assert_eq!(
        PROTOTYPE_IDENTITY_SCHEME_V1, "luad-prototype-v1",
        "the v1 scheme name is frozen"
    );
    let hello = std::fs::read(workspace_root().join(HELLO_FIXTURE)).expect("pinned hello fixture");
    let hello_chunk = parse_chunk(&hello);
    let hello_facts = analyze_chunk_prototype_identities_v1(&hello_chunk)
        .expect("v1 compatibility identity analysis")
        .prototypes;
    assert_eq!(
        hello_facts[0].scheme, PROTOTYPE_IDENTITY_SCHEME_V1,
        "the v1 encoder remains explicitly available as a compatibility definition"
    );
    assert_eq!(
        hello_facts[0].digest, HELLO_V1_ROOT_DIGEST,
        "the frozen v1 canonical vector must not move"
    );

    // Recursive export emits v2 as the current identity scheme for Lua 5.1, and the
    // corrected companion role changes canonical instruction content.
    struct IdentityCase {
        name: &'static str,
        bytes: Vec<u8>,
    }
    let cases: Vec<IdentityCase> = EXTRA_SHAPES
        .iter()
        .take(2)
        .map(|shape| IdentityCase {
            name: shape.name,
            bytes: build_chunk(&extra_shape_root(shape.word)),
        })
        .collect();

    let mut v2_roots: Vec<String> = Vec::new();
    for case in &cases {
        let file = temp_chunk(&case.bytes);
        let stdout = run_luad_ok(&[
            "export",
            file.path().to_str().expect("UTF-8 path"),
            "--format",
            "jsonl",
        ]);
        let identities: Vec<Value> = jsonl_records(&stdout)
            .into_iter()
            .filter(|record| record["record_type"] == "prototype_identity")
            .map(|record| record["data"].clone())
            .collect();
        assert!(
            !identities.is_empty(),
            "{}: recursive export must emit prototype identities",
            case.name
        );
        for identity in &identities {
            assert_eq!(
                identity["scheme"].as_str(),
                Some(IDENTITY_SCHEME_V2),
                "{}: recursive export must emit the current identity scheme",
                case.name
            );
            let digest = identity["digest"].as_str().expect("digest string");
            assert!(
                digest.starts_with("sha256:") && digest.len() == "sha256:".len() + 64,
                "{}: malformed digest {digest}",
                case.name
            );
        }
        let root_digest = identities[0]["digest"]
            .as_str()
            .expect("root digest")
            .to_string();

        let chunk = parse_chunk(&case.bytes);

        // The default analyzer is the current scheme, and recursive export reports it.
        let current_root = analyze_chunk_prototype_identities(&chunk)
            .expect("current identity analysis")
            .prototypes
            .remove(0);
        assert_eq!(
            current_root.scheme, IDENTITY_SCHEME_V2,
            "{}: the default analyzer must emit the current identity scheme",
            case.name
        );
        assert_eq!(
            current_root.digest, root_digest,
            "{}: recursive export must equal the current direct analysis",
            case.name
        );

        // The frozen v1 definition stays reachable only through its explicit encoder.
        let v1_root = analyze_chunk_prototype_identities_v1(&chunk)
            .expect("v1 compatibility identity analysis")
            .prototypes
            .remove(0);
        assert_eq!(
            v1_root.scheme, PROTOTYPE_IDENTITY_SCHEME_V1,
            "{}: the compatibility encoder must stay on the v1 scheme",
            case.name
        );
        assert_ne!(
            root_digest, v1_root.digest,
            "{}: corrected companion roles must change canonical instruction content",
            case.name
        );
        v2_roots.push(root_digest);
    }

    assert_ne!(
        v2_roots[0], v2_roots[1],
        "the extra word's complete raw value is canonical content, so chunks differing \
         only in that word must not share a v2 identity"
    );
}

// ===========================================================================
// Shared upvalue-cell capture safety.
// ===========================================================================
//
// Lua 5.1 closures that capture the same parent local share one upvalue cell. The model
// below is a bounded shared-cell mutation summary over the synthesized prototype tree: it
// resolves each `CLOSURE` binding descriptor to the cell it names, records every
// `SETUPVAL` that writes such a cell anywhere in the subtree, and records parent writes
// that reach a captured register after the closure site. It deliberately reconstructs no
// general dataflow, and it never consults production callee, origin, relation, or xref
// analysis to decide whether a case is safe.

type ProtoPathVec = Vec<usize>;
/// A shared cell, named by the prototype that owns the register and the register itself.
type CellId = (ProtoPathVec, u8);

fn path_text(path: &[usize]) -> String {
    format!(
        "proto:{}",
        path.iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join("/")
    )
}

/// The outcome the contract requires for one call whose callee comes from a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CaptureVerdict {
    /// No relevant mutation exists, so the captured target survives.
    Preserved { callee: String },
    /// Some path can mutate the shared cell, so the capture must be rejected.
    Mutable,
}

fn preserved(callee: &str) -> CaptureVerdict {
    CaptureVerdict::Preserved {
        callee: callee.to_string(),
    }
}

/// Registers written by the bounded opcode set this family synthesizes. `None` marks a
/// word the model does not describe, which the matrix refuses to ignore silently.
fn modelled_writes(word: u32) -> Option<Vec<u8>> {
    let a = field_a(word);
    match opcode_of(word) {
        OP_MOVE | OP_GETUPVAL | OP_CLOSURE | OP_CALL | OP_SETLIST => Some(vec![a]),
        OP_LOADNIL => Some((a..=a.max(field_b(word) as u8)).collect()),
        OP_SETUPVAL | OP_RETURN => Some(Vec::new()),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct CaptureEdge {
    child_path: ProtoPathVec,
    slot: u8,
    cell: CellId,
    owner_path: ProtoPathVec,
    closure_pc: usize,
    /// `true` for a `MOVE` descriptor naming a parent local, `false` for `GETUPVAL`.
    binder_is_local: bool,
}

#[derive(Debug, Default)]
struct CaptureSummary {
    edges: Vec<CaptureEdge>,
    /// `(cell, path of the prototype whose SETUPVAL writes it)`.
    mutations: Vec<(CellId, ProtoPathVec)>,
    /// `(owner path, register, closure pc)` where the parent writes the captured
    /// register at a later PC.
    late_writes: BTreeSet<(ProtoPathVec, u8, usize)>,
    /// The closure prototype a cell holds where the cell is first captured.
    cell_values: BTreeMap<CellId, ProtoPathVec>,
    /// Executable words outside the bounded opcode model.
    unmodelled: Vec<(String, usize, u8)>,
}

fn summarize_captures(
    spec: &ProtoSpec,
    path: &[usize],
    upvalue_cells: &[CellId],
    out: &mut CaptureSummary,
) {
    let child_nups = spec.child_nups();
    let map = enumerate_roles(&spec.code, &child_nups);
    let mut child_cells: BTreeMap<usize, Vec<Vec<CellId>>> = BTreeMap::new();
    let mut register_closure: BTreeMap<u8, ProtoPathVec> = BTreeMap::new();
    let mut local_bindings: Vec<(usize, u8)> = Vec::new();

    for pc in 0..spec.code.len() {
        if !map.roles[pc].is_executable() {
            continue;
        }
        let word = spec.code[pc];
        if modelled_writes(word).is_none() {
            out.unmodelled.push((path_text(path), pc, opcode_of(word)));
        }
        match opcode_of(word) {
            OP_SETUPVAL => {
                if let Some(cell) = upvalue_cells.get(field_b(word) as usize) {
                    out.mutations.push((cell.clone(), path.to_vec()));
                }
            }
            OP_CLOSURE => {
                let index = field_bx(word) as usize;
                let nups = child_nups.get(index).copied().unwrap_or(0);
                let mut child_path = path.to_vec();
                child_path.push(index);
                let mut cells = Vec::with_capacity(nups);
                for slot in 0..nups {
                    let descriptor = spec.code[pc + 1 + slot];
                    let binder_is_local = opcode_of(descriptor) == OP_MOVE;
                    let cell = if binder_is_local {
                        (path.to_vec(), field_b(descriptor) as u8)
                    } else {
                        upvalue_cells
                            .get(field_b(descriptor) as usize)
                            .cloned()
                            .unwrap_or_else(|| (child_path.clone(), u8::MAX))
                    };
                    if binder_is_local {
                        if let Some(value) = register_closure.get(&cell.1) {
                            out.cell_values
                                .entry(cell.clone())
                                .or_insert_with(|| value.clone());
                        }
                        local_bindings.push((pc, cell.1));
                    }
                    cells.push(cell.clone());
                    out.edges.push(CaptureEdge {
                        child_path: child_path.clone(),
                        slot: slot as u8,
                        cell,
                        owner_path: path.to_vec(),
                        closure_pc: pc,
                        binder_is_local,
                    });
                }
                child_cells.entry(index).or_default().push(cells);
                register_closure.insert(field_a(word), child_path.clone());
            }
            _ => {
                for register in modelled_writes(word).unwrap_or_default() {
                    register_closure.remove(&register);
                }
            }
        }
    }

    for (closure_pc, register) in local_bindings {
        let written_after = (closure_pc + 1..spec.code.len()).any(|pc| {
            map.roles[pc].is_executable()
                && modelled_writes(spec.code[pc])
                    .map(|written| written.contains(&register))
                    .unwrap_or(true)
        });
        if written_after {
            out.late_writes
                .insert((path.to_vec(), register, closure_pc));
        }
    }

    for (index, child) in spec.children.iter().enumerate() {
        let mut child_path = path.to_vec();
        child_path.push(index);
        let bindings = child_cells
            .get(&index)
            .cloned()
            .unwrap_or_else(|| vec![Vec::new()]);
        for cells in bindings {
            summarize_captures(child, &child_path, &cells, out);
        }
    }
}

/// Switches used only by the killer harness, so each seeded defect is a single-rule
/// departure from the reference summary.
#[derive(Debug, Clone, Copy)]
struct SummaryFlags {
    /// Count mutations performed by closures outside the capturing child's own subtree.
    sibling_scan: bool,
    /// Follow the binding chain past one level below the cell's owner.
    transitive_scan: bool,
    /// Count parent writes to the captured register after the closure site.
    late_write_scan: bool,
}

impl SummaryFlags {
    const REFERENCE: Self = Self {
        sibling_scan: true,
        transitive_scan: true,
        late_write_scan: true,
    };
}

fn edge_verdict(
    summary: &CaptureSummary,
    edge: &CaptureEdge,
    flags: SummaryFlags,
) -> CaptureVerdict {
    let mutated = summary.mutations.iter().any(|(cell, mutator)| {
        cell == &edge.cell
            && (flags.sibling_scan || mutator.starts_with(&edge.child_path))
            && (flags.transitive_scan || mutator.len() == edge.cell.0.len() + 1)
    });
    let late = flags.late_write_scan
        && edge.binder_is_local
        && summary
            .late_writes
            .contains(&(edge.owner_path.clone(), edge.cell.1, edge.closure_pc));
    if mutated || late {
        CaptureVerdict::Mutable
    } else {
        CaptureVerdict::Preserved {
            callee: summary
                .cell_values
                .get(&edge.cell)
                .map(|value| path_text(value))
                .unwrap_or_else(|| "<unknown>".to_string()),
        }
    }
}

fn edge_for<'a>(summary: &'a CaptureSummary, child_path: &str, slot: u8) -> &'a CaptureEdge {
    summary
        .edges
        .iter()
        .find(|edge| path_text(&edge.child_path) == child_path && edge.slot == slot)
        .unwrap_or_else(|| panic!("no capture edge for {child_path} upvalue {slot}"))
}

/// Guards the bounded model: with no executable control transfer in the corpus, "after
/// the closure site" is exactly "at a later physical PC".
fn assert_straight_line(spec: &ProtoSpec, path: &[usize]) {
    let map = enumerate_roles(&spec.code, &spec.child_nups());
    for pc in 0..spec.code.len() {
        if map.roles[pc].is_executable() {
            assert!(
                transfer_targets(spec.code[pc], pc).is_empty(),
                "{}: PC {pc} transfers control; the bounded capture model assumes \
                 straight-line prototypes",
                path_text(path)
            );
        }
    }
    for (index, child) in spec.children.iter().enumerate() {
        let mut child_path = path.to_vec();
        child_path.push(index);
        assert_straight_line(child, &child_path);
    }
}

// ---------------------------------------------------------------------------
// Observation and pure comparator.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum CallOutcome {
    Prototype(String),
    MutableCapture,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaptureObservation {
    callee: CallOutcome,
    relation: CallOutcome,
    calls_xref_targets: Vec<String>,
    /// `None` where the call carries no fixed argument to trace.
    origin_is_mutable_capture: Option<bool>,
}

fn capture_mismatches(expected: &CaptureVerdict, observed: &CaptureObservation) -> Vec<String> {
    let mut mismatches = Vec::new();
    match expected {
        CaptureVerdict::Mutable => {
            if observed.callee != CallOutcome::MutableCapture {
                mismatches.push(format!(
                    "callee must be unresolved mutable-capture, got {:?}",
                    observed.callee
                ));
            }
            if observed.relation != CallOutcome::MutableCapture {
                mismatches.push(format!(
                    "call relation must be unresolved mutable-capture, got {:?}",
                    observed.relation
                ));
            }
            if !observed.calls_xref_targets.is_empty() {
                mismatches.push(format!(
                    "an unresolved relation must emit no calls xref, got {:?}",
                    observed.calls_xref_targets
                ));
            }
            if observed.origin_is_mutable_capture == Some(false) {
                mismatches
                    .push("origin analysis must agree the shared cell is mutable".to_string());
            }
        }
        CaptureVerdict::Preserved { callee } => {
            let want = CallOutcome::Prototype(callee.clone());
            if observed.callee != want {
                mismatches.push(format!(
                    "callee must resolve to {callee}, got {:?}",
                    observed.callee
                ));
            }
            if observed.relation != want {
                mismatches.push(format!(
                    "call relation must resolve to {callee}, got {:?}",
                    observed.relation
                ));
            }
            if observed.calls_xref_targets != vec![callee.clone()] {
                mismatches.push(format!(
                    "a resolved relation must emit exactly one calls xref to {callee}, got {:?}",
                    observed.calls_xref_targets
                ));
            }
            if observed.origin_is_mutable_capture == Some(true) {
                mismatches.push("origin analysis must not reject a safe equal capture".to_string());
            }
        }
    }
    mismatches
}

fn observe_capture(chunk: &Chunk, call_id: &str, trace_origin: bool) -> CaptureObservation {
    let callees = analyze_chunk_callees(chunk);
    let callee_fact = callees
        .prototypes
        .iter()
        .flat_map(|prototype| &prototype.calls)
        .find(|fact| fact.call_id.to_string() == call_id)
        .unwrap_or_else(|| panic!("no callee fact for {call_id}"));
    let callee = match &callee_fact.resolution {
        CalleeResolution::ResolvedPrototype { prototype, .. } => {
            CallOutcome::Prototype(luad_core::StableId::proto(prototype.clone()).to_string())
        }
        CalleeResolution::Unresolved {
            reason: CalleeUnresolvedReason::MutableCapture,
        } => CallOutcome::MutableCapture,
        other => CallOutcome::Other(format!("{other:?}")),
    };

    let relations = analyze_chunk_call_relations(chunk);
    let relation_fact = relations
        .prototypes
        .iter()
        .flat_map(|prototype| &prototype.calls)
        .find(|fact| fact.call_id.to_string() == call_id)
        .unwrap_or_else(|| panic!("no call relation for {call_id}"));
    let relation = match &relation_fact.resolution {
        CallRelationResolution::Resolved { callee, .. } => {
            CallOutcome::Prototype(luad_core::StableId::proto(callee.clone()).to_string())
        }
        CallRelationResolution::Unresolved {
            reason: CallRelationUnresolvedReason::MutableCapture,
            ..
        } => CallOutcome::MutableCapture,
        other => CallOutcome::Other(format!("{other:?}")),
    };

    let calls_xref_targets = XrefIndex::build(chunk)
        .entries
        .iter()
        .filter(|entry| {
            entry.relation == XrefRelation::Calls && entry.source.to_string() == call_id
        })
        .map(|entry| entry.target.to_string())
        .collect();

    let origin_is_mutable_capture = trace_origin.then(|| {
        let origins = analyze_chunk_origins(chunk);
        let origin_fact = origins
            .prototypes
            .iter()
            .flat_map(|prototype| &prototype.calls)
            .find(|fact| fact.call_id.to_string() == call_id)
            .unwrap_or_else(|| panic!("no origin fact for {call_id}"));
        match &origin_fact.argument_window {
            CallArgumentWindow::Fixed { arguments } => {
                let argument = arguments
                    .first()
                    .unwrap_or_else(|| panic!("{call_id} must carry one fixed argument"));
                matches!(
                    argument.origin.kind,
                    OriginExpressionKind::Unknown {
                        reason: OriginUnknownReason::MutableCapture
                    }
                )
            }
            CallArgumentWindow::Open { reason } => {
                panic!("{call_id} argument window unexpectedly open: {reason:?}")
            }
        }
    });

    CaptureObservation {
        callee,
        relation,
        calls_xref_targets,
        origin_is_mutable_capture,
    }
}

// ---------------------------------------------------------------------------
// Synthesized capture trees.
// ---------------------------------------------------------------------------

/// Calls its captured upvalue and passes the same cell as the single argument, so callee
/// and origin analysis both depend on one shared cell.
fn caller_child() -> ProtoSpec {
    ProtoSpec::child(
        1,
        vec![
            iabc(OP_GETUPVAL, 0, 0, 0),
            iabc(OP_GETUPVAL, 1, 0, 0),
            iabc(OP_CALL, 0, 2, 1),
            iabc(OP_RETURN, 0, 1, 0),
        ],
    )
}

/// Writes the shared cell through `SETUPVAL`.
fn mutator_child() -> ProtoSpec {
    ProtoSpec::child(
        1,
        vec![
            iabc(OP_LOADNIL, 0, 0, 0),
            iabc(OP_SETUPVAL, 0, 0, 0),
            iabc(OP_RETURN, 0, 1, 0),
        ],
    )
}

/// Captures the shared cell and only reads it.
fn reader_child() -> ProtoSpec {
    ProtoSpec::child(
        1,
        vec![iabc(OP_GETUPVAL, 0, 0, 0), iabc(OP_RETURN, 0, 1, 0)],
    )
}

/// Captures the shared cell and hands it to a grandchild that mutates it.
fn holder_child() -> ProtoSpec {
    ProtoSpec::child(
        1,
        vec![
            iabx(OP_CLOSURE, 0, 0),
            iabc(OP_GETUPVAL, 0, 0, 0),
            iabc(OP_RETURN, 0, 1, 0),
        ],
    )
    .with_child(mutator_child())
}

struct CaptureRow {
    name: &'static str,
    root: ProtoSpec,
    caller_path: &'static str,
    caller_pc: usize,
    /// The caller's upvalue slot the callee flows from; `None` for direct local flow.
    capture_slot: Option<u8>,
    verdict: CaptureVerdict,
}

fn capture_rows() -> Vec<CaptureRow> {
    // Shared parent shape: PC 0 stores the closure target in R0, then one or two
    // closures capture R0 through `MOVE` binding descriptors.
    let two_captures = |first: u32, second: u32| {
        vec![
            iabx(OP_CLOSURE, 0, 0),
            first,
            iabc(OP_MOVE, 0, 0, 0),
            second,
            iabc(OP_MOVE, 0, 0, 0),
            iabc(OP_RETURN, 0, 1, 0),
        ]
    };

    vec![
        CaptureRow {
            name: "sibling-mutates-shared-local",
            root: ProtoSpec::root(
                3,
                two_captures(iabx(OP_CLOSURE, 1, 1), iabx(OP_CLOSURE, 2, 2)),
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child())
            .with_child(mutator_child()),
            caller_path: "proto:0/1",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: CaptureVerdict::Mutable,
        },
        // Placement: the mutating sibling is created *before* the caller. A scan limited
        // to physical order after the caller's CLOSURE would miss this.
        CaptureRow {
            name: "sibling-mutator-created-before-caller",
            root: ProtoSpec::root(
                3,
                two_captures(iabx(OP_CLOSURE, 1, 2), iabx(OP_CLOSURE, 2, 1)),
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child())
            .with_child(mutator_child()),
            caller_path: "proto:0/1",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: CaptureVerdict::Mutable,
        },
        // A sibling that does not write the cell keeps the capture safe.
        CaptureRow {
            name: "non-mutating-sibling-stays-resolved",
            root: ProtoSpec::root(
                3,
                two_captures(iabx(OP_CLOSURE, 1, 1), iabx(OP_CLOSURE, 2, 2)),
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child())
            .with_child(reader_child()),
            caller_path: "proto:0/1",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: preserved("proto:0/0"),
        },
        // Equal safe captures: two closures capture the same cell, neither writes it.
        CaptureRow {
            name: "equal-safe-captures-first",
            root: ProtoSpec::root(
                3,
                two_captures(iabx(OP_CLOSURE, 1, 1), iabx(OP_CLOSURE, 2, 2)),
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child())
            .with_child(caller_child()),
            caller_path: "proto:0/1",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: preserved("proto:0/0"),
        },
        CaptureRow {
            name: "equal-safe-captures-second",
            root: ProtoSpec::root(
                3,
                two_captures(iabx(OP_CLOSURE, 1, 1), iabx(OP_CLOSURE, 2, 2)),
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child())
            .with_child(caller_child()),
            caller_path: "proto:0/2",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: preserved("proto:0/0"),
        },
        // A sibling's descendant mutates the cell the sibling only forwards.
        CaptureRow {
            name: "descendant-of-sibling-mutates-shared-local",
            root: ProtoSpec::root(
                3,
                two_captures(iabx(OP_CLOSURE, 1, 1), iabx(OP_CLOSURE, 2, 2)),
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child())
            .with_child(holder_child()),
            caller_path: "proto:0/1",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: CaptureVerdict::Mutable,
        },
        // Placement: the parent itself rewrites the captured register after the site.
        CaptureRow {
            name: "parent-writes-shared-local-after-closure",
            root: ProtoSpec::root(
                2,
                vec![
                    iabx(OP_CLOSURE, 0, 0),
                    iabx(OP_CLOSURE, 1, 1),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabx(OP_CLOSURE, 0, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child()),
            caller_path: "proto:0/1",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: CaptureVerdict::Mutable,
        },
        // Placement: every parent write precedes the site, so the capture survives.
        CaptureRow {
            name: "parent-writes-shared-local-only-before-closure",
            root: ProtoSpec::root(
                2,
                vec![
                    iabx(OP_CLOSURE, 0, 0),
                    iabx(OP_CLOSURE, 0, 0),
                    iabx(OP_CLOSURE, 1, 1),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child()),
            caller_path: "proto:0/1",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: preserved("proto:0/0"),
        },
        // The same unsafety one nesting level deeper, through a parent upvalue: the
        // caller binds `GETUPVAL`, and a sibling of the caller writes that same cell.
        CaptureRow {
            name: "parent-upvalue-mutated-one-level-deeper",
            root: ProtoSpec::root(
                2,
                vec![
                    iabx(OP_CLOSURE, 0, 0),
                    iabx(OP_CLOSURE, 1, 1),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(
                ProtoSpec::child(
                    1,
                    vec![
                        iabx(OP_CLOSURE, 0, 0),
                        iabc(OP_GETUPVAL, 0, 0, 0),
                        iabx(OP_CLOSURE, 1, 1),
                        iabc(OP_GETUPVAL, 0, 0, 0),
                        iabc(OP_RETURN, 0, 1, 0),
                    ],
                )
                .with_child(caller_child())
                .with_child(mutator_child()),
            ),
            caller_path: "proto:0/1/0",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: CaptureVerdict::Mutable,
        },
        // Direct local closure flow: no capture is involved at all.
        CaptureRow {
            name: "direct-local-closure-flow",
            root: ProtoSpec::root(
                2,
                vec![
                    iabx(OP_CLOSURE, 0, 0),
                    iabc(OP_CALL, 0, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(0)),
            caller_path: "proto:0",
            caller_pc: 1,
            capture_slot: None,
            verdict: preserved("proto:0/0"),
        },
        // A SETLIST payload resembling CLOSURE must not rebind child upvalues.
        CaptureRow {
            name: "setlist-payload-resembling-closure-does-not-rebind",
            root: ProtoSpec::root(
                10,
                vec![
                    iabx(OP_CLOSURE, 0, 0),
                    iabx(OP_CLOSURE, 1, 1),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabx(OP_CLOSURE, 2, 2),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabc(OP_SETLIST, 1, 1, 0),
                    iabx(OP_CLOSURE, 0, 2),
                    iabc(OP_MOVE, 0, 9, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child())
            .with_child(mutator_child()),
            caller_path: "proto:0/1",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: CaptureVerdict::Mutable,
        },
        // One child prototype can be instantiated at more than one site. Its upvalue
        // slot denotes every cell supplied by those sites, rather than whichever site
        // happens to be visited last.
        CaptureRow {
            name: "repeated-child-prototype-unions-captured-cells",
            root: ProtoSpec::root(
                10,
                vec![
                    iabx(OP_CLOSURE, 0, 0),
                    iabx(OP_CLOSURE, 1, 1),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabx(OP_CLOSURE, 2, 2),
                    iabc(OP_MOVE, 0, 0, 0),
                    iabx(OP_CLOSURE, 3, 2),
                    iabc(OP_MOVE, 0, 9, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
            )
            .with_child(ProtoSpec::leaf_child(0))
            .with_child(caller_child())
            .with_child(mutator_child()),
            caller_path: "proto:0/1",
            caller_pc: 2,
            capture_slot: Some(0),
            verdict: CaptureVerdict::Mutable,
        },
    ]
}

#[test]
fn test_shared_capture_mutation_matrix() {
    for row in capture_rows() {
        let label = row.name;
        assert_straight_line(&row.root, &[0]);

        let mut summary = CaptureSummary::default();
        summarize_captures(&row.root, &[0], &[], &mut summary);
        assert!(
            summary.unmodelled.is_empty(),
            "{label}: the bounded capture model does not describe {:?}",
            summary.unmodelled
        );

        // The independent shared-cell summary must reach the declared verdict on its own.
        match row.capture_slot {
            Some(slot) => {
                let edge = edge_for(&summary, row.caller_path, slot);
                assert_eq!(
                    edge_verdict(&summary, edge, SummaryFlags::REFERENCE),
                    row.verdict,
                    "{label}: independent shared-cell summary"
                );
            }
            None => assert!(
                summary.edges.is_empty(),
                "{label}: direct local closure flow captures nothing: {:?}",
                summary.edges
            ),
        }

        // Production callee, relation, xref, and origin facts must agree.
        let chunk = parse_chunk(&build_chunk(&row.root));
        let call_id = format!("{}:pc:{}", row.caller_path, row.caller_pc);
        let observed = observe_capture(&chunk, &call_id, row.capture_slot.is_some());
        let mismatches = capture_mismatches(&row.verdict, &observed);
        assert!(
            mismatches.is_empty(),
            "{label} ({call_id}): {mismatches:?}\nobserved={observed:?}"
        );
    }
}

#[test]
fn test_shared_capture_killer_mutations_are_rejected() {
    // Killer mutations of the independent summary: each removed rule must change the
    // verdict of at least one row, so no rule in the model is inert.
    let rows = capture_rows();
    let verdicts = |flags: SummaryFlags| -> Vec<CaptureVerdict> {
        rows.iter()
            .filter_map(|row| {
                let slot = row.capture_slot?;
                let mut summary = CaptureSummary::default();
                summarize_captures(&row.root, &[0], &[], &mut summary);
                Some(edge_verdict(
                    &summary,
                    edge_for(&summary, row.caller_path, slot),
                    flags,
                ))
            })
            .collect()
    };
    let reference = verdicts(SummaryFlags::REFERENCE);
    for (name, flags) in [
        (
            "sibling scan removed",
            SummaryFlags {
                sibling_scan: false,
                ..SummaryFlags::REFERENCE
            },
        ),
        (
            "transitive parent-upvalue scan removed",
            SummaryFlags {
                transitive_scan: false,
                ..SummaryFlags::REFERENCE
            },
        ),
        (
            "parent late-write scan removed",
            SummaryFlags {
                late_write_scan: false,
                ..SummaryFlags::REFERENCE
            },
        ),
    ] {
        assert_ne!(
            verdicts(flags),
            reference,
            "summary killer mutation survived: {name}"
        );
    }

    // Killer mutations of the comparator: every plausible production defect must be
    // rejected, and both faithful observations must be accepted.
    let stale = "proto:0/0".to_string();
    let faithful_mutable = CaptureObservation {
        callee: CallOutcome::MutableCapture,
        relation: CallOutcome::MutableCapture,
        calls_xref_targets: Vec::new(),
        origin_is_mutable_capture: Some(true),
    };
    let faithful_preserved = CaptureObservation {
        callee: CallOutcome::Prototype(stale.clone()),
        relation: CallOutcome::Prototype(stale.clone()),
        calls_xref_targets: vec![stale.clone()],
        origin_is_mutable_capture: Some(false),
    };
    assert!(
        capture_mismatches(&CaptureVerdict::Mutable, &faithful_mutable).is_empty(),
        "the comparator must accept a faithful rejection"
    );
    assert!(
        capture_mismatches(&preserved(&stale), &faithful_preserved).is_empty(),
        "the comparator must accept a faithful preservation"
    );

    // The first two removals share one observable signature (a stale target survives) on
    // different rows; the summary flags above separate their causes.
    let killers: Vec<(&str, CaptureVerdict, CaptureObservation)> = vec![
        (
            "sibling scan removed: stale sibling-mutated target resolved",
            CaptureVerdict::Mutable,
            faithful_preserved.clone(),
        ),
        (
            "transitive parent-upvalue scan removed: stale nested target resolved",
            CaptureVerdict::Mutable,
            faithful_preserved.clone(),
        ),
        (
            "stale prototype target retained beside a rejected relation",
            CaptureVerdict::Mutable,
            CaptureObservation {
                callee: CallOutcome::Prototype(stale.clone()),
                ..faithful_mutable.clone()
            },
        ),
        (
            "unresolved call emits a calls xref",
            CaptureVerdict::Mutable,
            CaptureObservation {
                calls_xref_targets: vec![stale.clone()],
                ..faithful_mutable.clone()
            },
        ),
        (
            "origin analysis disagrees with a rejected capture",
            CaptureVerdict::Mutable,
            CaptureObservation {
                origin_is_mutable_capture: Some(false),
                ..faithful_mutable.clone()
            },
        ),
        (
            "safe equal capture needlessly downgraded",
            preserved(&stale),
            faithful_mutable.clone(),
        ),
    ];
    for (name, expected, observed) in killers {
        assert!(
            !capture_mismatches(&expected, &observed).is_empty(),
            "capture killer mutation survived: {name}"
        );
    }
}

#[test]
fn test_shared_capture_summary_exhaustion_returns_analysis_limit() {
    // The bounded mutation summary is exercised through an explicit budget rather than an
    // enormous tree, so exhaustion is deterministic and cheap.
    let mut rows = capture_rows();
    let row = rows.remove(0);
    assert_eq!(row.name, "sibling-mutates-shared-local");
    let chunk = parse_chunk(&build_chunk(&row.root));
    let call_id = format!("{}:pc:{}", row.caller_path, row.caller_pc);

    let starved = analyze_chunk_callees_with_mutation_budget(&chunk, 0);
    let facts: Vec<_> = starved
        .prototypes
        .iter()
        .flat_map(|prototype| &prototype.calls)
        .collect();
    let target = facts
        .iter()
        .find(|fact| fact.call_id.to_string() == call_id)
        .unwrap_or_else(|| panic!("no callee fact for {call_id}"));
    assert!(
        matches!(
            target.resolution,
            CalleeResolution::Unresolved {
                reason: CalleeUnresolvedReason::AnalysisLimit
            }
        ),
        "reaching the summary bound must produce analysis-limit, got {:?}",
        target.resolution
    );
    for fact in &facts {
        assert!(
            !matches!(
                fact.resolution,
                CalleeResolution::ResolvedPrototype { .. } | CalleeResolution::ResolvedPath { .. }
            ),
            "reaching the summary bound must never preserve a value: {:?}",
            fact.resolution
        );
    }

    assert_eq!(
        analyze_chunk_callees_with_mutation_budget(&chunk, usize::MAX),
        analyze_chunk_callees(&chunk),
        "a budget that is never reached must reproduce the default analysis exactly"
    );
}
