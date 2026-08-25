//! Independent acceptance for the constant-key Lua 5.1 call-label contract.
//!
//! This file freezes the whole claim of `docs/NEXT-SPRINT.md` as one table-driven family:
//! a `CALL`/`TAILCALL` whose callee value comes from a constant-key `GETTABLE` or `SELF`
//! carries a tagged `lookup-label` result recording only the lookup form, the exact typed
//! constant key, and the value-preserving proof sites between the lookup and the call.
//!
//! Everything below the "public observation" banner is a test-local transcription of the
//! PUC-Rio Lua 5.1.5 chunk format, instruction encoding, and reference register flow. The
//! chunk writer, the operand decoder, the bounded dataflow, the join, the capture
//! derivation, the capture-mutation summary, and the expected wire shapes are written here
//! from the published contract. They deliberately never call luad's callee transfer, join,
//! capture derivation, call-relation mapping, renderer, or schema types to decide what the
//! answer should be: production output is only ever *observed*, serialized, and compared
//! against the independent model and against a hand-written expectation table.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

use luad_core::model::Chunk;
use luad_core::reader::SafeReader;
use serde_json::{json, Value};
use tempfile::NamedTempFile;

// ===========================================================================
// 1. Independent Lua 5.1.5 instruction encoding and decoding.
// ===========================================================================

const OP_MOVE: u8 = 0;
const OP_LOADK: u8 = 1;
const OP_LOADBOOL: u8 = 2;
const OP_GETUPVAL: u8 = 4;
const OP_GETGLOBAL: u8 = 5;
const OP_GETTABLE: u8 = 6;
const OP_SETUPVAL: u8 = 8;
const OP_NEWTABLE: u8 = 10;
const OP_SELF: u8 = 11;
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

/// `BITRK` in `lopcodes.h`: the ninth bit of an RK operand selects the constant table.
const BITRK: u16 = 1 << 8;

const fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    (op as u32) | ((a as u32) << 6) | ((c as u32) << 14) | ((b as u32) << 23)
}

const fn iabx(op: u8, a: u8, bx: u32) -> u32 {
    (op as u32) | ((a as u32) << 6) | (bx << 14)
}

fn iasbx(op: u8, a: u8, sbx: i32) -> u32 {
    // MAXARG_sBx = (2^18 - 1) / 2 in Lua 5.1.
    iabx(op, a, (sbx + 131_071) as u32)
}

/// `RK(C)` for a constant table index.
const fn rk_k(index: u8) -> u16 {
    BITRK | index as u16
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

/// The independently decoded meaning of one RK operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rk {
    /// The operand names a register.
    Register(u8),
    /// The operand names a constant-table index.
    Constant(usize),
}

/// Decode one 9-bit RK field exactly as `ISK`/`INDEXK` do.
fn decode_rk(field: u16) -> Rk {
    if field & BITRK != 0 {
        Rk::Constant(usize::from(field & !BITRK))
    } else {
        Rk::Register(field as u8)
    }
}

// ===========================================================================
// 2. Independent typed constants and their published machine encoding.
// ===========================================================================

/// A Lua 5.1 constant this family can write into a synthesized chunk, held by its exact
/// serialized bytes. Equality is therefore byte-exact and type-tagged by construction: it
/// is never numeric equality and never stringified equality.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyConst {
    /// `LUA_TNIL`.
    Nil,
    /// `LUA_TBOOLEAN`.
    Boolean(bool),
    /// `LUA_TNUMBER`, stored as the exact 8 little-endian IEEE-754 bytes.
    Number([u8; 8]),
    /// `LUA_TSTRING`, stored as the exact payload bytes without the trailing NUL.
    Text(&'static [u8]),
}

impl KeyConst {
    fn number(value: f64) -> Self {
        Self::Number(value.to_le_bytes())
    }

    fn number_bits(bits: u64) -> Self {
        Self::Number(bits.to_le_bytes())
    }

    /// The chunk-format type tag written before the payload.
    fn tag(&self) -> u8 {
        match self {
            Self::Nil => 0,
            Self::Boolean(_) => 1,
            Self::Number(_) => 3,
            Self::Text(_) => 4,
        }
    }

    /// IEEE-754 quiet or signalling NaN, decided from the raw bytes alone.
    fn is_nan(&self) -> bool {
        match self {
            Self::Number(bytes) => {
                let bits = u64::from_le_bytes(*bytes);
                (bits & 0x7ff0_0000_0000_0000) == 0x7ff0_0000_0000_0000
                    && (bits & 0x000f_ffff_ffff_ffff) != 0
            }
            _ => false,
        }
    }

    /// The `f64` this constant denotes, for the deliberately-wrong numeric comparison used
    /// by one killer mutation.
    fn numeric_value(&self) -> Option<f64> {
        match self {
            Self::Number(bytes) => Some(f64::from_le_bytes(*bytes)),
            _ => None,
        }
    }

    /// The literal string a symbolic path segment would take, when the key is a string.
    fn as_path_segment(&self) -> Option<String> {
        match self {
            Self::Text(bytes) => Some(escape_bytes(bytes)),
            _ => None,
        }
    }

    /// The published `luad_core::model::ConstantValue` machine encoding, written out here
    /// rather than obtained by serializing a production value.
    fn wire(&self) -> Value {
        match self {
            Self::Nil => json!({ "type": "nil" }),
            Self::Boolean(value) => json!({ "type": "boolean", "value": value }),
            Self::Number(bytes) => {
                let value = f64::from_le_bytes(*bytes);
                // Non-finite doubles have no JSON number form and serialize as `null`;
                // `raw_hex` is what preserves the exact payload and the sign bit.
                let rendered = if value.is_finite() {
                    Value::from(value)
                } else {
                    Value::Null
                };
                json!({
                    "type": "float",
                    "value": {
                        "val": rendered,
                        "raw_hex": hex_lower(bytes),
                        "is_nan": value.is_nan(),
                        "is_inf": value.is_infinite(),
                    }
                })
            }
            Self::Text(bytes) => json!({
                "type": "short-string",
                "value": {
                    "raw_bytes": bytes.to_vec(),
                    "display": escape_bytes(bytes),
                    "is_utf8": std::str::from_utf8(bytes).is_ok(),
                }
            }),
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The published lossless display escaping for a Lua string, transcribed from the
/// documented rule rather than imported.
fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str(r"\\"),
            b'"' => out.push_str(r#"\""#),
            b'\n' => out.push_str(r"\n"),
            b'\r' => out.push_str(r"\r"),
            b'\t' => out.push_str(r"\t"),
            0x20..=0x7E => out.push(byte as char),
            _ => out.push_str(&format!(r"\x{byte:02x}")),
        }
    }
    out
}

// ===========================================================================
// 3. Independent Lua 5.1 chunk writer.
// ===========================================================================

const PROBE_SOURCE: &str = "@constant_key_probe.lua";

/// A prototype to synthesize, written verbatim so that every physical word is under test
/// control.
#[derive(Debug, Clone)]
struct ProtoSpec {
    nups: u8,
    numparams: u8,
    is_vararg: u8,
    maxstacksize: u8,
    code: Vec<u32>,
    constants: Vec<KeyConst>,
    children: Vec<ProtoSpec>,
}

impl ProtoSpec {
    fn root(maxstacksize: u8, code: Vec<u32>, constants: Vec<KeyConst>) -> Self {
        Self {
            nups: 0,
            numparams: 0,
            is_vararg: 2, // VARARG_ISVARARG
            maxstacksize,
            code,
            constants,
            children: Vec::new(),
        }
    }

    fn child(nups: u8, maxstacksize: u8, code: Vec<u32>, constants: Vec<KeyConst>) -> Self {
        Self {
            nups,
            numparams: 0,
            is_vararg: 0,
            maxstacksize,
            code,
            constants,
            children: Vec::new(),
        }
    }

    fn with_child(mut self, child: ProtoSpec) -> Self {
        self.children.push(child);
        self
    }
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&((bytes.len() + 1) as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    out.push(0);
}

fn write_proto(out: &mut Vec<u8>, spec: &ProtoSpec) {
    write_string(out, PROBE_SOURCE.as_bytes());
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
    write_u32(out, spec.constants.len() as u32);
    for constant in &spec.constants {
        out.push(constant.tag());
        match constant {
            KeyConst::Nil => {}
            KeyConst::Boolean(value) => out.push(u8::from(*value)),
            KeyConst::Number(bytes) => out.extend_from_slice(bytes),
            KeyConst::Text(bytes) => write_string(out, bytes),
        }
    }
    write_u32(out, spec.children.len() as u32);
    for child in &spec.children {
        write_proto(out, child);
    }
    write_u32(out, 0); // lineinfo
    write_u32(out, 0); // locvars
    write_u32(out, 0); // upvalue names
}

/// A complete little-endian 64-bit stock Lua 5.1 chunk around `root`.
fn build_chunk(root: &ProtoSpec) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1bLua");
    out.extend_from_slice(&[0x51, 0, 1, 4, 8, 4, 8, 0]);
    write_proto(&mut out, root);
    out
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

// ===========================================================================
// 4. Independent stable identities and expected outcomes.
// ===========================================================================

/// One instruction identity. Ordering is the published structural order for stable IDs:
/// prototype path first, then program counter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EvId {
    proto: Vec<usize>,
    pc: usize,
}

impl EvId {
    fn new(proto: &[usize], pc: usize) -> Self {
        Self {
            proto: proto.to_vec(),
            pc,
        }
    }

    fn text(&self) -> String {
        format!("proto:{}:pc:{}", path_text(&self.proto), self.pc)
    }
}

fn path_text(path: &[usize]) -> String {
    path.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("/")
}

fn parse_path(text: &str) -> Vec<usize> {
    text.split('/')
        .map(|part| part.parse().expect("prototype path component"))
        .collect()
}

/// Hand-written evidence, in the exact order the public result must publish.
fn ev(items: &[(&str, usize)]) -> Vec<EvId> {
    items
        .iter()
        .map(|(path, pc)| EvId::new(&parse_path(path), *pc))
        .collect()
}

fn call_id(path: &str, pc: usize) -> String {
    format!("proto:{path}:pc:{pc}")
}

/// Which physical opcode selected the callee value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupKind {
    GetTable,
    SelfOp,
}

impl LookupKind {
    fn wire(self) -> &'static str {
        match self {
            Self::GetTable => "gettable",
            Self::SelfOp => "self",
        }
    }

    fn opcode(self) -> u8 {
        match self {
            Self::GetTable => OP_GETTABLE,
            Self::SelfOp => OP_SELF,
        }
    }
}

// Closed stop reasons, spelled in their published kebab-case wire form.
const STOP_MISSING_DEFINITION: &str = "missing-definition";
const STOP_CONTROL_FLOW_CONFLICT: &str = "control-flow-conflict";
const STOP_DYNAMIC_KEY: &str = "dynamic-key";
const STOP_OVERWRITTEN: &str = "overwritten";
const STOP_OPEN_REGISTER_WINDOW: &str = "open-register-window";
const STOP_UNSUPPORTED_VALUE: &str = "unsupported-value";
const STOP_MUTABLE_CAPTURE: &str = "mutable-capture";
const STOP_AMBIGUOUS_CAPTURE: &str = "ambiguous-capture";
const STOP_ANALYSIS_LIMIT: &str = "analysis-limit";
const STOP_UNREACHABLE: &str = "unreachable";

const BASIS_GLOBAL: &str = "global-label";
const BASIS_MODULE: &str = "module-label";

/// The complete public outcome required for one physical call.
#[derive(Debug, Clone, PartialEq)]
enum Expected {
    /// The new tagged constant-key selector result.
    LookupLabel {
        kind: LookupKind,
        key: KeyConst,
        evidence: Vec<EvId>,
    },
    /// The stronger, unchanged symbolic-path result.
    Path {
        basis: &'static str,
        segments: Vec<String>,
        evidence: Vec<EvId>,
    },
    /// The stronger, unchanged directly-constructed-closure result.
    Prototype {
        prototype: Vec<usize>,
        evidence: Vec<EvId>,
    },
    /// An explicit stop reason.
    Stop { reason: &'static str },
}

impl Expected {
    fn path(basis: &'static str, segments: &[&str], evidence: Vec<EvId>) -> Self {
        Self::Path {
            basis,
            segments: segments.iter().map(ToString::to_string).collect(),
            evidence,
        }
    }

    fn label(kind: LookupKind, key: KeyConst, evidence: Vec<EvId>) -> Self {
        Self::LookupLabel {
            kind,
            key,
            evidence,
        }
    }

    fn evidence(&self) -> &[EvId] {
        match self {
            Self::LookupLabel { evidence, .. }
            | Self::Path { evidence, .. }
            | Self::Prototype { evidence, .. } => evidence,
            Self::Stop { .. } => &[],
        }
    }

    fn evidence_wire(&self) -> Value {
        Value::Array(
            self.evidence()
                .iter()
                .map(|id| Value::String(id.text()))
                .collect(),
        )
    }

    /// The required `CalleeResolution` wire object.
    fn callee_wire(&self) -> Value {
        match self {
            Self::LookupLabel { kind, key, .. } => json!({
                "status": "lookup-label",
                "lookup_kind": kind.wire(),
                "key": key.wire(),
                "evidence": self.evidence_wire(),
            }),
            Self::Path {
                basis, segments, ..
            } => json!({
                "status": "resolved-path",
                "basis": basis,
                "segments": segments,
                "evidence": self.evidence_wire(),
            }),
            Self::Prototype { prototype, .. } => json!({
                "status": "resolved-prototype",
                "prototype": path_text(prototype),
                "evidence": self.evidence_wire(),
            }),
            Self::Stop { reason } => json!({ "status": "unresolved", "reason": reason }),
        }
    }

    /// The required `CallRelationResolution` wire object.
    ///
    /// No row in this family stores a global, so a single-segment global label can only
    /// stop at `missing-prototype-store`; every longer or module path stops at
    /// `symbolic-path-only`. A constant-key label never becomes an exact relation: it stops
    /// at the new `lookup-label-only` reason while retaining the label's evidence.
    fn relation_wire(&self) -> Value {
        match self {
            Self::LookupLabel { .. } => json!({
                "status": "unresolved",
                "reason": "lookup-label-only",
                "evidence": self.evidence_wire(),
            }),
            Self::Path {
                basis, segments, ..
            } => {
                let reason = if *basis == BASIS_GLOBAL && segments.len() == 1 {
                    "missing-prototype-store"
                } else {
                    "symbolic-path-only"
                };
                json!({
                    "status": "unresolved",
                    "reason": reason,
                    "evidence": self.evidence_wire(),
                })
            }
            Self::Prototype { prototype, .. } => json!({
                "status": "resolved",
                "callee": path_text(prototype),
                "basis": "closure-value",
                "evidence": self.evidence_wire(),
            }),
            Self::Stop { reason } => json!({
                "status": "unresolved",
                "reason": reason,
                "evidence": [],
            }),
        }
    }

    /// The exact `calls` cross-reference target, when this outcome licenses one at all.
    fn calls_xref_target(&self) -> Option<String> {
        match self {
            Self::Prototype { prototype, .. } => Some(format!("proto:{}", path_text(prototype))),
            _ => None,
        }
    }
}

// ===========================================================================
// 5. Independent bounded register-flow model.
// ===========================================================================

/// One abstract value in the independent model.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fact {
    Bottom,
    Label {
        kind: LookupKind,
        key: KeyConst,
        ev: BTreeSet<EvId>,
    },
    Path {
        basis: &'static str,
        segments: Vec<String>,
        ev: BTreeSet<EvId>,
    },
    Proto {
        path: Vec<usize>,
        ev: BTreeSet<EvId>,
    },
    Literal {
        value: String,
        ev: BTreeSet<EvId>,
    },
    NonClosure,
    Unknown(&'static str),
}

impl Fact {
    fn evidence(&self) -> BTreeSet<EvId> {
        match self {
            Self::Label { ev, .. }
            | Self::Path { ev, .. }
            | Self::Proto { ev, .. }
            | Self::Literal { ev, .. } => ev.clone(),
            _ => BTreeSet::new(),
        }
    }

    fn with_evidence(mut self, id: &EvId) -> Self {
        match &mut self {
            Self::Label { ev, .. }
            | Self::Path { ev, .. }
            | Self::Proto { ev, .. }
            | Self::Literal { ev, .. } => {
                ev.insert(id.clone());
            }
            _ => {}
        }
        self
    }

    fn into_expected(self) -> Expected {
        match self {
            Self::Label { kind, key, ev } => Expected::LookupLabel {
                kind,
                key,
                evidence: ev.into_iter().collect(),
            },
            Self::Path {
                basis,
                segments,
                ev,
            } => Expected::Path {
                basis,
                segments,
                evidence: ev.into_iter().collect(),
            },
            Self::Proto { path, ev } => Expected::Prototype {
                prototype: path,
                evidence: ev.into_iter().collect(),
            },
            Self::Literal { .. } | Self::NonClosure => Expected::Stop {
                reason: STOP_UNSUPPORTED_VALUE,
            },
            Self::Unknown(reason) => Expected::Stop { reason },
            Self::Bottom => Expected::Stop {
                reason: STOP_MISSING_DEFINITION,
            },
        }
    }
}

/// Single-rule departures from the reference model, used only by the killer harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ModelFlags {
    /// Ignore the decoded `RK(C)` index and key every label with constant 0.
    drop_key_operand: bool,
    /// Report every constant-key lookup as `self`.
    all_labels_are_self: bool,
    /// Join any two labels regardless of key or lookup kind.
    merge_any_two_labels: bool,
    /// Compare numeric keys by value instead of by exact bytes.
    numeric_key_equality: bool,
    /// Keep only one branch's evidence on an equal join.
    drop_branch_evidence: bool,
    /// Let a `MOVE` alias contribute no evidence hop.
    erase_alias_hop: bool,
    /// Publish a constant-key label as a rootless symbolic path.
    label_becomes_path: bool,
    /// Downgrade a provable symbolic path to a constant-key label.
    path_becomes_label: bool,
    /// Replace the dynamic-key stop with a plausible label.
    stop_becomes_label: bool,
    /// Let NaN-keyed labels take part in equal joins.
    nan_joins: bool,
    /// Fold the receiver's evidence into the label.
    receiver_evidence: bool,
}

impl ModelFlags {
    const REFERENCE: Self = Self {
        drop_key_operand: false,
        all_labels_are_self: false,
        merge_any_two_labels: false,
        numeric_key_equality: false,
        drop_branch_evidence: false,
        erase_alias_hop: false,
        label_becomes_path: false,
        path_becomes_label: false,
        stop_becomes_label: false,
        nan_joins: false,
        receiver_evidence: false,
    };
}

/// Byte-exact, type-tagged key identity. NaN keys never satisfy it.
fn keys_join(left: &KeyConst, right: &KeyConst, flags: ModelFlags) -> bool {
    if flags.numeric_key_equality {
        if let (Some(a), Some(b)) = (left.numeric_value(), right.numeric_value()) {
            return a == b;
        }
    }
    if left != right {
        return false;
    }
    flags.nan_joins || !left.is_nan()
}

fn meet(left: &Fact, right: &Fact, flags: ModelFlags) -> Fact {
    match (left, right) {
        (Fact::Bottom, value) | (value, Fact::Bottom) => value.clone(),
        (
            Fact::Label {
                kind: lk,
                key: lkey,
                ev: lev,
            },
            Fact::Label {
                kind: rk,
                key: rkey,
                ev: rev,
            },
        ) if flags.merge_any_two_labels || (lk == rk && keys_join(lkey, rkey, flags)) => {
            Fact::Label {
                kind: *lk,
                key: lkey.clone(),
                ev: if flags.drop_branch_evidence {
                    lev.clone()
                } else {
                    lev.union(rev).cloned().collect()
                },
            }
        }
        (
            Fact::Path {
                basis: lb,
                segments: ls,
                ev: lev,
            },
            Fact::Path {
                basis: rb,
                segments: rs,
                ev: rev,
            },
        ) if lb == rb && ls == rs => Fact::Path {
            basis: *lb,
            segments: ls.clone(),
            ev: lev.union(rev).cloned().collect(),
        },
        (Fact::Proto { path: lp, ev: lev }, Fact::Proto { path: rp, ev: rev }) if lp == rp => {
            Fact::Proto {
                path: lp.clone(),
                ev: lev.union(rev).cloned().collect(),
            }
        }
        (Fact::Literal { value: lv, ev: lev }, Fact::Literal { value: rv, ev: rev })
            if lv == rv =>
        {
            Fact::Literal {
                value: lv.clone(),
                ev: lev.union(rev).cloned().collect(),
            }
        }
        (Fact::NonClosure, Fact::NonClosure) => Fact::NonClosure,
        (Fact::Unknown(a), Fact::Unknown(b)) if a == b => Fact::Unknown(*a),
        _ => Fact::Unknown(STOP_CONTROL_FLOW_CONFLICT),
    }
}

type State = Vec<Fact>;

/// A synthesized prototype prepared for the independent dataflow.
struct ModelProto<'a> {
    spec: &'a ProtoSpec,
    path: Vec<usize>,
    /// Physical PCs that the VM executes; `CLOSURE` binding descriptors are excluded.
    executable: Vec<bool>,
    /// For every `CLOSURE` owner PC, the child prototype index it instantiates.
    closures: Vec<(usize, usize)>,
}

impl<'a> ModelProto<'a> {
    fn new(spec: &'a ProtoSpec, path: Vec<usize>) -> Self {
        let count = spec.code.len();
        let mut executable = vec![true; count];
        let mut closures = Vec::new();
        for pc in 0..count {
            if !executable[pc] {
                // A claimed companion word is data and can never own companions of its own.
                continue;
            }
            let word = spec.code[pc];
            assert_ne!(
                opcode_of(word),
                OP_SETLIST,
                "this family never synthesizes SETLIST companion ranges"
            );
            if opcode_of(word) != OP_CLOSURE {
                continue;
            }
            let child_index = field_bx(word) as usize;
            let nups = usize::from(
                spec.children
                    .get(child_index)
                    .unwrap_or_else(|| panic!("CLOSURE Bx {child_index} has no child prototype"))
                    .nups,
            );
            closures.push((pc, child_index));
            for slot in 0..nups {
                let descriptor = pc + 1 + slot;
                assert!(descriptor < count, "closure binding range must be complete");
                executable[descriptor] = false;
            }
        }
        Self {
            spec,
            path,
            executable,
            closures,
        }
    }

    fn next_executable(&self, from: usize) -> Option<usize> {
        (from..self.spec.code.len()).find(|pc| self.executable[*pc])
    }

    fn id(&self, pc: usize) -> EvId {
        EvId::new(&self.path, pc)
    }

    /// Where the reference VM can continue after the executable word at `pc`.
    fn successors(&self, pc: usize) -> Vec<usize> {
        let word = self.spec.code[pc];
        let relative = |sbx: i32| -> usize {
            let target = pc as i64 + 1 + i64::from(sbx);
            assert!(target >= 0, "jump before the code vector");
            target as usize
        };
        let raw: Vec<usize> = match opcode_of(word) {
            OP_RETURN | OP_TAILCALL => Vec::new(),
            OP_JMP | OP_FORPREP => vec![relative(field_sbx(word))],
            OP_FORLOOP => vec![relative(field_sbx(word)), pc + 1],
            OP_EQ | OP_LT | OP_LE | OP_TEST | OP_TESTSET | OP_TFORLOOP => vec![pc + 1, pc + 2],
            OP_LOADBOOL if field_c(word) != 0 => vec![pc + 2],
            _ => vec![pc + 1],
        };
        raw.into_iter()
            .filter_map(|target| self.next_executable(target))
            .collect()
    }

    /// Straight line means: every executable word either ends the prototype or continues at
    /// the next executable word. Companion words are stepped over, not branched around.
    fn has_control_transfer(&self) -> bool {
        (0..self.spec.code.len())
            .filter(|pc| self.executable[*pc])
            .any(|pc| {
                let successors = self.successors(pc);
                match successors.len() {
                    0 => false,
                    1 => Some(successors[0]) != self.next_executable(pc + 1),
                    _ => true,
                }
            })
    }

    /// Registers the bounded opcode set writes. `None` marks a word the model refuses to
    /// interpret silently.
    fn writes(&self, pc: usize) -> Option<Vec<u8>> {
        let word = self.spec.code[pc];
        let a = field_a(word);
        let b = field_b(word);
        let c = field_c(word);
        Some(match opcode_of(word) {
            OP_MOVE | OP_LOADK | OP_LOADBOOL | OP_GETUPVAL | OP_GETGLOBAL | OP_GETTABLE
            | OP_NEWTABLE | OP_CLOSURE => vec![a],
            OP_SELF => vec![a + 1, a],
            OP_SETUPVAL | OP_JMP | OP_EQ | OP_LT | OP_LE | OP_RETURN | OP_TAILCALL => Vec::new(),
            OP_CALL => {
                if c > 1 {
                    (a..=a + (c as u8) - 2).collect()
                } else {
                    Vec::new()
                }
            }
            OP_VARARG => {
                if b > 1 {
                    (a..=a + (b as u8) - 2).collect()
                } else {
                    Vec::new()
                }
            }
            _ => return None,
        })
    }

    /// Whether the word at `pc` opens the register window past the frame.
    fn opens_register_window(&self, pc: usize) -> bool {
        let word = self.spec.code[pc];
        match opcode_of(word) {
            OP_CALL => field_b(word) == 0 || field_c(word) == 0,
            OP_VARARG => field_b(word) == 0,
            _ => false,
        }
    }

    fn constant(&self, index: usize) -> KeyConst {
        self.spec
            .constants
            .get(index)
            .unwrap_or_else(|| panic!("constant index {index} out of range"))
            .clone()
    }

    fn transfer(
        &self,
        pc: usize,
        before: &State,
        captures: &BTreeMap<u8, Fact>,
        flags: ModelFlags,
    ) -> State {
        let word = self.spec.code[pc];
        let frame = self.spec.maxstacksize as usize;
        let mut after = before.clone();
        let id = self.id(pc);

        let writes = self
            .writes(pc)
            .unwrap_or_else(|| panic!("unmodelled opcode {} at PC {pc}", opcode_of(word)));
        for register in writes {
            set(&mut after, register, Fact::Unknown(STOP_OVERWRITTEN), frame);
        }
        if self.opens_register_window(pc) {
            for slot in after.iter_mut().take(frame) {
                *slot = Fact::Unknown(STOP_OPEN_REGISTER_WINDOW);
            }
        }

        let a = field_a(word);
        let b = field_b(word);
        match opcode_of(word) {
            OP_LOADK => {
                let value = self.constant(field_bx(word) as usize);
                let fact = match value.as_path_segment() {
                    Some(text) => Fact::Literal {
                        value: text,
                        ev: [id.clone()].into_iter().collect(),
                    },
                    None => Fact::NonClosure,
                };
                set(&mut after, a, fact, frame);
            }
            OP_GETGLOBAL => {
                let name = self
                    .constant(field_bx(word) as usize)
                    .as_path_segment()
                    .expect("GETGLOBAL names a string constant");
                set(
                    &mut after,
                    a,
                    Fact::Path {
                        basis: BASIS_GLOBAL,
                        segments: vec![name],
                        ev: [id.clone()].into_iter().collect(),
                    },
                    frame,
                );
            }
            OP_MOVE => {
                let source = get(before, b as u8, frame);
                let aliased = if flags.erase_alias_hop {
                    source
                } else {
                    source.with_evidence(&id)
                };
                set(&mut after, a, aliased, frame);
            }
            OP_GETUPVAL => {
                let value = captures
                    .get(&(b as u8))
                    .cloned()
                    .unwrap_or(Fact::Unknown(STOP_AMBIGUOUS_CAPTURE));
                set(&mut after, a, value, frame);
            }
            OP_GETTABLE | OP_SELF => {
                let kind = if opcode_of(word) == OP_SELF {
                    LookupKind::SelfOp
                } else {
                    LookupKind::GetTable
                };
                let receiver = get(before, b as u8, frame);
                if kind == LookupKind::SelfOp {
                    set(&mut after, a + 1, receiver.clone(), frame);
                }
                let selected = match decode_rk(field_c(word)) {
                    // A dynamic key is one of the closed stops; it never yields a label.
                    Rk::Register(_) if flags.stop_becomes_label => {
                        self.make_label(kind, self.constant(0), &receiver, &id, flags)
                    }
                    Rk::Register(_) => Fact::Unknown(STOP_DYNAMIC_KEY),
                    Rk::Constant(index) => {
                        let index = if flags.drop_key_operand { 0 } else { index };
                        let key = self.constant(index);
                        // A provable global or module receiver keeps the stronger result.
                        match (&receiver, key.as_path_segment()) {
                            (
                                Fact::Path {
                                    basis,
                                    segments,
                                    ev,
                                },
                                Some(segment),
                            ) if !flags.path_becomes_label => {
                                let mut segments = segments.clone();
                                segments.push(segment);
                                let mut ev = ev.clone();
                                ev.insert(id.clone());
                                Fact::Path {
                                    basis: *basis,
                                    segments,
                                    ev,
                                }
                            }
                            _ => self.make_label(kind, key, &receiver, &id, flags),
                        }
                    }
                };
                set(&mut after, a, selected, frame);
            }
            OP_CALL => {
                if let Some(module) = self.require_module(before, a, word, frame) {
                    let mut ev = get(before, a + 1, frame).evidence();
                    ev.extend(get(before, a, frame).evidence());
                    ev.insert(id.clone());
                    set(
                        &mut after,
                        a,
                        Fact::Path {
                            basis: BASIS_MODULE,
                            segments: module,
                            ev,
                        },
                        frame,
                    );
                }
            }
            OP_CLOSURE => {
                let mut path = self.path.clone();
                path.push(field_bx(word) as usize);
                set(
                    &mut after,
                    a,
                    Fact::Proto {
                        path,
                        ev: [id].into_iter().collect(),
                    },
                    frame,
                );
            }
            _ => {}
        }
        after
    }

    fn make_label(
        &self,
        kind: LookupKind,
        key: KeyConst,
        receiver: &Fact,
        id: &EvId,
        flags: ModelFlags,
    ) -> Fact {
        let mut ev: BTreeSet<EvId> = [id.clone()].into_iter().collect();
        if flags.receiver_evidence {
            ev.extend(receiver.evidence());
        }
        let kind = if flags.all_labels_are_self {
            LookupKind::SelfOp
        } else {
            kind
        };
        if flags.label_becomes_path {
            return Fact::Path {
                basis: BASIS_GLOBAL,
                segments: vec![key.as_path_segment().unwrap_or_else(|| "?".to_string())],
                ev,
            };
        }
        Fact::Label { kind, key, ev }
    }

    /// The exact `require "name"` call shape that yields a module label.
    fn require_module(
        &self,
        before: &State,
        base: u8,
        word: u32,
        frame: usize,
    ) -> Option<Vec<String>> {
        if field_b(word) != 2 || field_c(word) != 2 {
            return None;
        }
        let is_require = match get(before, base, frame) {
            Fact::Path {
                basis, segments, ..
            } => basis == BASIS_GLOBAL && segments.len() == 1 && segments[0] == "require",
            _ => false,
        };
        if !is_require {
            return None;
        }
        let Fact::Literal { value, .. } = get(before, base + 1, frame) else {
            return None;
        };
        let segments: Vec<String> = value
            .split('.')
            .filter(|segment| !segment.is_empty())
            .map(ToString::to_string)
            .collect();
        (!segments.is_empty()).then_some(segments)
    }
}

fn get(state: &State, index: u8, frame: usize) -> Fact {
    if usize::from(index) >= frame {
        return Fact::Unknown(STOP_OPEN_REGISTER_WINDOW);
    }
    state
        .get(usize::from(index))
        .cloned()
        .unwrap_or(Fact::Unknown(STOP_OPEN_REGISTER_WINDOW))
}

fn set(state: &mut State, index: u8, value: Fact, frame: usize) {
    if usize::from(index) < frame {
        if let Some(slot) = state.get_mut(usize::from(index)) {
            *slot = value;
        }
    }
}

/// A shared variable cell, named by the prototype that owns it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Cell {
    Local(Vec<usize>, u8),
    Upvalue(Vec<usize>, u8),
}

/// The bounded whole-tree capture-mutation summary the contract requires.
#[derive(Debug, Default)]
struct MutationSummary {
    upvalue_to_cells: BTreeMap<(Vec<usize>, u8), BTreeSet<Cell>>,
    mutated: BTreeSet<Cell>,
}

impl MutationSummary {
    fn build(root: &ProtoSpec) -> Self {
        let mut summary = Self::default();
        summary.map_upvalues(root, &[0]);
        summary.collect_mutations(root, &[0]);
        summary
    }

    fn map_upvalues(&mut self, spec: &ProtoSpec, path: &[usize]) {
        if path.len() == 1 {
            for slot in 0..spec.nups {
                self.upvalue_to_cells.insert(
                    (path.to_vec(), slot),
                    [Cell::Upvalue(path.to_vec(), slot)].into_iter().collect(),
                );
            }
        }
        let model = ModelProto::new(spec, path.to_vec());
        for (pc, child_index) in &model.closures {
            let child = &spec.children[*child_index];
            let mut child_path = path.to_vec();
            child_path.push(*child_index);
            for slot in 0..child.nups {
                let descriptor = spec.code[pc + 1 + usize::from(slot)];
                let cells: BTreeSet<Cell> = match opcode_of(descriptor) {
                    OP_MOVE => [Cell::Local(path.to_vec(), field_b(descriptor) as u8)]
                        .into_iter()
                        .collect(),
                    OP_GETUPVAL => self
                        .upvalue_to_cells
                        .get(&(path.to_vec(), field_b(descriptor) as u8))
                        .cloned()
                        .unwrap_or_else(|| {
                            [Cell::Upvalue(path.to_vec(), field_b(descriptor) as u8)]
                                .into_iter()
                                .collect()
                        }),
                    other => panic!("illegal closure binding opcode {other}"),
                };
                self.upvalue_to_cells
                    .entry((child_path.clone(), slot))
                    .or_default()
                    .extend(cells);
            }
        }
        for (index, child) in spec.children.iter().enumerate() {
            let mut child_path = path.to_vec();
            child_path.push(index);
            self.map_upvalues(child, &child_path);
        }
    }

    fn collect_mutations(&mut self, spec: &ProtoSpec, path: &[usize]) {
        for (index, child) in spec.children.iter().enumerate() {
            let mut child_path = path.to_vec();
            child_path.push(index);
            self.collect_mutations(child, &child_path);
        }
        let model = ModelProto::new(spec, path.to_vec());
        for pc in 0..spec.code.len() {
            if !model.executable[pc] || opcode_of(spec.code[pc]) != OP_SETUPVAL {
                continue;
            }
            let slot = field_b(spec.code[pc]) as u8;
            let cells = self
                .upvalue_to_cells
                .get(&(path.to_vec(), slot))
                .cloned()
                .unwrap_or_else(|| [Cell::Upvalue(path.to_vec(), slot)].into_iter().collect());
            self.mutated.extend(cells);
        }
    }

    fn cell_is_mutated(&self, path: &[usize], slot: u8) -> bool {
        match self.upvalue_to_cells.get(&(path.to_vec(), slot)) {
            Some(cells) => cells.iter().any(|cell| self.mutated.contains(cell)),
            None => self.mutated.contains(&Cell::Upvalue(path.to_vec(), slot)),
        }
    }

    fn local_is_mutated(&self, path: &[usize], register: u8) -> bool {
        self.mutated.contains(&Cell::Local(path.to_vec(), register))
    }
}

/// Join two capture values: only an equal value survives a repeated instantiation site.
fn join_capture(left: &Fact, right: &Fact, flags: ModelFlags) -> Fact {
    match meet(left, right, flags) {
        Fact::Unknown(STOP_CONTROL_FLOW_CONFLICT) => Fact::Unknown(STOP_AMBIGUOUS_CAPTURE),
        joined => joined,
    }
}

/// The complete independent expectation for every physical call in one chunk.
fn model_chunk(root: &ProtoSpec, flags: ModelFlags) -> BTreeMap<String, Expected> {
    let summary = MutationSummary::build(root);
    let mut out = BTreeMap::new();
    model_proto(root, &[0], &BTreeMap::new(), &summary, flags, &mut out);
    out
}

fn model_proto(
    spec: &ProtoSpec,
    path: &[usize],
    captures: &BTreeMap<u8, Fact>,
    summary: &MutationSummary,
    flags: ModelFlags,
    out: &mut BTreeMap<String, Expected>,
) {
    let model = ModelProto::new(spec, path.to_vec());
    let frame = spec.maxstacksize as usize;
    let count = spec.code.len();

    // Reachability over executable words only.
    let entry = model.next_executable(0).expect("a non-empty code vector");
    let mut reachable: BTreeSet<usize> = BTreeSet::new();
    let mut queue = vec![entry];
    while let Some(pc) = queue.pop() {
        if !reachable.insert(pc) {
            continue;
        }
        queue.extend(model.successors(pc));
    }

    let mut predecessors: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for pc in reachable.iter().copied() {
        for target in model.successors(pc) {
            predecessors.entry(target).or_default().insert(pc);
        }
    }

    let entry_state: State = vec![Fact::Unknown(STOP_MISSING_DEFINITION); frame];
    let mut in_states: BTreeMap<usize, State> = BTreeMap::new();
    let mut out_states: BTreeMap<usize, State> = BTreeMap::new();
    for pc in reachable.iter().copied() {
        in_states.insert(pc, vec![Fact::Bottom; frame]);
        out_states.insert(pc, vec![Fact::Bottom; frame]);
    }
    in_states.insert(entry, entry_state.clone());

    // Bounded chaotic iteration to a fixed point.
    for _ in 0..(count * count + 8) {
        let mut changed = false;
        for pc in reachable.iter().copied() {
            let incoming = if pc == entry {
                entry_state.clone()
            } else {
                let mut merged = vec![Fact::Bottom; frame];
                for predecessor in predecessors.get(&pc).into_iter().flatten() {
                    let previous = &out_states[predecessor];
                    for (slot, value) in merged.iter_mut().zip(previous) {
                        let joined = meet(slot, value, flags);
                        *slot = joined;
                    }
                }
                merged
            };
            if in_states[&pc] != incoming {
                in_states.insert(pc, incoming.clone());
                changed = true;
            }
            let produced = model.transfer(pc, &incoming, captures, flags);
            if out_states[&pc] != produced {
                out_states.insert(pc, produced);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    for pc in 0..count {
        if !model.executable[pc] {
            continue;
        }
        let opcode = opcode_of(spec.code[pc]);
        if opcode != OP_CALL && opcode != OP_TAILCALL {
            continue;
        }
        let expected = if reachable.contains(&pc) {
            get(&in_states[&pc], field_a(spec.code[pc]), frame).into_expected()
        } else {
            Expected::Stop {
                reason: STOP_UNREACHABLE,
            }
        };
        out.insert(model.id(pc).text(), expected);
    }

    // Child capture environments.
    if !model.closures.is_empty() {
        assert!(
            !model.has_control_transfer(),
            "the bounded capture model requires straight-line prototypes; \
             proto:{} transfers control",
            path_text(path)
        );
    }
    let mut environments: BTreeMap<usize, BTreeMap<u8, Fact>> = BTreeMap::new();
    for (closure_pc, child_index) in &model.closures {
        if !reachable.contains(closure_pc) {
            continue;
        }
        let child = &spec.children[*child_index];
        let mut child_path = path.to_vec();
        child_path.push(*child_index);
        let state = &in_states[closure_pc];
        let closure_dest = field_a(spec.code[*closure_pc]);
        let closure_id = model.id(*closure_pc);
        let environment = environments.entry(*child_index).or_default();

        for slot in 0..child.nups {
            let descriptor_pc = closure_pc + 1 + usize::from(slot);
            let descriptor = spec.code[descriptor_pc];
            let descriptor_id = model.id(descriptor_pc);
            let mut value = if summary.cell_is_mutated(&child_path, slot) {
                Fact::Unknown(STOP_MUTABLE_CAPTURE)
            } else {
                match opcode_of(descriptor) {
                    OP_MOVE => {
                        let register = field_b(descriptor) as u8;
                        if register == closure_dest
                            || summary.local_is_mutated(path, register)
                            || written_after(&model, *closure_pc, Some(register), None)
                        {
                            Fact::Unknown(STOP_MUTABLE_CAPTURE)
                        } else {
                            match get(state, register, frame) {
                                Fact::NonClosure => Fact::Unknown(STOP_UNSUPPORTED_VALUE),
                                Fact::Bottom => Fact::Unknown(STOP_MISSING_DEFINITION),
                                other => other,
                            }
                        }
                    }
                    OP_GETUPVAL => {
                        let parent_slot = field_b(descriptor) as u8;
                        if summary.cell_is_mutated(path, parent_slot)
                            || written_after(&model, *closure_pc, None, Some(parent_slot))
                        {
                            Fact::Unknown(STOP_MUTABLE_CAPTURE)
                        } else {
                            captures
                                .get(&parent_slot)
                                .cloned()
                                .unwrap_or(Fact::Unknown(STOP_AMBIGUOUS_CAPTURE))
                        }
                    }
                    other => panic!("illegal closure binding opcode {other}"),
                }
            };
            value = value
                .with_evidence(&closure_id)
                .with_evidence(&descriptor_id);
            let merged = match environment.get(&slot) {
                Some(existing) => join_capture(existing, &value, flags),
                None => value,
            };
            environment.insert(slot, merged);
        }
    }

    for (index, child) in spec.children.iter().enumerate() {
        let mut child_path = path.to_vec();
        child_path.push(index);
        let environment = environments.get(&index).cloned().unwrap_or_else(|| {
            (0..child.nups)
                .map(|slot| (slot, Fact::Unknown(STOP_AMBIGUOUS_CAPTURE)))
                .collect()
        });
        model_proto(child, &child_path, &environment, summary, flags, out);
    }
}

/// Whether a captured cell may be written after the closure site. The capture rows are
/// asserted straight-line, so "after" is exactly "at a later physical PC".
fn written_after(
    model: &ModelProto<'_>,
    closure_pc: usize,
    register: Option<u8>,
    upvalue: Option<u8>,
) -> bool {
    (closure_pc + 1..model.spec.code.len())
        .filter(|pc| model.executable[*pc])
        .any(|pc| {
            let word = model.spec.code[pc];
            if let Some(slot) = upvalue {
                return opcode_of(word) == OP_SETUPVAL && field_b(word) as u8 == slot;
            }
            let Some(target) = register else { return false };
            model
                .writes(pc)
                .map(|writes| writes.contains(&target))
                .unwrap_or(true)
        })
}

// ===========================================================================
// 6. The acceptance matrix.
// ===========================================================================

struct Row {
    name: &'static str,
    root: ProtoSpec,
    /// Every physical call in this program, with the outcome the contract requires.
    expect: Vec<(String, Expected)>,
}

fn gettable(a: u8, b: u8, key: u8) -> u32 {
    iabc(OP_GETTABLE, a, u16::from(b), rk_k(key))
}

fn self_op(a: u8, b: u8, key: u8) -> u32 {
    iabc(OP_SELF, a, u16::from(b), rk_k(key))
}

/// `<kind> R1 R0 K0` immediately followed by a call of `R1`.
fn immediate_row(name: &'static str, kind: LookupKind, key: KeyConst) -> Row {
    let argument_count = if kind == LookupKind::SelfOp { 2 } else { 1 };
    let lookup = iabc(kind.opcode(), 1, 0, rk_k(0));
    Row {
        name,
        root: ProtoSpec::root(
            3,
            vec![
                lookup,
                iabc(OP_CALL, 1, argument_count, 1),
                iabc(OP_RETURN, 0, 1, 0),
            ],
            vec![key.clone()],
        ),
        expect: vec![(call_id("0", 1), Expected::label(kind, key, ev(&[("0", 0)])))],
    }
}

/// A control-flow diamond whose two branches each select a callee, joined before the call.
fn join_row(
    name: &'static str,
    constants: Vec<KeyConst>,
    left: (LookupKind, u8, u8),
    right: (LookupKind, u8, u8),
    expected: Expected,
) -> Row {
    let encode = |(kind, receiver, key): (LookupKind, u8, u8)| {
        iabc(kind.opcode(), 1, u16::from(receiver), rk_k(key))
    };
    Row {
        name,
        root: ProtoSpec::root(
            3,
            vec![
                iabc(OP_EQ, 0, 0, 0),
                iasbx(OP_JMP, 0, 2),
                encode(left),
                iasbx(OP_JMP, 0, 1),
                encode(right),
                iabc(OP_CALL, 1, 1, 1),
                iabc(OP_RETURN, 0, 1, 0),
            ],
            constants,
        ),
        expect: vec![(call_id("0", 5), expected)],
    }
}

const KEY_EXECUTE: KeyConst = KeyConst::Text(b"execute");
const KEY_CALL: KeyConst = KeyConst::Text(b"call");

fn typed_key_rows() -> Vec<Row> {
    vec![
        ("typed-key-boolean-true", KeyConst::Boolean(true)),
        ("typed-key-nil", KeyConst::Nil),
        ("typed-key-number", KeyConst::number(3.5)),
        ("typed-key-positive-zero", KeyConst::number(0.0)),
        ("typed-key-negative-zero", KeyConst::number(-0.0)),
        (
            "typed-key-quiet-nan",
            KeyConst::number_bits(0x7ff8_0000_0000_0000),
        ),
        ("typed-key-non-utf8-string", KeyConst::Text(b"ex\xffec")),
    ]
    .into_iter()
    .map(|(name, key)| immediate_row(name, LookupKind::GetTable, key))
    .collect()
}

fn join_rows() -> Vec<Row> {
    let nan = KeyConst::number_bits(0x7ff8_0000_0000_0000);
    vec![
        join_row(
            "equal-key-join-across-branches",
            vec![KEY_EXECUTE],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::GetTable, 0, 0),
            Expected::label(LookupKind::GetTable, KEY_EXECUTE, ev(&[("0", 2), ("0", 4)])),
        ),
        join_row(
            "equal-key-different-unknown-receivers",
            vec![KEY_EXECUTE],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::GetTable, 2, 0),
            Expected::label(LookupKind::GetTable, KEY_EXECUTE, ev(&[("0", 2), ("0", 4)])),
        ),
        join_row(
            "equal-bytes-different-constant-index",
            vec![KEY_EXECUTE, KEY_EXECUTE],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::GetTable, 0, 1),
            Expected::label(LookupKind::GetTable, KEY_EXECUTE, ev(&[("0", 2), ("0", 4)])),
        ),
        join_row(
            "equal-self-join-across-branches",
            vec![KEY_CALL],
            (LookupKind::SelfOp, 0, 0),
            (LookupKind::SelfOp, 0, 0),
            Expected::label(LookupKind::SelfOp, KEY_CALL, ev(&[("0", 2), ("0", 4)])),
        ),
        join_row(
            "conflicting-keys-join",
            vec![KEY_EXECUTE, KEY_CALL],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::GetTable, 0, 1),
            Expected::Stop {
                reason: STOP_CONTROL_FLOW_CONFLICT,
            },
        ),
        join_row(
            "conflicting-lookup-kinds-join",
            vec![KEY_EXECUTE],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::SelfOp, 0, 0),
            Expected::Stop {
                reason: STOP_CONTROL_FLOW_CONFLICT,
            },
        ),
        join_row(
            "positive-zero-keys-join",
            vec![KeyConst::number(0.0), KeyConst::number(0.0)],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::GetTable, 0, 1),
            Expected::label(
                LookupKind::GetTable,
                KeyConst::number(0.0),
                ev(&[("0", 2), ("0", 4)]),
            ),
        ),
        join_row(
            "signed-zero-keys-conflict",
            vec![KeyConst::number(0.0), KeyConst::number(-0.0)],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::GetTable, 0, 1),
            Expected::Stop {
                reason: STOP_CONTROL_FLOW_CONFLICT,
            },
        ),
        join_row(
            "nan-key-join-blocked-same-payload",
            vec![nan.clone(), nan],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::GetTable, 0, 1),
            Expected::Stop {
                reason: STOP_CONTROL_FLOW_CONFLICT,
            },
        ),
        join_row(
            "type-tag-conflict-boolean-versus-number",
            vec![KeyConst::Boolean(true), KeyConst::number(1.0)],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::GetTable, 0, 1),
            Expected::Stop {
                reason: STOP_CONTROL_FLOW_CONFLICT,
            },
        ),
        join_row(
            "type-tag-conflict-number-versus-string",
            vec![KeyConst::number(1.0), KeyConst::Text(b"1")],
            (LookupKind::GetTable, 0, 0),
            (LookupKind::GetTable, 0, 1),
            Expected::Stop {
                reason: STOP_CONTROL_FLOW_CONFLICT,
            },
        ),
    ]
}

fn flow_rows() -> Vec<Row> {
    vec![
        Row {
            name: "move-alias-hops",
            root: ProtoSpec::root(
                4,
                vec![
                    gettable(1, 0, 0),
                    iabc(OP_MOVE, 2, 1, 0),
                    iabc(OP_MOVE, 3, 2, 0),
                    iabc(OP_CALL, 3, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KeyConst::Text(b"format")],
            ),
            expect: vec![(
                call_id("0", 3),
                Expected::label(
                    LookupKind::GetTable,
                    KeyConst::Text(b"format"),
                    ev(&[("0", 0), ("0", 1), ("0", 2)]),
                ),
            )],
        },
        Row {
            name: "tailcall-lookup-label",
            root: ProtoSpec::root(
                2,
                vec![
                    gettable(1, 0, 0),
                    iabc(OP_TAILCALL, 1, 1, 0),
                    iabc(OP_RETURN, 0, 0, 0),
                ],
                vec![KeyConst::Text(b"run")],
            ),
            expect: vec![(
                call_id("0", 1),
                Expected::label(
                    LookupKind::GetTable,
                    KeyConst::Text(b"run"),
                    ev(&[("0", 0)]),
                ),
            )],
        },
        Row {
            name: "chained-lookup-keeps-last-selector",
            root: ProtoSpec::root(
                3,
                vec![
                    gettable(1, 0, 0),
                    gettable(2, 1, 1),
                    iabc(OP_CALL, 2, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KeyConst::Text(b"sys"), KEY_EXECUTE],
            ),
            expect: vec![(
                call_id("0", 2),
                Expected::label(LookupKind::GetTable, KEY_EXECUTE, ev(&[("0", 1)])),
            )],
        },
        Row {
            name: "dynamic-register-key",
            root: ProtoSpec::root(
                3,
                vec![
                    iabc(OP_GETTABLE, 1, 0, 2),
                    iabc(OP_CALL, 1, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE],
            ),
            expect: vec![(
                call_id("0", 1),
                Expected::Stop {
                    reason: STOP_DYNAMIC_KEY,
                },
            )],
        },
        Row {
            name: "overwrite-after-lookup",
            root: ProtoSpec::root(
                3,
                vec![
                    gettable(1, 0, 0),
                    iabc(OP_NEWTABLE, 1, 0, 0),
                    iabc(OP_CALL, 1, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE],
            ),
            expect: vec![(
                call_id("0", 2),
                Expected::Stop {
                    reason: STOP_OVERWRITTEN,
                },
            )],
        },
        Row {
            name: "open-register-window",
            root: ProtoSpec::root(
                3,
                vec![
                    gettable(1, 0, 0),
                    iabc(OP_VARARG, 2, 0, 0),
                    iabc(OP_CALL, 1, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE],
            ),
            expect: vec![(
                call_id("0", 2),
                Expected::Stop {
                    reason: STOP_OPEN_REGISTER_WINDOW,
                },
            )],
        },
        Row {
            name: "unreachable-call-keeps-its-stop-reason",
            root: ProtoSpec::root(
                2,
                vec![
                    gettable(1, 0, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                    iabc(OP_CALL, 1, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE],
            ),
            expect: vec![(
                call_id("0", 2),
                Expected::Stop {
                    reason: STOP_UNREACHABLE,
                },
            )],
        },
    ]
}

fn stronger_result_rows() -> Vec<Row> {
    vec![
        Row {
            name: "global-receiver-keeps-resolved-path",
            root: ProtoSpec::root(
                3,
                vec![
                    iabx(OP_GETGLOBAL, 0, 0),
                    gettable(1, 0, 1),
                    iabc(OP_CALL, 1, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KeyConst::Text(b"luci"), KeyConst::Text(b"exec")],
            ),
            expect: vec![(
                call_id("0", 2),
                Expected::path(BASIS_GLOBAL, &["luci", "exec"], ev(&[("0", 0), ("0", 1)])),
            )],
        },
        Row {
            name: "self-on-global-receiver-keeps-resolved-path",
            root: ProtoSpec::root(
                3,
                vec![
                    iabx(OP_GETGLOBAL, 0, 0),
                    self_op(1, 0, 1),
                    iabc(OP_CALL, 1, 2, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KeyConst::Text(b"luci"), KeyConst::Text(b"exec")],
            ),
            expect: vec![(
                call_id("0", 2),
                Expected::path(BASIS_GLOBAL, &["luci", "exec"], ev(&[("0", 0), ("0", 1)])),
            )],
        },
        Row {
            name: "module-receiver-keeps-resolved-path",
            root: ProtoSpec::root(
                2,
                vec![
                    iabx(OP_GETGLOBAL, 0, 0),
                    iabx(OP_LOADK, 1, 1),
                    iabc(OP_CALL, 0, 2, 2),
                    gettable(1, 0, 2),
                    iabc(OP_CALL, 1, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![
                    KeyConst::Text(b"require"),
                    KeyConst::Text(b"luci.sys"),
                    KeyConst::Text(b"exec"),
                ],
            ),
            expect: vec![
                (
                    call_id("0", 2),
                    Expected::path(BASIS_GLOBAL, &["require"], ev(&[("0", 0)])),
                ),
                (
                    call_id("0", 4),
                    Expected::path(
                        BASIS_MODULE,
                        &["luci", "sys", "exec"],
                        ev(&[("0", 0), ("0", 1), ("0", 2), ("0", 3)]),
                    ),
                ),
            ],
        },
        Row {
            name: "closure-value-keeps-resolved-prototype",
            root: ProtoSpec::root(
                2,
                vec![
                    iabx(OP_CLOSURE, 0, 0),
                    iabc(OP_CALL, 0, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![],
            )
            .with_child(ProtoSpec::child(
                0,
                2,
                vec![iabc(OP_RETURN, 0, 1, 0)],
                vec![],
            )),
            expect: vec![(
                call_id("0", 1),
                Expected::Prototype {
                    prototype: vec![0, 0],
                    evidence: ev(&[("0", 0)]),
                },
            )],
        },
    ]
}

/// The child that reads its single upvalue and calls it.
fn calling_child() -> ProtoSpec {
    ProtoSpec::child(
        1,
        2,
        vec![
            iabc(OP_GETUPVAL, 0, 0, 0),
            iabc(OP_CALL, 0, 1, 1),
            iabc(OP_RETURN, 0, 1, 0),
        ],
        vec![],
    )
}

fn capture_rows() -> Vec<Row> {
    let label = |evidence: Vec<EvId>| Expected::label(LookupKind::GetTable, KEY_EXECUTE, evidence);
    vec![
        Row {
            name: "capture-safe-local-label",
            root: ProtoSpec::root(
                3,
                vec![
                    gettable(1, 0, 0),
                    iabx(OP_CLOSURE, 2, 0),
                    iabc(OP_MOVE, 0, 1, 0), // binding descriptor: capture parent R1
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE],
            )
            .with_child(calling_child()),
            expect: vec![(
                call_id("0/0", 1),
                label(ev(&[("0", 0), ("0", 1), ("0", 2)])),
            )],
        },
        Row {
            name: "capture-safe-parent-upvalue-label",
            root: ProtoSpec::root(
                3,
                vec![
                    gettable(1, 0, 0),
                    iabx(OP_CLOSURE, 2, 0),
                    iabc(OP_MOVE, 0, 1, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE],
            )
            .with_child(
                ProtoSpec::child(
                    1,
                    2,
                    vec![
                        iabx(OP_CLOSURE, 0, 0),
                        iabc(OP_GETUPVAL, 0, 0, 0), // binding descriptor: re-capture upvalue 0
                        iabc(OP_RETURN, 0, 1, 0),
                    ],
                    vec![],
                )
                .with_child(calling_child()),
            ),
            expect: vec![(
                call_id("0/0/0", 1),
                label(ev(&[("0", 0), ("0", 1), ("0", 2), ("0/0", 0), ("0/0", 1)])),
            )],
        },
        Row {
            name: "capture-mutable-child-setupval",
            root: ProtoSpec::root(
                3,
                vec![
                    gettable(1, 0, 0),
                    iabx(OP_CLOSURE, 2, 0),
                    iabc(OP_MOVE, 0, 1, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE],
            )
            .with_child(ProtoSpec::child(
                1,
                2,
                vec![
                    iabc(OP_GETUPVAL, 0, 0, 0),
                    iabc(OP_SETUPVAL, 0, 0, 0),
                    iabc(OP_CALL, 0, 1, 1),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![],
            )),
            expect: vec![(
                call_id("0/0", 2),
                Expected::Stop {
                    reason: STOP_MUTABLE_CAPTURE,
                },
            )],
        },
        Row {
            name: "capture-mutable-parent-write-after",
            root: ProtoSpec::root(
                3,
                vec![
                    gettable(1, 0, 0),
                    iabx(OP_CLOSURE, 2, 0),
                    iabc(OP_MOVE, 0, 1, 0),
                    iabc(OP_NEWTABLE, 1, 0, 0), // the captured cell is written afterwards
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE],
            )
            .with_child(calling_child()),
            expect: vec![(
                call_id("0/0", 1),
                Expected::Stop {
                    reason: STOP_MUTABLE_CAPTURE,
                },
            )],
        },
        Row {
            name: "capture-repeated-instantiation-equal-labels",
            root: ProtoSpec::root(
                4,
                vec![
                    gettable(1, 0, 0),
                    iabx(OP_CLOSURE, 2, 0),
                    iabc(OP_MOVE, 0, 1, 0),
                    gettable(3, 0, 0),
                    iabx(OP_CLOSURE, 2, 0),
                    iabc(OP_MOVE, 0, 3, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE],
            )
            .with_child(calling_child()),
            expect: vec![(
                call_id("0/0", 1),
                label(ev(&[
                    ("0", 0),
                    ("0", 1),
                    ("0", 2),
                    ("0", 3),
                    ("0", 4),
                    ("0", 5),
                ])),
            )],
        },
        Row {
            name: "capture-repeated-instantiation-conflicting-labels",
            root: ProtoSpec::root(
                4,
                vec![
                    gettable(1, 0, 0),
                    iabx(OP_CLOSURE, 2, 0),
                    iabc(OP_MOVE, 0, 1, 0),
                    gettable(3, 0, 1),
                    iabx(OP_CLOSURE, 2, 0),
                    iabc(OP_MOVE, 0, 3, 0),
                    iabc(OP_RETURN, 0, 1, 0),
                ],
                vec![KEY_EXECUTE, KEY_CALL],
            )
            .with_child(calling_child()),
            expect: vec![(
                call_id("0/0", 1),
                Expected::Stop {
                    reason: STOP_AMBIGUOUS_CAPTURE,
                },
            )],
        },
    ]
}

fn matrix() -> Vec<Row> {
    let mut rows = vec![
        immediate_row(
            "gettable-string-key-immediate-call",
            LookupKind::GetTable,
            KEY_EXECUTE,
        ),
        immediate_row(
            "self-string-key-immediate-call",
            LookupKind::SelfOp,
            KEY_CALL,
        ),
    ];
    rows.extend(typed_key_rows());
    rows.extend(join_rows());
    rows.extend(flow_rows());
    rows.extend(stronger_result_rows());
    rows.extend(capture_rows());
    rows
}

// ===========================================================================
// 7. Public observation: pure comparators over serialized production output.
// ===========================================================================

/// A canonical, key-sorted rendering of a JSON value so that comparison is exact and
/// independent of map ordering. `-0.0` and `0.0` render differently, which is what the
/// signed-zero rows depend on.
fn canonical(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => format!("{text:?}"),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Value::Object(map) => {
            let mut entries: Vec<String> = map
                .iter()
                .map(|(key, nested)| format!("{key:?}:{}", canonical(nested)))
                .collect();
            entries.sort();
            format!("{{{}}}", entries.join(","))
        }
    }
}

fn evidence_order_key(id: &str) -> Option<(Vec<usize>, usize)> {
    let rest = id.strip_prefix("proto:")?;
    let (path, tail) = rest.split_once(':')?;
    let pc = tail.strip_prefix("pc:")?.parse().ok()?;
    let components: Option<Vec<usize>> = path.split('/').map(|part| part.parse().ok()).collect();
    Some((components?, pc))
}

/// Every way one observed resolution departs from the required outcome. An empty result is
/// the only accepting answer.
fn resolution_mismatches(expected: &Expected, observed: &Value) -> Vec<String> {
    let mut mismatches = Vec::new();
    let required = expected.callee_wire();
    if canonical(&required) != canonical(observed) {
        mismatches.push(format!(
            "resolution mismatch\n  expected {}\n  observed {}",
            canonical(&required),
            canonical(observed)
        ));
    }

    let Some(map) = observed.as_object() else {
        mismatches.push("resolution is not a JSON object".to_string());
        return mismatches;
    };

    if matches!(expected, Expected::LookupLabel { .. }) {
        let keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let allowed: BTreeSet<&str> = ["status", "lookup_kind", "key", "evidence"]
            .into_iter()
            .collect();
        if keys != allowed {
            mismatches.push(format!(
                "lookup-label fields are {keys:?}, required {allowed:?}"
            ));
        }
    }
    for key in map.keys() {
        if key.to_lowercase().contains("receiver") {
            mismatches.push(format!("result carries a receiver-derived field '{key}'"));
        }
    }

    if let Some(entries) = map.get("evidence").and_then(Value::as_array) {
        let mut previous: Option<(Vec<usize>, usize)> = None;
        for entry in entries {
            let Some(text) = entry.as_str() else {
                mismatches.push(format!("evidence entry {entry} is not a stable ID string"));
                continue;
            };
            let Some(order) = evidence_order_key(text) else {
                mismatches.push(format!(
                    "evidence entry '{text}' is not an instruction stable ID"
                ));
                continue;
            };
            if let Some(previous) = &previous {
                if *previous >= order {
                    mismatches.push(format!(
                        "evidence is not sorted and deduplicated at '{text}'"
                    ));
                }
            }
            previous = Some(order);
        }
    } else if !matches!(expected, Expected::Stop { .. }) {
        mismatches.push("a preserved result must publish an evidence array".to_string());
    }

    mismatches
}

fn relation_mismatches(expected: &Expected, observed: &Value) -> Vec<String> {
    let required = expected.relation_wire();
    if canonical(&required) == canonical(observed) {
        return Vec::new();
    }
    vec![format!(
        "call relation mismatch\n  expected {}\n  observed {}",
        canonical(&required),
        canonical(observed)
    )]
}

/// Compare the `calls` cross-references a chunk publishes against the only edges the
/// contract licenses: exact closure values. A constant-key label never creates one.
fn calls_xref_mismatches(
    expect: &[(String, Expected)],
    observed: &BTreeMap<String, String>,
) -> Vec<String> {
    let required: BTreeMap<String, String> = expect
        .iter()
        .filter_map(|(id, outcome)| {
            outcome
                .calls_xref_target()
                .map(|target| (id.clone(), target))
        })
        .collect();
    if required == *observed {
        return Vec::new();
    }
    vec![format!(
        "calls xrefs are {observed:?}, required {required:?}"
    )]
}

// ===========================================================================
// 8. Public CLI helpers.
// ===========================================================================

fn workspace_root() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn luad_bin() -> PathBuf {
    static LUAD: OnceLock<PathBuf> = OnceLock::new();
    LUAD.get_or_init(|| {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
            return path.into();
        }
        let root = workspace_root();
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
    })
    .clone()
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

fn jsonl_records(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("JSONL record"))
        .collect()
}

/// Every serialized callee fact in one analysis document, indexed by physical call ID.
fn facts_by_call_id(document: &Value) -> BTreeMap<String, Value> {
    let mut collected = Vec::new();
    collect_call_facts(document, &mut collected);
    collected
        .into_iter()
        .map(|fact| {
            (
                fact["call_id"]
                    .as_str()
                    .expect("call_id string")
                    .to_string(),
                fact,
            )
        })
        .collect()
}

fn collect_call_facts(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            if map.contains_key("call_id") && map.contains_key("resolution") {
                out.push(value.clone());
            }
            for nested in map.values() {
                collect_call_facts(nested, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_call_facts(item, out)),
        _ => {}
    }
}

/// The chunk, its file, and the serialized library analyses for one matrix row.
struct Observation {
    chunk: Chunk,
    file: NamedTempFile,
    callees: Value,
    relations: Value,
    xrefs: Value,
}

fn observe(row: &Row) -> Observation {
    let bytes = build_chunk(&row.root);
    let chunk = parse_chunk(&bytes);
    let errors: Vec<_> = chunk
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == luad_core::diagnostic::Severity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "{}: synthesized chunk must parse cleanly: {errors:?}",
        row.name
    );
    Observation {
        callees: serde_json::to_value(luad_analysis::analyze_chunk_callees(&chunk))
            .expect("serialize callee analysis"),
        relations: serde_json::to_value(luad_analysis::analyze_chunk_call_relations(&chunk))
            .expect("serialize call-relation analysis"),
        xrefs: serde_json::to_value(luad_analysis::XrefIndex::build(&chunk))
            .expect("serialize xref index"),
        file: temp_chunk(&bytes),
        chunk,
    }
}

fn calls_xrefs(index: &Value) -> BTreeMap<String, String> {
    index["entries"]
        .as_array()
        .expect("xref entries")
        .iter()
        .filter(|entry| entry["relation"] == "calls")
        .map(|entry| {
            (
                entry["source"].as_str().expect("source").to_string(),
                entry["target"].as_str().expect("target").to_string(),
            )
        })
        .collect()
}

// ===========================================================================
// 9. Tests.
// ===========================================================================

#[test]
fn test_independent_model_reproduces_the_hand_written_lookup_label_matrix() {
    // The RK(C) encoding itself, proved by the independent decoder before any chunk exists.
    assert_eq!(decode_rk(0), Rk::Register(0));
    assert_eq!(decode_rk(255), Rk::Register(255));
    assert_eq!(decode_rk(BITRK), Rk::Constant(0));
    assert_eq!(decode_rk(BITRK | 1), Rk::Constant(1));
    assert_eq!(decode_rk(BITRK | 255), Rk::Constant(255));
    let word = gettable(1, 0, 7);
    assert_eq!(opcode_of(word), OP_GETTABLE);
    assert_eq!(field_a(word), 1);
    assert_eq!(field_b(word), 0);
    assert_eq!(decode_rk(field_c(word)), Rk::Constant(7));
    let method = self_op(4, 2, 3);
    assert_eq!(opcode_of(method), OP_SELF);
    assert_eq!(field_a(method), 4);
    assert_eq!(field_b(method), 2);
    assert_eq!(decode_rk(field_c(method)), Rk::Constant(3));

    for row in matrix() {
        // The writer is authoritative over the bytes: the parsed chunk must return exactly
        // the words and constants this family wrote.
        let chunk = parse_chunk(&build_chunk(&row.root));
        let observed_words: Vec<u32> = chunk
            .main_proto
            .instructions
            .iter()
            .map(|instruction| instruction.raw_word)
            .collect();
        assert_eq!(
            observed_words, row.root.code,
            "{}: physical words must round-trip",
            row.name
        );
        assert_eq!(
            chunk.main_proto.constants.len(),
            row.root.constants.len(),
            "{}: constant table size must round-trip",
            row.name
        );
        for (index, constant) in row.root.constants.iter().enumerate() {
            let observed = serde_json::to_value(&chunk.main_proto.constants[index].value)
                .expect("serialize constant");
            assert_eq!(
                canonical(&observed),
                canonical(&constant.wire()),
                "{}: constant K{index} must round-trip byte-exactly",
                row.name
            );
        }

        // Every constant-key lookup word decodes to the key the hand table names.
        for pc in 0..row.root.code.len() {
            let word = row.root.code[pc];
            if !matches!(opcode_of(word), OP_GETTABLE | OP_SELF) {
                continue;
            }
            if let Rk::Constant(index) = decode_rk(field_c(word)) {
                assert!(
                    index < row.root.constants.len(),
                    "{}: RK(C) constant index {index} is out of range at PC {pc}",
                    row.name
                );
            }
        }

        let modelled = model_chunk(&row.root, ModelFlags::REFERENCE);
        let hand: BTreeMap<String, Expected> = row.expect.iter().cloned().collect();
        assert_eq!(
            modelled.keys().collect::<Vec<_>>(),
            hand.keys().collect::<Vec<_>>(),
            "{}: the model and the hand table must describe the same physical calls",
            row.name
        );
        for (id, expected) in &hand {
            assert_eq!(
                &modelled[id], expected,
                "{}: independent model disagrees with the hand table at {id}",
                row.name
            );
        }
    }
}

#[test]
fn test_independent_model_and_comparator_reject_killer_mutations() {
    let rows = matrix();
    let reference: Vec<BTreeMap<String, Expected>> = rows
        .iter()
        .map(|row| row.expect.iter().cloned().collect())
        .collect();

    let mutants: [(&str, ModelFlags); 11] = [
        (
            "dropped the RK(C) key operand",
            ModelFlags {
                drop_key_operand: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "treated every label as SELF",
            ModelFlags {
                all_labels_are_self: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "merged different keys and lookup kinds",
            ModelFlags {
                merge_any_two_labels: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "compared keys numerically instead of byte-exactly",
            ModelFlags {
                numeric_key_equality: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "dropped one branch's lookup evidence",
            ModelFlags {
                drop_branch_evidence: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "erased an alias evidence hop",
            ModelFlags {
                erase_alias_hop: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "converted a lookup label into a symbolic path",
            ModelFlags {
                label_becomes_path: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "downgraded a provable path to a lookup label",
            ModelFlags {
                path_becomes_label: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "replaced an explicit stop reason with a plausible label",
            ModelFlags {
                stop_becomes_label: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "let NaN keys take part in equal joins",
            ModelFlags {
                nan_joins: true,
                ..ModelFlags::REFERENCE
            },
        ),
        (
            "folded receiver evidence into the label",
            ModelFlags {
                receiver_evidence: true,
                ..ModelFlags::REFERENCE
            },
        ),
    ];

    for (name, flags) in mutants {
        let differs = rows
            .iter()
            .zip(&reference)
            .any(|(row, expected)| model_chunk(&row.root, flags) != *expected);
        assert!(differs, "model killer mutation survived: {name}");
    }

    // Comparator killers: every plausible production defect in the published object must be
    // reported, and a faithful observation must be accepted.
    let expected = Expected::label(LookupKind::GetTable, KEY_EXECUTE, ev(&[("0", 0), ("0", 2)]));
    let faithful = expected.callee_wire();
    assert!(
        resolution_mismatches(&expected, &faithful).is_empty(),
        "the comparator must accept a faithful observation"
    );

    let mut receiver_field = faithful.clone();
    receiver_field["receiver_register"] = json!(0);

    let mut renamed_kind = faithful.clone();
    let kind = renamed_kind["lookup_kind"].clone();
    renamed_kind
        .as_object_mut()
        .expect("object")
        .remove("lookup_kind");
    renamed_kind["kind"] = kind;

    let mut dropped_key = faithful.clone();
    dropped_key.as_object_mut().expect("object").remove("key");

    let mut self_kind = faithful.clone();
    self_kind["lookup_kind"] = json!("self");

    let mut stringified = faithful.clone();
    stringified["key"] = json!("execute");

    let mut unsorted = faithful.clone();
    unsorted["evidence"] = json!(["proto:0:pc:2", "proto:0:pc:0"]);

    let mut duplicated = faithful.clone();
    duplicated["evidence"] = json!(["proto:0:pc:0", "proto:0:pc:0", "proto:0:pc:2"]);

    let mut non_instruction = faithful.clone();
    non_instruction["evidence"] = json!(["proto:0:k:0", "proto:0:pc:2"]);

    let mut promoted = faithful.clone();
    promoted["status"] = json!("resolved-path");

    for (name, observation) in [
        ("receiver-derived field published", receiver_field),
        ("lookup kind renamed", renamed_kind),
        ("key operand dropped", dropped_key),
        ("every label reported as SELF", self_kind),
        ("typed key silently stringified", stringified),
        ("evidence not sorted", unsorted),
        ("evidence not deduplicated", duplicated),
        ("evidence cites a non-instruction artifact", non_instruction),
        ("label promoted to a symbolic path", promoted),
    ] {
        assert!(
            !resolution_mismatches(&expected, &observation).is_empty(),
            "comparator killer mutation survived: {name}"
        );
    }

    // Relation and xref comparators.
    assert!(
        relation_mismatches(&expected, &expected.relation_wire()).is_empty(),
        "the relation comparator must accept a faithful observation"
    );
    let mut exact_edge = expected.relation_wire();
    exact_edge["status"] = json!("resolved");
    assert!(
        !relation_mismatches(&expected, &exact_edge).is_empty(),
        "a lookup label must never become an exact call relation"
    );
    let mut without_evidence = expected.relation_wire();
    without_evidence["evidence"] = json!([]);
    assert!(
        !relation_mismatches(&expected, &without_evidence).is_empty(),
        "an unresolved lookup-label relation must retain the label's evidence"
    );

    let labelled = vec![(call_id("0", 1), expected.clone())];
    assert!(
        calls_xref_mismatches(&labelled, &BTreeMap::new()).is_empty(),
        "a labelled call licenses no calls xref"
    );
    let invented: BTreeMap<String, String> = [(call_id("0", 1), "proto:0/0".to_string())]
        .into_iter()
        .collect();
    assert!(
        !calls_xref_mismatches(&labelled, &invented).is_empty(),
        "an invented exact call edge must be detected"
    );
    let prototype_row = vec![(
        call_id("0", 1),
        Expected::Prototype {
            prototype: vec![0, 0],
            evidence: ev(&[("0", 0)]),
        },
    )];
    assert!(
        !calls_xref_mismatches(&prototype_row, &BTreeMap::new()).is_empty(),
        "dropping a licensed exact call edge must be detected"
    );
}

#[test]
fn test_library_callee_facts_match_the_independent_lookup_label_matrix() {
    for row in matrix() {
        let observation = observe(&row);
        let facts = facts_by_call_id(&observation.callees);
        let expected: BTreeMap<String, Expected> = row.expect.iter().cloned().collect();
        assert_eq!(
            facts.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "{}: one fact per physical call, and no invented calls",
            row.name
        );

        for (id, outcome) in &expected {
            let fact = &facts[id];
            let mismatches = resolution_mismatches(outcome, &fact["resolution"]);
            assert!(
                mismatches.is_empty(),
                "{}: {id} departs from the contract: {mismatches:?}",
                row.name
            );

            // The physical call identity published alongside the outcome.
            let (path, pc) = evidence_order_key(id).expect("call ID is an instruction ID");
            assert_eq!(
                fact["pc"].as_u64(),
                Some(pc as u64),
                "{}: {id} physical PC",
                row.name
            );
            assert_eq!(
                fact["proto_path"].as_str(),
                Some(path_text(&path).as_str()),
                "{}: {id} owning prototype",
                row.name
            );
            let spec = proto_spec_at(&row.root, &path[1..]);
            let word = spec.code[pc];
            let kind = if opcode_of(word) == OP_TAILCALL {
                "TAILCALL"
            } else {
                "CALL"
            };
            assert_eq!(
                fact["call_kind"].as_str(),
                Some(kind),
                "{}: {id} call kind",
                row.name
            );
            assert_eq!(
                fact["callee_register"].as_u64(),
                Some(u64::from(field_a(word))),
                "{}: {id} callee register",
                row.name
            );
            let fields: BTreeSet<&str> = fact
                .as_object()
                .expect("fact object")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                fields,
                BTreeSet::from([
                    "call_id",
                    "proto_path",
                    "pc",
                    "call_kind",
                    "callee_register",
                    "resolution",
                ]),
                "{}: {id} publishes an unexpected fact field set",
                row.name
            );
        }

        // Deterministic repetition of the library analysis.
        let repeated =
            serde_json::to_value(luad_analysis::analyze_chunk_callees(&observation.chunk))
                .expect("serialize repeated analysis");
        assert_eq!(
            canonical(&repeated),
            canonical(&observation.callees),
            "{}: repeated analysis must be byte-identical",
            row.name
        );
    }
}

fn proto_spec_at<'a>(root: &'a ProtoSpec, path: &[usize]) -> &'a ProtoSpec {
    let mut current = root;
    for index in path {
        current = &current.children[*index];
    }
    current
}

#[test]
fn test_call_relations_and_xrefs_preserve_the_no_exact_edge_boundary() {
    for row in matrix() {
        let observation = observe(&row);
        let relations = facts_by_call_id(&observation.relations);
        let expected: BTreeMap<String, Expected> = row.expect.iter().cloned().collect();
        assert_eq!(
            relations.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "{}: every physical call keeps exactly one total relation",
            row.name
        );
        for (id, outcome) in &expected {
            let mismatches = relation_mismatches(outcome, &relations[id]["resolution"]);
            assert!(
                mismatches.is_empty(),
                "{}: {id} relation departs from the contract: {mismatches:?}",
                row.name
            );
        }

        let observed = calls_xrefs(&observation.xrefs);
        let mismatches = calls_xref_mismatches(&row.expect, &observed);
        assert!(
            mismatches.is_empty(),
            "{}: exact call edges departed from the contract: {mismatches:?}",
            row.name
        );

        // The same boundary on the public callgraph command.
        let path = observation.file.path().to_str().expect("UTF-8 path");
        let document =
            run_luad_json(&["callgraph", path, "--dialect", "lua5.1", "--format", "json"]);
        let public = facts_by_call_id(&document);
        for (id, outcome) in &expected {
            let mismatches = relation_mismatches(outcome, &public[id]["resolution"]);
            assert!(
                mismatches.is_empty(),
                "{}: public callgraph {id} departs from the contract: {mismatches:?}",
                row.name
            );
        }
    }
}

#[test]
fn test_public_cli_text_json_jsonl_and_export_agree_on_lookup_labels() {
    for row in matrix() {
        let observation = observe(&row);
        let path = observation.file.path().to_str().expect("UTF-8 path");
        let expected: BTreeMap<String, Expected> = row.expect.iter().cloned().collect();

        // JSON, and deterministic repetition of the public command.
        let json_stdout =
            run_luad_ok(&["callees", path, "--dialect", "lua5.1", "--format", "json"]);
        let repeated = run_luad_ok(&["callees", path, "--dialect", "lua5.1", "--format", "json"]);
        assert_eq!(
            json_stdout, repeated,
            "{}: repeated JSON invocations must be byte-identical",
            row.name
        );
        let document: Value = serde_json::from_str(&json_stdout).expect("callees JSON");
        let json_facts = facts_by_call_id(&document);

        // JSONL.
        let jsonl_stdout =
            run_luad_ok(&["callees", path, "--dialect", "lua5.1", "--format", "jsonl"]);
        let jsonl_facts: BTreeMap<String, Value> = jsonl_records(&jsonl_stdout)
            .into_iter()
            .filter(|record| record["record_type"] == "callee")
            .map(|record| {
                (
                    record["data"]["call_id"]
                        .as_str()
                        .expect("call_id")
                        .to_string(),
                    record["data"].clone(),
                )
            })
            .collect();

        // Recursive export, and its determinism.
        let export_stdout = run_luad_ok(&["export", path, "--format", "jsonl"]);
        assert_eq!(
            export_stdout,
            run_luad_ok(&["export", path, "--format", "jsonl"]),
            "{}: repeated export invocations must be byte-identical",
            row.name
        );
        let export_records = jsonl_records(&export_stdout);
        let export_facts: BTreeMap<String, Value> = export_records
            .iter()
            .filter(|record| record["record_type"] == "callee")
            .map(|record| {
                (
                    record["data"]["call_id"]
                        .as_str()
                        .expect("call_id")
                        .to_string(),
                    record["data"].clone(),
                )
            })
            .collect();
        let export_relations: BTreeMap<String, Value> = export_records
            .iter()
            .filter(|record| record["record_type"] == "call_relation")
            .map(|record| {
                (
                    record["data"]["call_id"]
                        .as_str()
                        .expect("call_id")
                        .to_string(),
                    record["data"].clone(),
                )
            })
            .collect();
        let export_calls_xrefs: BTreeMap<String, String> = export_records
            .iter()
            .filter(|record| {
                record["record_type"] == "xref" && record["data"]["relation"] == "calls"
            })
            .map(|record| {
                (
                    record["data"]["source"]
                        .as_str()
                        .expect("source")
                        .to_string(),
                    record["data"]["target"]
                        .as_str()
                        .expect("target")
                        .to_string(),
                )
            })
            .collect();
        let mismatches = calls_xref_mismatches(&row.expect, &export_calls_xrefs);
        assert!(
            mismatches.is_empty(),
            "{}: recursive export published unlicensed exact call edges: {mismatches:?}",
            row.name
        );

        // Text.
        let text_stdout =
            run_luad_ok(&["callees", path, "--dialect", "lua5.1", "--format", "text"]);
        assert_eq!(
            text_stdout
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count(),
            expected.len(),
            "{}: one text line per physical call",
            row.name
        );

        for (id, outcome) in &expected {
            for (surface, fact) in [
                ("json", &json_facts[id]),
                ("jsonl", &jsonl_facts[id]),
                ("export", &export_facts[id]),
            ] {
                let mismatches = resolution_mismatches(outcome, &fact["resolution"]);
                assert!(
                    mismatches.is_empty(),
                    "{} [{surface}]: {id} departs from the contract: {mismatches:?}",
                    row.name
                );
            }
            let mismatches = relation_mismatches(outcome, &export_relations[id]["resolution"]);
            assert!(
                mismatches.is_empty(),
                "{} [export]: {id} relation departs from the contract: {mismatches:?}",
                row.name
            );

            let line = text_stdout
                .lines()
                .find(|line| line.split_whitespace().next() == Some(id.as_str()))
                .unwrap_or_else(|| panic!("{}: no text line for {id}:\n{text_stdout}", row.name));
            let lowered = line.to_lowercase();
            for id_text in outcome.evidence().iter().map(EvId::text) {
                assert!(
                    line.contains(&id_text),
                    "{}: text rendering of {id} must cite {id_text}: {line:?}",
                    row.name
                );
            }
            if let Expected::LookupLabel { kind, key, .. } = outcome {
                assert!(
                    lowered.contains(kind.wire()),
                    "{}: text rendering of {id} must name the lookup form {}: {line:?}",
                    row.name,
                    kind.wire()
                );
                // Human text may render an escaped, bounded preview. Only a printable
                // string selector has one obligatory spelling; the typed machine value is
                // asserted on the structured surfaces instead.
                if let KeyConst::Text(bytes) = key {
                    if bytes.is_ascii() {
                        let preview = escape_bytes(bytes);
                        assert!(
                            line.contains(&preview),
                            "{}: text rendering of {id} must preview the selector \
                             {preview:?}: {line:?}",
                            row.name
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn test_lookup_label_bounds_and_stop_reasons_stay_explicit() {
    for row in matrix() {
        let chunk = parse_chunk(&build_chunk(&row.root));

        // A budget that is never reached must reproduce the default analysis exactly.
        assert_eq!(
            luad_analysis::analyze_chunk_callees_with_mutation_budget(&chunk, usize::MAX),
            luad_analysis::analyze_chunk_callees(&chunk),
            "{}: an unreached bound must not change the answer",
            row.name
        );

        // Reaching the analysis bound stops explicitly and never invents a label.
        let starved = serde_json::to_value(
            luad_analysis::analyze_chunk_callees_with_mutation_budget(&chunk, 0),
        )
        .expect("serialize starved analysis");
        let facts = facts_by_call_id(&starved);
        let expected: BTreeMap<String, Expected> = row.expect.iter().cloned().collect();
        assert_eq!(
            facts.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "{}: exhaustion must still enumerate every physical call",
            row.name
        );
        for (id, fact) in &facts {
            let mismatches = resolution_mismatches(
                &Expected::Stop {
                    reason: STOP_ANALYSIS_LIMIT,
                },
                &fact["resolution"],
            );
            assert!(
                mismatches.is_empty(),
                "{}: exhaustion at {id} must stop explicitly: {mismatches:?}",
                row.name
            );
        }
    }

    // Every stop reason this family reaches is a member of the frozen callee vocabulary:
    // the new lookup label adds no unresolved variant.
    let reached: BTreeSet<&str> = matrix()
        .iter()
        .flat_map(|row| row.expect.clone())
        .filter_map(|(_, outcome)| match outcome {
            Expected::Stop { reason } => Some(reason),
            _ => None,
        })
        .collect();
    for reason in [
        STOP_CONTROL_FLOW_CONFLICT,
        STOP_DYNAMIC_KEY,
        STOP_OVERWRITTEN,
        STOP_OPEN_REGISTER_WINDOW,
        STOP_MUTABLE_CAPTURE,
        STOP_AMBIGUOUS_CAPTURE,
        STOP_UNREACHABLE,
    ] {
        assert!(
            reached.contains(reason),
            "the matrix must exercise the {reason} stop"
        );
    }
}

#[test]
fn test_query_grammar_never_matches_lookup_labels() {
    let row = matrix()
        .into_iter()
        .find(|row| row.name == "gettable-string-key-immediate-call")
        .expect("the canonical GETTABLE row");
    let file = temp_chunk(&build_chunk(&row.root));
    let path = file.path().to_str().expect("UTF-8 path");

    // No callee-path or lookup-label predicate enters the grammar in this sprint.
    for predicate in [
        "lookup_label == \"execute\"",
        "lookup.kind == gettable",
        "callee == \"execute\"",
        "callee.path == \"execute\"",
        "callee.key == \"execute\"",
    ] {
        let output = run_luad(&["query", path, "--where", predicate, "--format", "json"]);
        assert!(
            !output.status.success(),
            "query grammar accepted a lookup-label predicate: {predicate:?}"
        );
    }

    // The predicates that do exist keep matching physical artifacts only.
    for predicate in ["mnemonic == GETTABLE", "string == \"execute\"", "CALL"] {
        let document = run_luad_json(&["query", path, "--where", predicate, "--format", "json"]);
        let matches = find_query_matches(&document);
        assert!(
            !matches.is_empty(),
            "query {predicate:?} must still match physical artifacts"
        );
        for entry in matches {
            let kind = entry["kind"].as_str().expect("match kind");
            assert!(
                ["instruction", "constant", "prototype", "upvalue"].contains(&kind),
                "query returned a {kind} match; lookup labels are not query artifacts"
            );
            let id = entry["id"].as_str().expect("match id");
            assert!(
                !id.contains("lookup"),
                "query returned a lookup-label artifact: {id}"
            );
        }
    }
}

fn find_query_matches(document: &Value) -> Vec<Value> {
    fn walk(value: &Value, out: &mut Vec<Value>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::Array(items)) = map.get("matches") {
                    out.extend(items.iter().cloned());
                }
                for nested in map.values() {
                    walk(nested, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(document, &mut out);
    out
}

/// Every `$ref` anywhere inside one subschema, so that a `$ref` wrapped in `allOf` by the
/// schema generator still counts as the same reference.
fn schema_refs(value: &Value) -> BTreeSet<String> {
    fn walk(value: &Value, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(reference)) = map.get("$ref") {
                    out.insert(reference.clone());
                }
                for nested in map.values() {
                    walk(nested, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, out)),
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    walk(value, &mut out);
    out
}

#[test]
fn test_public_schema_freezes_the_lookup_label_contract() {
    let callees = run_luad_json(&["schema", "callees"]);
    let definitions = &callees["definitions"];

    let variants = definitions["CalleeResolution"]["oneOf"]
        .as_array()
        .expect("CalleeResolution is a tagged union");
    let statuses: BTreeSet<String> = variants
        .iter()
        .filter_map(|variant| {
            variant["properties"]["status"]["enum"][0]
                .as_str()
                .map(ToString::to_string)
        })
        .collect();
    assert_eq!(
        statuses,
        BTreeSet::from([
            "lookup-label".to_string(),
            "resolved-path".to_string(),
            "resolved-prototype".to_string(),
            "unresolved".to_string(),
        ]),
        "the lookup label must be a distinct tagged result, not a rootless path"
    );

    let label = variants
        .iter()
        .find(|variant| variant["properties"]["status"]["enum"][0] == "lookup-label")
        .expect("lookup-label variant");
    let properties: BTreeSet<&str> = label["properties"]
        .as_object()
        .expect("lookup-label properties")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        properties,
        BTreeSet::from(["status", "lookup_kind", "key", "evidence"]),
        "the lookup label publishes no receiver-derived field"
    );
    assert!(
        schema_refs(&label["properties"]["key"]).contains("#/definitions/ConstantValue"),
        "the key must keep the normal ConstantValue machine encoding, got {}",
        label["properties"]["key"]
    );
    assert!(
        definitions["ConstantValue"].is_object(),
        "the published schema must define ConstantValue"
    );

    let reasons: BTreeSet<String> = definitions["CalleeUnresolvedReason"]["enum"]
        .as_array()
        .expect("CalleeUnresolvedReason enum")
        .iter()
        .map(|value| value.as_str().expect("reason").to_string())
        .collect();
    assert_eq!(
        reasons,
        [
            "missing-definition",
            "control-flow-conflict",
            "dynamic-key",
            "overwritten",
            "call-result",
            "open-register-window",
            "unsupported-value",
            "unsupported-instruction",
            "mutable-capture",
            "ambiguous-capture",
            "path-limit",
            "analysis-limit",
            "unreachable",
        ]
        .into_iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>(),
        "CalleeUnresolvedReason gains no variant in this sprint"
    );

    let callgraph = run_luad_json(&["schema", "callgraph"]);
    let relation_reasons: BTreeSet<String> = callgraph["definitions"]
        ["CallRelationUnresolvedReason"]["enum"]
        .as_array()
        .expect("CallRelationUnresolvedReason enum")
        .iter()
        .map(|value| value.as_str().expect("reason").to_string())
        .collect();
    assert!(
        relation_reasons.contains("lookup-label-only"),
        "the unresolved call relation must name the lookup-label-only reason"
    );
    let mut required: BTreeSet<String> = reasons.clone();
    for extra in [
        "symbolic-path-only",
        "missing-prototype-store",
        "multiple-prototype-stores",
        "non-closure-store",
        "ambiguous-store-value",
        "lookup-label-only",
    ] {
        required.insert(extra.to_string());
    }
    assert_eq!(
        relation_reasons, required,
        "the call-relation vocabulary gains exactly one additive member"
    );
}
