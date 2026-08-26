//! Bounded symbolic callee analysis over the normalized instruction and CFG facts.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use luad_core::{
    EffectTarget, ImplicitEffect, ProtoPath, SemanticInstruction, StableId, TypedOperand,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ControlFlowGraph;

const MAX_PATH_SEGMENTS: usize = 32;
const MAX_TRANSFER_STEPS: usize = 1_000_000;

/// Which physical opcode selected the callee value.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum CalleeLookupKind {
    /// Lookup via `GETTABLE`.
    Gettable,
    /// Lookup via `SELF`.
    #[serde(rename = "self")]
    SelfOp,
}

/// Epistemic basis for a symbolic Lua value label.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolicPathBasis {
    /// A path rooted in a literal global-table lookup.
    GlobalLabel,
    /// A path rooted in the result of a literal `require` call.
    ModuleLabel,
}

/// Closed reasons why a call target is not resolved.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum CalleeUnresolvedReason {
    MissingDefinition,
    ControlFlowConflict,
    DynamicKey,
    Overwritten,
    CallResult,
    OpenRegisterWindow,
    UnsupportedValue,
    UnsupportedInstruction,
    MutableCapture,
    AmbiguousCapture,
    PathLimit,
    AnalysisLimit,
    Unreachable,
}

/// Resolution attached to one physical call instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CalleeResolution {
    /// A constant-key lookup selector proved by the listed bytecode instructions.
    LookupLabel {
        lookup_kind: CalleeLookupKind,
        key: luad_core::model::ConstantValue,
        evidence: Vec<StableId>,
    },
    /// A symbolic label path proved by the listed bytecode instructions.
    ResolvedPath {
        basis: SymbolicPathBasis,
        segments: Vec<String>,
        evidence: Vec<StableId>,
    },
    /// A directly constructed closure whose child prototype identity is proved.
    ResolvedPrototype {
        prototype: ProtoPath,
        evidence: Vec<StableId>,
    },
    /// No symbolic label path is proved.
    Unresolved { reason: CalleeUnresolvedReason },
}

/// One auditable callee result for a `CALL` or `TAILCALL` instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CalleeFact {
    pub call_id: StableId,
    pub proto_path: ProtoPath,
    pub pc: usize,
    pub call_kind: String,
    pub callee_register: u8,
    pub resolution: CalleeResolution,
}

/// Callee facts for one prototype.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CalleeAnalysis {
    pub proto_id: StableId,
    pub calls: Vec<CalleeFact>,
}

/// Callee facts for every prototype in one parsed chunk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChunkCalleeAnalysis {
    pub prototypes: Vec<CalleeAnalysis>,
}

/// A caller-supplied fact about one captured upvalue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CaptureValue {
    LookupLabel {
        lookup_kind: CalleeLookupKind,
        key: luad_core::model::ConstantValue,
        evidence: Vec<StableId>,
    },
    SymbolicPath {
        basis: SymbolicPathBasis,
        segments: Vec<String>,
        evidence: Vec<StableId>,
    },
    LiteralString {
        value: String,
        evidence: Vec<StableId>,
    },
    Closure {
        prototype: ProtoPath,
        evidence: Vec<StableId>,
    },
    Unknown {
        reason: CalleeUnresolvedReason,
    },
}

/// Conservative upvalue facts supplied to a prototype analysis.
pub type CaptureEnvironment = BTreeMap<u8, CaptureValue>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GlobalStoreValue {
    Closure {
        prototype: ProtoPath,
        evidence: Vec<StableId>,
    },
    NonClosure {
        evidence: Vec<StableId>,
    },
    Unknown {
        reason: CalleeUnresolvedReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalStoreFact {
    pub name_raw: Vec<u8>,
    pub store_id: StableId,
    pub value: GlobalStoreValue,
}

#[derive(Debug, Clone, PartialEq)]
enum ValueKind {
    LookupLabel {
        lookup_kind: CalleeLookupKind,
        key: luad_core::model::ConstantValue,
    },
    SymbolicPath {
        basis: SymbolicPathBasis,
        segments: Vec<String>,
    },
    LiteralString(String),
    Closure(ProtoPath),
    NonClosure,
}

struct DataflowResult {
    in_states: Vec<RegisterState>,
    exhausted: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct KnownValue {
    kind: ValueKind,
    evidence: BTreeSet<StableId>,
}

#[derive(Debug, Clone, PartialEq)]
enum FlowValue {
    Bottom,
    Known(KnownValue),
    Unknown(CalleeUnresolvedReason),
}

type RegisterState = Vec<FlowValue>;

/// Analyze one prototype using a conservative environment for its captured upvalues.
#[must_use]
pub fn analyze_callees(
    proto_path: &ProtoPath,
    maxstacksize: u8,
    instructions: &[SemanticInstruction],
    cfg: &ControlFlowGraph,
    captures: &CaptureEnvironment,
) -> CalleeAnalysis {
    let dataflow = run_dataflow(maxstacksize, instructions, cfg, captures);
    let calls = if dataflow.exhausted {
        enumerate_with_reason(
            proto_path,
            instructions,
            CalleeUnresolvedReason::AnalysisLimit,
        )
    } else {
        collect_final_calls(
            proto_path,
            instructions,
            cfg,
            &dataflow.in_states,
            captures,
            maxstacksize as usize,
        )
    };

    CalleeAnalysis {
        proto_id: StableId::proto(proto_path.clone()),
        calls,
    }
}

fn run_dataflow(
    maxstacksize: u8,
    instructions: &[SemanticInstruction],
    cfg: &ControlFlowGraph,
    captures: &CaptureEnvironment,
) -> DataflowResult {
    let frame_size = maxstacksize as usize;
    let unknown_entry =
        vec![FlowValue::Unknown(CalleeUnresolvedReason::MissingDefinition); frame_size];
    let bottom = vec![FlowValue::Bottom; frame_size];
    let mut in_states = vec![bottom.clone(); cfg.blocks.len()];
    let mut out_states = vec![bottom; cfg.blocks.len()];
    if let Some(entry) = cfg.blocks.iter().position(|block| block.is_entry) {
        in_states[entry] = unknown_entry;
    }

    let mut worklist: VecDeque<usize> = reverse_postorder(cfg).into();
    let mut queued: BTreeSet<usize> = worklist.iter().copied().collect();
    let mut steps = 0usize;
    let mut exhausted = false;

    while let Some(block_idx) = worklist.pop_front() {
        queued.remove(&block_idx);
        let block = &cfg.blocks[block_idx];
        if !block.is_reachable {
            continue;
        }

        let incoming = if block.is_entry {
            in_states[block_idx].clone()
        } else {
            meet_predecessors(block, &out_states, frame_size)
        };
        if !register_states_equal(&incoming, &in_states[block_idx]) {
            in_states[block_idx] = incoming.clone();
        }

        let mut state = incoming;
        for &pc in &block.instruction_pcs {
            steps = steps.saturating_add(1);
            if steps > MAX_TRANSFER_STEPS {
                exhausted = true;
                break;
            }
            if let Some(inst) = instructions.get(pc) {
                transfer(inst, &mut state, captures, frame_size);
            }
        }
        if exhausted {
            break;
        }

        if !register_states_equal(&state, &out_states[block_idx]) {
            out_states[block_idx] = state;
            for edge in &block.successors {
                if cfg.blocks[edge.to_block].is_reachable && queued.insert(edge.to_block) {
                    worklist.push_back(edge.to_block);
                }
            }
        }
    }

    DataflowResult {
        in_states,
        exhausted,
    }
}

fn reverse_postorder(cfg: &ControlFlowGraph) -> Vec<usize> {
    fn visit(
        index: usize,
        cfg: &ControlFlowGraph,
        seen: &mut BTreeSet<usize>,
        post: &mut Vec<usize>,
    ) {
        if !seen.insert(index) || !cfg.blocks[index].is_reachable {
            return;
        }
        let mut successors: Vec<_> = cfg.blocks[index]
            .successors
            .iter()
            .map(|edge| edge.to_block)
            .collect();
        successors.sort_unstable();
        successors.dedup();
        for successor in successors {
            visit(successor, cfg, seen, post);
        }
        post.push(index);
    }

    let mut seen = BTreeSet::new();
    let mut post = Vec::new();
    if let Some(entry) = cfg.blocks.iter().position(|block| block.is_entry) {
        visit(entry, cfg, &mut seen, &mut post);
    }
    post.reverse();
    post
}

fn meet_predecessors(
    block: &crate::BasicBlock,
    out_states: &[RegisterState],
    frame_size: usize,
) -> RegisterState {
    let mut result = vec![FlowValue::Bottom; frame_size];
    for predecessor in &block.predecessors {
        if let Some(state) = out_states.get(*predecessor) {
            for (slot, incoming) in result.iter_mut().zip(state) {
                *slot = meet_value(slot, incoming);
            }
        }
    }
    result
}

fn keys_join(
    left: &luad_core::model::ConstantValue,
    right: &luad_core::model::ConstantValue,
) -> bool {
    match (left, right) {
        (luad_core::model::ConstantValue::Nil, luad_core::model::ConstantValue::Nil) => true,
        (
            luad_core::model::ConstantValue::Boolean(a),
            luad_core::model::ConstantValue::Boolean(b),
        ) => a == b,
        (
            luad_core::model::ConstantValue::Integer {
                val: v1,
                raw_hex: h1,
            },
            luad_core::model::ConstantValue::Integer {
                val: v2,
                raw_hex: h2,
            },
        ) => v1 == v2 && h1 == h2,
        (
            luad_core::model::ConstantValue::Float {
                raw_hex: h1,
                is_nan: n1,
                ..
            },
            luad_core::model::ConstantValue::Float {
                raw_hex: h2,
                is_nan: n2,
                ..
            },
        ) => {
            if *n1 || *n2 {
                false
            } else {
                h1 == h2
            }
        }
        (
            luad_core::model::ConstantValue::ShortString(s1),
            luad_core::model::ConstantValue::ShortString(s2),
        )
        | (
            luad_core::model::ConstantValue::LongString(s1),
            luad_core::model::ConstantValue::LongString(s2),
        ) => s1.raw_bytes == s2.raw_bytes,
        _ => false,
    }
}

fn constant_values_equal_for_state(
    left: &luad_core::model::ConstantValue,
    right: &luad_core::model::ConstantValue,
) -> bool {
    match (left, right) {
        (luad_core::model::ConstantValue::Nil, luad_core::model::ConstantValue::Nil) => true,
        (
            luad_core::model::ConstantValue::Boolean(left),
            luad_core::model::ConstantValue::Boolean(right),
        ) => left == right,
        (
            luad_core::model::ConstantValue::Integer {
                val: left_val,
                raw_hex: left_hex,
            },
            luad_core::model::ConstantValue::Integer {
                val: right_val,
                raw_hex: right_hex,
            },
        ) => left_val == right_val && left_hex == right_hex,
        (
            luad_core::model::ConstantValue::Float {
                val: left_val,
                raw_hex: left_hex,
                is_nan: left_nan,
                is_inf: left_inf,
            },
            luad_core::model::ConstantValue::Float {
                val: right_val,
                raw_hex: right_hex,
                is_nan: right_nan,
                is_inf: right_inf,
            },
        ) => {
            left_val.to_bits() == right_val.to_bits()
                && left_hex == right_hex
                && left_nan == right_nan
                && left_inf == right_inf
        }
        (
            luad_core::model::ConstantValue::ShortString(left),
            luad_core::model::ConstantValue::ShortString(right),
        )
        | (
            luad_core::model::ConstantValue::LongString(left),
            luad_core::model::ConstantValue::LongString(right),
        ) => left == right,
        _ => false,
    }
}

fn value_kinds_equal_for_state(left: &ValueKind, right: &ValueKind) -> bool {
    match (left, right) {
        (
            ValueKind::LookupLabel {
                lookup_kind: left_kind,
                key: left_key,
            },
            ValueKind::LookupLabel {
                lookup_kind: right_kind,
                key: right_key,
            },
        ) => left_kind == right_kind && constant_values_equal_for_state(left_key, right_key),
        (
            ValueKind::SymbolicPath {
                basis: left_basis,
                segments: left_segments,
            },
            ValueKind::SymbolicPath {
                basis: right_basis,
                segments: right_segments,
            },
        ) => left_basis == right_basis && left_segments == right_segments,
        (ValueKind::LiteralString(left), ValueKind::LiteralString(right)) => left == right,
        (ValueKind::Closure(left), ValueKind::Closure(right)) => left == right,
        (ValueKind::NonClosure, ValueKind::NonClosure) => true,
        _ => false,
    }
}

fn flow_values_equal_for_state(left: &FlowValue, right: &FlowValue) -> bool {
    match (left, right) {
        (FlowValue::Bottom, FlowValue::Bottom) => true,
        (FlowValue::Unknown(left), FlowValue::Unknown(right)) => left == right,
        (FlowValue::Known(left), FlowValue::Known(right)) => {
            left.evidence == right.evidence && value_kinds_equal_for_state(&left.kind, &right.kind)
        }
        _ => false,
    }
}

fn register_states_equal(left: &RegisterState, right: &RegisterState) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| flow_values_equal_for_state(left, right))
}

fn values_join(left: &ValueKind, right: &ValueKind) -> bool {
    match (left, right) {
        (
            ValueKind::LookupLabel {
                lookup_kind: lk,
                key: lkey,
            },
            ValueKind::LookupLabel {
                lookup_kind: rk,
                key: rkey,
            },
        ) => lk == rk && keys_join(lkey, rkey),
        (
            ValueKind::SymbolicPath {
                basis: lb,
                segments: ls,
            },
            ValueKind::SymbolicPath {
                basis: rb,
                segments: rs,
            },
        ) => lb == rb && ls == rs,
        (ValueKind::LiteralString(l), ValueKind::LiteralString(r)) => l == r,
        (ValueKind::Closure(l), ValueKind::Closure(r)) => l == r,
        (ValueKind::NonClosure, ValueKind::NonClosure) => true,
        _ => false,
    }
}

fn meet_value(left: &FlowValue, right: &FlowValue) -> FlowValue {
    match (left, right) {
        (FlowValue::Bottom, value) | (value, FlowValue::Bottom) => value.clone(),
        (FlowValue::Known(a), FlowValue::Known(b)) if values_join(&a.kind, &b.kind) => {
            let mut evidence = a.evidence.clone();
            evidence.extend(b.evidence.iter().cloned());
            FlowValue::Known(KnownValue {
                kind: a.kind.clone(),
                evidence,
            })
        }
        (FlowValue::Unknown(a), FlowValue::Unknown(b)) if a == b => FlowValue::Unknown(*a),
        _ => FlowValue::Unknown(CalleeUnresolvedReason::ControlFlowConflict),
    }
}

fn transfer(
    inst: &SemanticInstruction,
    state: &mut RegisterState,
    captures: &CaptureEnvironment,
    frame_size: usize,
) {
    if is_closure_binding(inst) {
        return;
    }

    let before = state.clone();
    invalidate_writes(inst, state, frame_size);

    match inst.mnemonic.as_str() {
        "LOADK" => {
            if let Some(dest) = register_operand(inst, 0) {
                if let Some(value) = string_operand(inst) {
                    set_known(
                        state,
                        dest,
                        ValueKind::LiteralString(value),
                        [inst.id.clone()],
                    );
                } else if has_constant_operand(inst) {
                    set_known(state, dest, ValueKind::NonClosure, [inst.id.clone()]);
                }
            }
        }
        "GETGLOBAL" => {
            if let (Some(dest), Some(name)) = (register_operand(inst, 0), string_operand(inst)) {
                set_path(
                    state,
                    dest,
                    SymbolicPathBasis::GlobalLabel,
                    vec![name],
                    [inst.id.clone()],
                );
            }
        }
        "MOVE" => {
            if let (Some(dest), Some(source)) =
                (register_operand(inst, 0), register_operand(inst, 1))
            {
                let value = get_register(&before, source);
                set_register(state, dest, add_evidence(value, &inst.id));
            }
        }
        "GETUPVAL" => {
            if let (Some(dest), Some(index)) = (register_operand(inst, 0), upvalue_operand(inst)) {
                set_register(
                    state,
                    dest,
                    captures
                        .get(&index)
                        .map(flow_from_capture)
                        .unwrap_or(FlowValue::Unknown(CalleeUnresolvedReason::AmbiguousCapture)),
                );
            }
        }
        "GETTABLE" => transfer_table_lookup(inst, &before, state, false),
        "SELF" => transfer_table_lookup(inst, &before, state, true),
        "CALL" => transfer_require(inst, &before, state, frame_size),
        "CLOSURE" => {
            if let (Some(dest), Some(path)) = (register_operand(inst, 0), prototype_operand(inst)) {
                set_known(state, dest, ValueKind::Closure(path), [inst.id.clone()]);
            }
        }
        "VARARG" => transfer_vararg(inst, state, frame_size),
        _ => {}
    }
}

fn transfer_table_lookup(
    inst: &SemanticInstruction,
    before: &RegisterState,
    state: &mut RegisterState,
    is_self: bool,
) {
    let Some(dest) = register_operand(inst, 0) else {
        return;
    };
    let Some(source) = register_operand(inst, 1) else {
        return;
    };
    if is_self {
        set_register(state, dest.saturating_add(1), get_register(before, source));
    }
    let Some(key_val) = constant_operand(inst) else {
        set_register(
            state,
            dest,
            FlowValue::Unknown(CalleeUnresolvedReason::DynamicKey),
        );
        return;
    };
    let lookup_kind = if is_self {
        CalleeLookupKind::SelfOp
    } else {
        CalleeLookupKind::Gettable
    };
    let receiver = get_register(before, source);
    let str_segment = match &key_val {
        luad_core::model::ConstantValue::ShortString(s)
        | luad_core::model::ConstantValue::LongString(s) => Some(s.display.clone()),
        _ => None,
    };
    match (receiver, str_segment) {
        (
            FlowValue::Known(KnownValue {
                kind:
                    ValueKind::SymbolicPath {
                        basis,
                        mut segments,
                    },
                mut evidence,
            }),
            Some(segment),
        ) => {
            if segments.len() >= MAX_PATH_SEGMENTS {
                set_register(
                    state,
                    dest,
                    FlowValue::Unknown(CalleeUnresolvedReason::PathLimit),
                );
            } else {
                segments.push(segment);
                evidence.insert(inst.id.clone());
                set_register(
                    state,
                    dest,
                    FlowValue::Known(KnownValue {
                        kind: ValueKind::SymbolicPath { basis, segments },
                        evidence,
                    }),
                );
            }
        }
        _ => {
            set_register(
                state,
                dest,
                FlowValue::Known(KnownValue {
                    kind: ValueKind::LookupLabel {
                        lookup_kind,
                        key: key_val,
                    },
                    evidence: [inst.id.clone()].into_iter().collect(),
                }),
            );
        }
    }
}

fn transfer_require(
    inst: &SemanticInstruction,
    before: &RegisterState,
    state: &mut RegisterState,
    frame_size: usize,
) {
    let Some(base) = register_operand(inst, 0) else {
        return;
    };
    let counts: Vec<_> = inst
        .operands
        .iter()
        .filter_map(|operand| match operand {
            TypedOperand::Count { value, is_variable } => Some((*value, *is_variable)),
            _ => None,
        })
        .collect();
    let exact_shape = matches!(counts.as_slice(), [(2, false), (2, false)]);
    let is_require = matches!(
        get_register(before, base),
        FlowValue::Known(KnownValue {
            kind: ValueKind::SymbolicPath {
                basis: SymbolicPathBasis::GlobalLabel,
                segments,
            },
            ..
        }) if segments == vec!["require".to_string()]
    );
    let argument = get_register(before, base.saturating_add(1));
    if exact_shape && is_require {
        if let FlowValue::Known(KnownValue {
            kind: ValueKind::LiteralString(module),
            mut evidence,
        }) = argument
        {
            let segments: Vec<_> = module
                .split('.')
                .filter(|segment| !segment.is_empty())
                .map(ToString::to_string)
                .collect();
            if segments.is_empty() || segments.len() > MAX_PATH_SEGMENTS {
                set_register(
                    state,
                    base,
                    FlowValue::Unknown(CalleeUnresolvedReason::PathLimit),
                );
            } else {
                if let FlowValue::Known(callee) = get_register(before, base) {
                    evidence.extend(callee.evidence);
                }
                evidence.insert(inst.id.clone());
                set_register(
                    state,
                    base,
                    FlowValue::Known(KnownValue {
                        kind: ValueKind::SymbolicPath {
                            basis: SymbolicPathBasis::ModuleLabel,
                            segments,
                        },
                        evidence,
                    }),
                );
            }
        }
    } else if let Some((_, true)) = counts.get(1) {
        invalidate_from(
            state,
            base,
            frame_size,
            CalleeUnresolvedReason::OpenRegisterWindow,
        );
    }
}

fn transfer_vararg(inst: &SemanticInstruction, state: &mut RegisterState, frame_size: usize) {
    let Some(base) = register_operand(inst, 0) else {
        return;
    };
    let is_variable = inst.operands.iter().any(|operand| {
        matches!(
            operand,
            TypedOperand::Count {
                is_variable: true,
                ..
            }
        )
    });
    if is_variable {
        invalidate_from(
            state,
            base,
            frame_size,
            CalleeUnresolvedReason::OpenRegisterWindow,
        );
    }
}

fn invalidate_writes(inst: &SemanticInstruction, state: &mut RegisterState, frame_size: usize) {
    if !is_known_lua51_mnemonic(inst.mnemonic.as_str()) {
        invalidate_all(
            state,
            frame_size,
            CalleeUnresolvedReason::UnsupportedInstruction,
        );
        return;
    }
    for write in &inst.writes {
        match write {
            EffectTarget::Register { index } => set_register(
                state,
                *index,
                FlowValue::Unknown(CalleeUnresolvedReason::Overwritten),
            ),
            EffectTarget::RegisterRange { start, end } => {
                for index in *start..=*end {
                    set_register(
                        state,
                        index,
                        FlowValue::Unknown(CalleeUnresolvedReason::Overwritten),
                    );
                }
            }
            EffectTarget::RegisterRangeToTop { start } => {
                invalidate_from(
                    state,
                    *start,
                    frame_size,
                    CalleeUnresolvedReason::OpenRegisterWindow,
                );
            }
            _ => {}
        }
    }
}

fn is_known_lua51_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "MOVE"
            | "LOADK"
            | "LOADBOOL"
            | "LOADNIL"
            | "GETUPVAL"
            | "GETGLOBAL"
            | "GETTABLE"
            | "SETGLOBAL"
            | "SETUPVAL"
            | "SETTABLE"
            | "NEWTABLE"
            | "SELF"
            | "ADD"
            | "SUB"
            | "MUL"
            | "DIV"
            | "MOD"
            | "POW"
            | "UNM"
            | "NOT"
            | "LEN"
            | "CONCAT"
            | "JMP"
            | "EQ"
            | "LT"
            | "LE"
            | "TEST"
            | "TESTSET"
            | "CALL"
            | "TAILCALL"
            | "RETURN"
            | "FORLOOP"
            | "FORPREP"
            | "TFORLOOP"
            | "SETLIST"
            | "CLOSE"
            | "CLOSURE"
            | "VARARG"
    )
}

fn is_closure_binding(inst: &SemanticInstruction) -> bool {
    inst.implicit_effects.iter().any(|effect| {
        matches!(
            effect,
            ImplicitEffect::CompanionPair { companion_role, .. }
                if companion_role == "closure_binding"
        )
    })
}

fn collect_final_calls(
    proto_path: &ProtoPath,
    instructions: &[SemanticInstruction],
    cfg: &ControlFlowGraph,
    in_states: &[RegisterState],
    captures: &CaptureEnvironment,
    frame_size: usize,
) -> Vec<CalleeFact> {
    let mut facts = Vec::new();
    let reachable_pcs: BTreeSet<_> = cfg
        .blocks
        .iter()
        .filter(|block| block.is_reachable)
        .flat_map(|block| block.instruction_pcs.iter().copied())
        .collect();

    for block in cfg.blocks.iter().filter(|block| block.is_reachable) {
        let mut state = in_states[block.index].clone();
        for &pc in &block.instruction_pcs {
            let Some(inst) = instructions.get(pc) else {
                continue;
            };
            if is_call(inst) {
                facts.push(fact_from_state(proto_path, inst, &state));
            }
            transfer(inst, &mut state, captures, frame_size);
        }
    }
    for inst in instructions.iter().filter(|inst| is_call(inst)) {
        if !reachable_pcs.contains(&inst.pc) {
            facts.push(fact_with_reason(
                proto_path,
                inst,
                CalleeUnresolvedReason::Unreachable,
            ));
        }
    }
    facts.sort_by_key(|fact| fact.pc);
    facts
}

fn enumerate_with_reason(
    proto_path: &ProtoPath,
    instructions: &[SemanticInstruction],
    reason: CalleeUnresolvedReason,
) -> Vec<CalleeFact> {
    instructions
        .iter()
        .filter(|inst| is_call(inst))
        .map(|inst| fact_with_reason(proto_path, inst, reason))
        .collect()
}

fn fact_from_state(
    proto_path: &ProtoPath,
    inst: &SemanticInstruction,
    state: &[FlowValue],
) -> CalleeFact {
    let register = register_operand(inst, 0).unwrap_or(0);
    let resolution = match get_register(state, register) {
        FlowValue::Known(KnownValue {
            kind: ValueKind::LookupLabel { lookup_kind, key },
            evidence,
        }) => CalleeResolution::LookupLabel {
            lookup_kind,
            key,
            evidence: evidence.into_iter().collect(),
        },
        FlowValue::Known(KnownValue {
            kind: ValueKind::SymbolicPath { basis, segments },
            evidence,
        }) => CalleeResolution::ResolvedPath {
            basis,
            segments,
            evidence: evidence.into_iter().collect(),
        },
        FlowValue::Known(KnownValue {
            kind: ValueKind::Closure(prototype),
            evidence,
        }) => CalleeResolution::ResolvedPrototype {
            prototype,
            evidence: evidence.into_iter().collect(),
        },
        FlowValue::Known(KnownValue {
            kind: ValueKind::NonClosure | ValueKind::LiteralString(_),
            ..
        }) => CalleeResolution::Unresolved {
            reason: CalleeUnresolvedReason::UnsupportedValue,
        },
        FlowValue::Unknown(reason) => CalleeResolution::Unresolved { reason },
        _ => CalleeResolution::Unresolved {
            reason: CalleeUnresolvedReason::MissingDefinition,
        },
    };
    CalleeFact {
        call_id: inst.id.clone(),
        proto_path: proto_path.clone(),
        pc: inst.pc,
        call_kind: inst.mnemonic.clone(),
        callee_register: register,
        resolution,
    }
}

fn fact_with_reason(
    proto_path: &ProtoPath,
    inst: &SemanticInstruction,
    reason: CalleeUnresolvedReason,
) -> CalleeFact {
    let mut fact = fact_from_state(proto_path, inst, &[]);
    fact.resolution = CalleeResolution::Unresolved { reason };
    fact
}

fn is_call(inst: &SemanticInstruction) -> bool {
    matches!(inst.mnemonic.as_str(), "CALL" | "TAILCALL")
}

fn register_operand(inst: &SemanticInstruction, ordinal: usize) -> Option<u8> {
    inst.operands
        .iter()
        .filter_map(|operand| match operand {
            TypedOperand::Register { index } => Some(*index),
            _ => None,
        })
        .nth(ordinal)
}

fn upvalue_operand(inst: &SemanticInstruction) -> Option<u8> {
    inst.operands.iter().find_map(|operand| match operand {
        TypedOperand::Upvalue { index, .. } => Some(*index),
        _ => None,
    })
}

fn prototype_operand(inst: &SemanticInstruction) -> Option<ProtoPath> {
    inst.operands.iter().find_map(|operand| match operand {
        TypedOperand::Prototype { path, .. } => Some(path.clone()),
        _ => None,
    })
}

fn constant_operand(inst: &SemanticInstruction) -> Option<luad_core::model::ConstantValue> {
    inst.operands.iter().find_map(|operand| match operand {
        TypedOperand::Constant { value, .. } => Some(value.clone()),
        _ => None,
    })
}

fn string_operand(inst: &SemanticInstruction) -> Option<String> {
    lua_string_operand(inst).map(|value| value.display.clone())
}

fn lua_string_operand(inst: &SemanticInstruction) -> Option<&luad_core::model::LuaString> {
    inst.operands.iter().find_map(|operand| match operand {
        TypedOperand::Constant {
            value:
                luad_core::model::ConstantValue::ShortString(value)
                | luad_core::model::ConstantValue::LongString(value),
            ..
        } => Some(value),
        _ => None,
    })
}

fn has_constant_operand(inst: &SemanticInstruction) -> bool {
    inst.operands
        .iter()
        .any(|operand| matches!(operand, TypedOperand::Constant { .. }))
}

fn flow_from_capture(value: &CaptureValue) -> FlowValue {
    match value {
        CaptureValue::LookupLabel {
            lookup_kind,
            key,
            evidence,
        } => FlowValue::Known(KnownValue {
            kind: ValueKind::LookupLabel {
                lookup_kind: *lookup_kind,
                key: key.clone(),
            },
            evidence: evidence.iter().cloned().collect(),
        }),
        CaptureValue::SymbolicPath {
            basis,
            segments,
            evidence,
        } => FlowValue::Known(KnownValue {
            kind: ValueKind::SymbolicPath {
                basis: *basis,
                segments: segments.clone(),
            },
            evidence: evidence.iter().cloned().collect(),
        }),
        CaptureValue::LiteralString { value, evidence } => FlowValue::Known(KnownValue {
            kind: ValueKind::LiteralString(value.clone()),
            evidence: evidence.iter().cloned().collect(),
        }),
        CaptureValue::Closure {
            prototype,
            evidence,
        } => FlowValue::Known(KnownValue {
            kind: ValueKind::Closure(prototype.clone()),
            evidence: evidence.iter().cloned().collect(),
        }),
        CaptureValue::Unknown { reason } => FlowValue::Unknown(*reason),
    }
}

fn add_evidence(value: FlowValue, evidence: &StableId) -> FlowValue {
    match value {
        FlowValue::Known(mut known) => {
            known.evidence.insert(evidence.clone());
            FlowValue::Known(known)
        }
        other => other,
    }
}

fn get_register(state: &[FlowValue], index: u8) -> FlowValue {
    state
        .get(index as usize)
        .cloned()
        .unwrap_or(FlowValue::Unknown(
            CalleeUnresolvedReason::OpenRegisterWindow,
        ))
}

fn set_register(state: &mut RegisterState, index: u8, value: FlowValue) {
    if let Some(slot) = state.get_mut(index as usize) {
        *slot = value;
    }
}

fn set_known(
    state: &mut RegisterState,
    index: u8,
    kind: ValueKind,
    evidence: impl IntoIterator<Item = StableId>,
) {
    set_register(
        state,
        index,
        FlowValue::Known(KnownValue {
            kind,
            evidence: evidence.into_iter().collect(),
        }),
    );
}

fn set_path(
    state: &mut RegisterState,
    index: u8,
    basis: SymbolicPathBasis,
    segments: Vec<String>,
    evidence: impl IntoIterator<Item = StableId>,
) {
    if segments.len() > MAX_PATH_SEGMENTS {
        set_register(
            state,
            index,
            FlowValue::Unknown(CalleeUnresolvedReason::PathLimit),
        );
    } else {
        set_known(
            state,
            index,
            ValueKind::SymbolicPath { basis, segments },
            evidence,
        );
    }
}

fn invalidate_all(state: &mut RegisterState, frame_size: usize, reason: CalleeUnresolvedReason) {
    for slot in state.iter_mut().take(frame_size) {
        *slot = FlowValue::Unknown(reason);
    }
}

fn invalidate_from(
    state: &mut RegisterState,
    start: u8,
    frame_size: usize,
    reason: CalleeUnresolvedReason,
) {
    for slot in state.iter_mut().take(frame_size).skip(usize::from(start)) {
        *slot = FlowValue::Unknown(reason);
    }
}

pub const DEFAULT_CAPTURE_MUTATION_BUDGET: usize = 100_000;

/// Analyze every prototype in structural order with conservative closure captures under a finite mutation budget.
#[must_use]
pub fn analyze_chunk_callees_with_mutation_budget(
    chunk: &luad_core::model::Chunk,
    budget: usize,
) -> ChunkCalleeAnalysis {
    let summary = crate::capture_mutation::CaptureMutationSummary::build(chunk, budget);
    if summary.exhausted {
        let mut prototypes = Vec::new();
        fail_closed_callees(&chunk.dialect, &chunk.main_proto, &mut prototypes);
        return ChunkCalleeAnalysis { prototypes };
    }

    let mut prototypes = Vec::new();
    analyze_proto_tree(
        &chunk.dialect,
        &chunk.main_proto,
        &CaptureEnvironment::new(),
        &summary,
        &mut prototypes,
    );
    ChunkCalleeAnalysis { prototypes }
}

/// Analyze every prototype in structural order with conservative closure captures.
#[must_use]
pub fn analyze_chunk_callees(chunk: &luad_core::model::Chunk) -> ChunkCalleeAnalysis {
    analyze_chunk_callees_with_mutation_budget(chunk, DEFAULT_CAPTURE_MUTATION_BUDGET)
}

fn fail_closed_callees(
    dialect: &str,
    proto: &luad_core::model::Prototype,
    results: &mut Vec<CalleeAnalysis>,
) {
    let instructions = crate::lift_proto_for_dialect(dialect, proto);
    results.push(CalleeAnalysis {
        proto_id: proto.id.clone(),
        calls: enumerate_with_reason(
            &proto.path,
            &instructions,
            CalleeUnresolvedReason::AnalysisLimit,
        ),
    });
    for child in &proto.protos {
        fail_closed_callees(dialect, child, results);
    }
}

pub(crate) fn analyze_chunk_global_stores(chunk: &luad_core::model::Chunk) -> Vec<GlobalStoreFact> {
    let summary = crate::capture_mutation::CaptureMutationSummary::build(
        chunk,
        DEFAULT_CAPTURE_MUTATION_BUDGET,
    );
    let mut stores = Vec::new();
    collect_global_stores_tree(
        &chunk.dialect,
        &chunk.main_proto,
        &CaptureEnvironment::new(),
        &summary,
        &mut stores,
    );
    stores.sort_by(|left, right| left.store_id.cmp(&right.store_id));
    stores
}

pub(crate) fn analyze_chunk_global_lookups(
    chunk: &luad_core::model::Chunk,
) -> BTreeMap<StableId, Vec<u8>> {
    fn collect(
        dialect: &str,
        proto: &luad_core::model::Prototype,
        lookups: &mut BTreeMap<StableId, Vec<u8>>,
    ) {
        for instruction in crate::lift_proto_for_dialect(dialect, proto) {
            if instruction.mnemonic == "GETGLOBAL" {
                if let Some(name) = lua_string_operand(&instruction) {
                    lookups.insert(instruction.id.clone(), name.raw_bytes.clone());
                }
            }
        }
        for child in &proto.protos {
            collect(dialect, child, lookups);
        }
    }

    let mut lookups = BTreeMap::new();
    collect(&chunk.dialect, &chunk.main_proto, &mut lookups);
    lookups
}

fn collect_global_stores_tree(
    dialect: &str,
    proto: &luad_core::model::Prototype,
    captures: &CaptureEnvironment,
    summary: &crate::capture_mutation::CaptureMutationSummary,
    stores: &mut Vec<GlobalStoreFact>,
) {
    let instructions = crate::lift_proto_for_dialect(dialect, proto);
    let cfg = ControlFlowGraph::build(proto, &instructions);
    let dataflow = run_dataflow(proto.maxstacksize, &instructions, &cfg, captures);

    if dataflow.exhausted {
        stores.extend(
            instructions
                .iter()
                .filter(|instruction| instruction.mnemonic == "SETGLOBAL")
                .filter_map(|instruction| {
                    lua_string_operand(instruction).map(|name| GlobalStoreFact {
                        name_raw: name.raw_bytes.clone(),
                        store_id: instruction.id.clone(),
                        value: GlobalStoreValue::Unknown {
                            reason: CalleeUnresolvedReason::AnalysisLimit,
                        },
                    })
                }),
        );
    } else {
        collect_reachable_global_stores(
            proto,
            &instructions,
            &cfg,
            &dataflow.in_states,
            captures,
            stores,
        );
    }

    let child_captures =
        derive_child_captures(proto, &instructions, &cfg, &dataflow, captures, summary);
    for (index, child) in proto.protos.iter().enumerate() {
        let environment = child_captures
            .get(&index)
            .cloned()
            .unwrap_or_else(|| unknown_capture_environment(child));
        collect_global_stores_tree(dialect, child, &environment, summary, stores);
    }
}

fn collect_reachable_global_stores(
    proto: &luad_core::model::Prototype,
    instructions: &[SemanticInstruction],
    cfg: &ControlFlowGraph,
    in_states: &[RegisterState],
    captures: &CaptureEnvironment,
    stores: &mut Vec<GlobalStoreFact>,
) {
    for block in cfg.blocks.iter().filter(|block| block.is_reachable) {
        let mut state = in_states[block.index].clone();
        for &pc in &block.instruction_pcs {
            let Some(instruction) = instructions.get(pc) else {
                continue;
            };
            if instruction.mnemonic == "SETGLOBAL" {
                if let (Some(name), Some(source)) = (
                    lua_string_operand(instruction),
                    register_operand(instruction, 0),
                ) {
                    stores.push(GlobalStoreFact {
                        name_raw: name.raw_bytes.clone(),
                        store_id: instruction.id.clone(),
                        value: global_store_value(get_register(&state, source), instruction),
                    });
                }
            }
            transfer(
                instruction,
                &mut state,
                captures,
                proto.maxstacksize as usize,
            );
        }
    }
}

fn global_store_value(value: FlowValue, store: &SemanticInstruction) -> GlobalStoreValue {
    match value {
        FlowValue::Known(KnownValue {
            kind: ValueKind::Closure(prototype),
            mut evidence,
        }) => {
            evidence.insert(store.id.clone());
            GlobalStoreValue::Closure {
                prototype,
                evidence: evidence.into_iter().collect(),
            }
        }
        FlowValue::Known(KnownValue { mut evidence, .. }) => {
            evidence.insert(store.id.clone());
            GlobalStoreValue::NonClosure {
                evidence: evidence.into_iter().collect(),
            }
        }
        FlowValue::Unknown(reason) => GlobalStoreValue::Unknown { reason },
        FlowValue::Bottom => GlobalStoreValue::Unknown {
            reason: CalleeUnresolvedReason::MissingDefinition,
        },
    }
}

fn analyze_proto_tree(
    dialect: &str,
    proto: &luad_core::model::Prototype,
    captures: &CaptureEnvironment,
    summary: &crate::capture_mutation::CaptureMutationSummary,
    results: &mut Vec<CalleeAnalysis>,
) {
    let instructions = crate::lift_proto_for_dialect(dialect, proto);
    let cfg = ControlFlowGraph::build(proto, &instructions);
    let dataflow = run_dataflow(proto.maxstacksize, &instructions, &cfg, captures);
    let analysis = if dataflow.exhausted {
        CalleeAnalysis {
            proto_id: proto.id.clone(),
            calls: enumerate_with_reason(
                &proto.path,
                &instructions,
                CalleeUnresolvedReason::AnalysisLimit,
            ),
        }
    } else {
        CalleeAnalysis {
            proto_id: proto.id.clone(),
            calls: collect_final_calls(
                &proto.path,
                &instructions,
                &cfg,
                &dataflow.in_states,
                captures,
                proto.maxstacksize as usize,
            ),
        }
    };
    results.push(analysis);

    let child_captures =
        derive_child_captures(proto, &instructions, &cfg, &dataflow, captures, summary);
    for (index, child) in proto.protos.iter().enumerate() {
        let environment = child_captures
            .get(&index)
            .cloned()
            .unwrap_or_else(|| unknown_capture_environment(child));
        analyze_proto_tree(dialect, child, &environment, summary, results);
    }
}

fn derive_child_captures(
    proto: &luad_core::model::Prototype,
    instructions: &[SemanticInstruction],
    cfg: &ControlFlowGraph,
    dataflow: &DataflowResult,
    parent_captures: &CaptureEnvironment,
    summary: &crate::capture_mutation::CaptureMutationSummary,
) -> BTreeMap<usize, CaptureEnvironment> {
    if dataflow.exhausted {
        return BTreeMap::new();
    }
    let mut environments: BTreeMap<usize, CaptureEnvironment> = BTreeMap::new();
    for closure in instructions
        .iter()
        .filter(|inst| inst.mnemonic == "CLOSURE")
    {
        let Some(block) = cfg
            .blocks
            .iter()
            .find(|block| block.is_reachable && block.instruction_pcs.contains(&closure.pc))
        else {
            continue;
        };
        let Some(child_index) = closure.operands.iter().find_map(|operand| match operand {
            TypedOperand::Prototype { index, .. } => Some(*index),
            _ => None,
        }) else {
            continue;
        };
        let Some(child) = proto.protos.get(child_index) else {
            continue;
        };
        let state = state_before_pc(
            closure.pc,
            block,
            &dataflow.in_states[block.index],
            instructions,
            parent_captures,
            proto.maxstacksize as usize,
        );
        let closure_dest = register_operand(closure, 0);
        let derivation = CaptureDerivation {
            closure,
            closure_dest,
            state: &state,
            parent_instructions: instructions,
            parent_cfg: cfg,
            parent_captures,
        };
        let candidate = environments.entry(child_index).or_default();
        let child_path = proto.path.child(child_index);

        for slot in 0..child.upvalues.len() {
            let descriptor_pc = closure.pc + 1 + slot;
            let value = instructions
                .get(descriptor_pc)
                .map(|descriptor| {
                    capture_from_descriptor(
                        descriptor,
                        &derivation,
                        summary.is_child_slot_mutated(&child_path, slot as u8),
                        summary,
                        &proto.path,
                    )
                })
                .unwrap_or(CaptureValue::Unknown {
                    reason: CalleeUnresolvedReason::AmbiguousCapture,
                });
            candidate
                .entry(slot as u8)
                .and_modify(|existing| *existing = join_capture(existing, &value))
                .or_insert(value);
        }
    }
    environments
}

fn state_before_pc(
    target_pc: usize,
    block: &crate::BasicBlock,
    incoming: &RegisterState,
    instructions: &[SemanticInstruction],
    captures: &CaptureEnvironment,
    frame_size: usize,
) -> RegisterState {
    let mut state = incoming.clone();
    for &pc in &block.instruction_pcs {
        if pc >= target_pc {
            break;
        }
        if let Some(inst) = instructions.get(pc) {
            transfer(inst, &mut state, captures, frame_size);
        }
    }
    state
}

struct CaptureDerivation<'a> {
    closure: &'a SemanticInstruction,
    closure_dest: Option<u8>,
    state: &'a RegisterState,
    parent_instructions: &'a [SemanticInstruction],
    parent_cfg: &'a ControlFlowGraph,
    parent_captures: &'a CaptureEnvironment,
}

fn capture_from_descriptor(
    descriptor: &SemanticInstruction,
    context: &CaptureDerivation<'_>,
    child_mutates_capture: bool,
    summary: &crate::capture_mutation::CaptureMutationSummary,
    parent_path: &luad_core::ProtoPath,
) -> CaptureValue {
    if child_mutates_capture || !is_closure_binding(descriptor) {
        return CaptureValue::Unknown {
            reason: CalleeUnresolvedReason::MutableCapture,
        };
    }
    let mut value = match descriptor.reads.first() {
        Some(EffectTarget::Register { index }) => {
            if Some(*index) == context.closure_dest
                || summary.is_local_register_mutated(parent_path, *index)
                || effect_may_be_written_after(
                    context.parent_instructions,
                    context.parent_cfg,
                    context.closure.pc,
                    &EffectTarget::Register { index: *index },
                )
            {
                CaptureValue::Unknown {
                    reason: CalleeUnresolvedReason::MutableCapture,
                }
            } else {
                capture_from_flow(get_register(context.state, *index))
            }
        }
        Some(EffectTarget::Upvalue { index, .. }) => {
            if summary.is_upvalue_slot_mutated(parent_path, *index)
                || effect_may_be_written_after(
                    context.parent_instructions,
                    context.parent_cfg,
                    context.closure.pc,
                    &EffectTarget::Upvalue {
                        index: *index,
                        name: None,
                    },
                )
            {
                CaptureValue::Unknown {
                    reason: CalleeUnresolvedReason::MutableCapture,
                }
            } else {
                context
                    .parent_captures
                    .get(index)
                    .cloned()
                    .unwrap_or(CaptureValue::Unknown {
                        reason: CalleeUnresolvedReason::AmbiguousCapture,
                    })
            }
        }
        _ => CaptureValue::Unknown {
            reason: CalleeUnresolvedReason::AmbiguousCapture,
        },
    };
    add_capture_evidence(&mut value, &context.closure.id);
    add_capture_evidence(&mut value, &descriptor.id);
    value
}

fn capture_from_flow(value: FlowValue) -> CaptureValue {
    match value {
        FlowValue::Known(KnownValue {
            kind: ValueKind::LookupLabel { lookup_kind, key },
            evidence,
        }) => CaptureValue::LookupLabel {
            lookup_kind,
            key,
            evidence: evidence.into_iter().collect(),
        },
        FlowValue::Known(KnownValue {
            kind: ValueKind::SymbolicPath { basis, segments },
            evidence,
        }) => CaptureValue::SymbolicPath {
            basis,
            segments,
            evidence: evidence.into_iter().collect(),
        },
        FlowValue::Known(KnownValue {
            kind: ValueKind::LiteralString(value),
            evidence,
        }) => CaptureValue::LiteralString {
            value,
            evidence: evidence.into_iter().collect(),
        },
        FlowValue::Known(KnownValue {
            kind: ValueKind::Closure(prototype),
            evidence,
        }) => CaptureValue::Closure {
            prototype,
            evidence: evidence.into_iter().collect(),
        },
        FlowValue::Known(KnownValue {
            kind: ValueKind::NonClosure,
            ..
        }) => CaptureValue::Unknown {
            reason: CalleeUnresolvedReason::UnsupportedValue,
        },
        FlowValue::Unknown(reason) => CaptureValue::Unknown { reason },
        FlowValue::Bottom => CaptureValue::Unknown {
            reason: CalleeUnresolvedReason::MissingDefinition,
        },
    }
}

fn join_capture(left: &CaptureValue, right: &CaptureValue) -> CaptureValue {
    match (left, right) {
        (
            CaptureValue::LookupLabel {
                lookup_kind: left_kind,
                key: left_key,
                evidence: left_evidence,
            },
            CaptureValue::LookupLabel {
                lookup_kind: right_kind,
                key: right_key,
                evidence: right_evidence,
            },
        ) if left_kind == right_kind && keys_join(left_key, right_key) => {
            CaptureValue::LookupLabel {
                lookup_kind: *left_kind,
                key: left_key.clone(),
                evidence: union_evidence(left_evidence, right_evidence),
            }
        }
        (
            CaptureValue::SymbolicPath {
                basis: left_basis,
                segments: left_segments,
                evidence: left_evidence,
            },
            CaptureValue::SymbolicPath {
                basis: right_basis,
                segments: right_segments,
                evidence: right_evidence,
            },
        ) if left_basis == right_basis && left_segments == right_segments => {
            CaptureValue::SymbolicPath {
                basis: *left_basis,
                segments: left_segments.clone(),
                evidence: union_evidence(left_evidence, right_evidence),
            }
        }
        (
            CaptureValue::LiteralString {
                value: left_value,
                evidence: left_evidence,
            },
            CaptureValue::LiteralString {
                value: right_value,
                evidence: right_evidence,
            },
        ) if left_value == right_value => CaptureValue::LiteralString {
            value: left_value.clone(),
            evidence: union_evidence(left_evidence, right_evidence),
        },
        (
            CaptureValue::Closure {
                prototype: left_proto,
                evidence: left_evidence,
            },
            CaptureValue::Closure {
                prototype: right_proto,
                evidence: right_evidence,
            },
        ) if left_proto == right_proto => CaptureValue::Closure {
            prototype: left_proto.clone(),
            evidence: union_evidence(left_evidence, right_evidence),
        },
        (CaptureValue::Unknown { reason: left }, CaptureValue::Unknown { reason: right })
            if left == right =>
        {
            CaptureValue::Unknown { reason: *left }
        }
        _ => CaptureValue::Unknown {
            reason: CalleeUnresolvedReason::AmbiguousCapture,
        },
    }
}

fn union_evidence(left: &[StableId], right: &[StableId]) -> Vec<StableId> {
    left.iter()
        .chain(right)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn add_capture_evidence(value: &mut CaptureValue, id: &StableId) {
    let evidence = match value {
        CaptureValue::LookupLabel { evidence, .. }
        | CaptureValue::SymbolicPath { evidence, .. }
        | CaptureValue::LiteralString { evidence, .. }
        | CaptureValue::Closure { evidence, .. } => Some(evidence),
        CaptureValue::Unknown { .. } => None,
    };
    if let Some(evidence) = evidence {
        evidence.push(id.clone());
        evidence.sort();
        evidence.dedup();
    }
}

fn effect_may_be_written_after(
    instructions: &[SemanticInstruction],
    cfg: &ControlFlowGraph,
    origin_pc: usize,
    target: &EffectTarget,
) -> bool {
    let Some(origin_block) = cfg
        .blocks
        .iter()
        .find(|block| block.instruction_pcs.contains(&origin_pc))
    else {
        return true;
    };
    let reachable_blocks = reachable_blocks_after(cfg, origin_block.index);
    instructions.iter().any(|inst| {
        if is_closure_binding(inst) || !write_overlaps(&inst.writes, target) {
            return false;
        }
        let Some(writer_block) = cfg
            .blocks
            .iter()
            .find(|block| block.instruction_pcs.contains(&inst.pc))
        else {
            return true;
        };
        if writer_block.index == origin_block.index {
            inst.pc > origin_pc || reachable_blocks.contains(&origin_block.index)
        } else {
            reachable_blocks.contains(&writer_block.index)
        }
    })
}

fn reachable_blocks_after(cfg: &ControlFlowGraph, origin: usize) -> BTreeSet<usize> {
    let mut reached = BTreeSet::new();
    let mut queue: VecDeque<_> = cfg.blocks[origin]
        .successors
        .iter()
        .map(|edge| edge.to_block)
        .collect();
    while let Some(block) = queue.pop_front() {
        if reached.insert(block) {
            queue.extend(
                cfg.blocks[block]
                    .successors
                    .iter()
                    .map(|edge| edge.to_block),
            );
        }
    }
    reached
}

fn write_overlaps(writes: &[EffectTarget], target: &EffectTarget) -> bool {
    writes.iter().any(|write| match (write, target) {
        (EffectTarget::Register { index: written }, EffectTarget::Register { index }) => {
            written == index
        }
        (EffectTarget::RegisterRange { start, end }, EffectTarget::Register { index }) => {
            start <= index && index <= end
        }
        (EffectTarget::RegisterRangeToTop { start }, EffectTarget::Register { index }) => {
            start <= index
        }
        (EffectTarget::Upvalue { index: written, .. }, EffectTarget::Upvalue { index, .. }) => {
            written == index
        }
        _ => false,
    })
}

fn unknown_capture_environment(proto: &luad_core::model::Prototype) -> CaptureEnvironment {
    (0..proto.upvalues.len())
        .map(|index| {
            (
                index as u8,
                CaptureValue::Unknown {
                    reason: CalleeUnresolvedReason::AmbiguousCapture,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_basis_participates_in_equality() {
        let evidence = BTreeSet::new();
        let global = FlowValue::Known(KnownValue {
            kind: ValueKind::SymbolicPath {
                basis: SymbolicPathBasis::GlobalLabel,
                segments: vec!["luci".into()],
            },
            evidence: evidence.clone(),
        });
        let module = FlowValue::Known(KnownValue {
            kind: ValueKind::SymbolicPath {
                basis: SymbolicPathBasis::ModuleLabel,
                segments: vec!["luci".into()],
            },
            evidence,
        });
        assert_eq!(
            meet_value(&global, &module),
            FlowValue::Unknown(CalleeUnresolvedReason::ControlFlowConflict)
        );
    }

    #[test]
    fn equal_join_unions_evidence_deterministically() {
        let kind = ValueKind::LiteralString("x".into());
        let left = FlowValue::Known(KnownValue {
            kind: kind.clone(),
            evidence: [StableId::instruction(ProtoPath::root(), 9)]
                .into_iter()
                .collect(),
        });
        let right = FlowValue::Known(KnownValue {
            kind,
            evidence: [StableId::instruction(ProtoPath::root(), 2)]
                .into_iter()
                .collect(),
        });
        let FlowValue::Known(joined) = meet_value(&left, &right) else {
            panic!("equal values must survive the join")
        };
        assert_eq!(
            joined.evidence.into_iter().collect::<Vec<_>>(),
            vec![
                StableId::instruction(ProtoPath::root(), 2),
                StableId::instruction(ProtoPath::root(), 9)
            ]
        );
    }

    #[test]
    fn resolution_is_a_tagged_union() {
        let unresolved = CalleeResolution::Unresolved {
            reason: CalleeUnresolvedReason::DynamicKey,
        };
        assert!(matches!(
            unresolved,
            CalleeResolution::Unresolved {
                reason: CalleeUnresolvedReason::DynamicKey
            }
        ));
    }

    #[test]
    fn lookup_label_joins_equal_keys_and_rejects_conflicts() {
        let key = luad_core::model::ConstantValue::ShortString(
            luad_core::model::LuaString::from_bytes(b"execute"),
        );
        let left = FlowValue::Known(KnownValue {
            kind: ValueKind::LookupLabel {
                lookup_kind: CalleeLookupKind::Gettable,
                key: key.clone(),
            },
            evidence: [StableId::instruction(ProtoPath::root(), 2)]
                .into_iter()
                .collect(),
        });
        let right = FlowValue::Known(KnownValue {
            kind: ValueKind::LookupLabel {
                lookup_kind: CalleeLookupKind::Gettable,
                key,
            },
            evidence: [StableId::instruction(ProtoPath::root(), 4)]
                .into_iter()
                .collect(),
        });
        let FlowValue::Known(joined) = meet_value(&left, &right) else {
            panic!("equal lookup labels must survive join");
        };
        assert_eq!(
            joined.evidence.into_iter().collect::<Vec<_>>(),
            vec![
                StableId::instruction(ProtoPath::root(), 2),
                StableId::instruction(ProtoPath::root(), 4)
            ]
        );
    }
}
