//! Bounded, evidence-linked Lua 5.1 call-argument origin analysis.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use luad_core::{
    model::{ConstantValue, LuaString, Prototype},
    EffectTarget, ImplicitEffect, ProtoPath, SemanticInstruction, StableId, TypedOperand,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ControlFlowGraph;

const MAX_EXPRESSION_DEPTH: usize = 24;
const MAX_EXPRESSION_NODES: usize = 512;
const MAX_REGISTER_WINDOW: usize = 256;
const MAX_TRANSFER_STEPS: usize = 1_000_000;

/// A lossless literal suitable for structural equality in an origin graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OriginLiteral {
    Nil,
    Boolean {
        value: bool,
    },
    Integer {
        value: i64,
        raw_hex: String,
    },
    Float {
        raw_hex: String,
        is_nan: bool,
        is_inf: bool,
    },
    String {
        value: LuaString,
    },
}

/// Closed reasons why the analysis cannot describe a value expression.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum OriginUnknownReason {
    MissingDefinition,
    ControlFlowConflict,
    DynamicKey,
    Overwritten,
    OpenArgumentWindow,
    OpenResultWindow,
    VarargValue,
    UnsupportedValue,
    UnsupportedInstruction,
    MutableCapture,
    AmbiguousCapture,
    ExpressionDepthLimit,
    ExpressionNodeLimit,
    RegisterWindowLimit,
    AnalysisLimit,
    Unreachable,
}

/// One eager, cycle-free value-expression node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OriginExpression {
    #[serde(flatten)]
    pub kind: OriginExpressionKind,
    /// Stable bytecode facts that establish this node.
    pub evidence: Vec<StableId>,
}

/// Factual expression kinds. Operation nodes do not imply security policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OriginExpressionKind {
    Literal {
        #[serde(skip_serializing_if = "Option::is_none")]
        constant_id: Option<StableId>,
        value: OriginLiteral,
    },
    Parameter {
        owner: ProtoPath,
        index: u8,
    },
    Upvalue {
        owner: ProtoPath,
        index: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Global {
        name: LuaString,
    },
    Field {
        base: Box<OriginExpression>,
        key: OriginLiteral,
        #[serde(skip_serializing_if = "Option::is_none")]
        key_id: Option<StableId>,
    },
    CallResult {
        call_id: StableId,
        result_index: usize,
    },
    Concat {
        parts: Vec<OriginExpression>,
    },
    Table {
        entries: Vec<OriginExpression>,
    },
    Unary {
        operator: String,
        operand: Box<OriginExpression>,
    },
    Binary {
        operator: String,
        left: Box<OriginExpression>,
        right: Box<OriginExpression>,
    },
    Unknown {
        reason: OriginUnknownReason,
    },
}

/// One fixed argument position and its pre-call origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FixedArgumentOrigin {
    pub argument_index: usize,
    pub register: u8,
    pub origin: OriginExpression,
}

/// The argument window represented by a call fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CallArgumentWindow {
    Fixed { arguments: Vec<FixedArgumentOrigin> },
    Open { reason: OriginUnknownReason },
}

/// Auditable origins for one physical `CALL` or `TAILCALL` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallOriginFact {
    pub call_id: StableId,
    pub proto_path: ProtoPath,
    pub pc: usize,
    pub call_kind: String,
    pub callee_register: u8,
    pub argument_window: CallArgumentWindow,
}

/// Call-argument origins for one prototype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OriginAnalysis {
    pub proto_id: StableId,
    pub calls: Vec<CallOriginFact>,
}

/// Call-argument origins for every prototype in one chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChunkOriginAnalysis {
    pub prototypes: Vec<OriginAnalysis>,
}

type CaptureEnvironment = BTreeMap<u8, OriginExpression>;
type RegisterState = Vec<FlowValue>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum FlowValue {
    Bottom,
    Origin(OriginExpression),
}

struct DataflowResult {
    in_states: Vec<RegisterState>,
    exhausted: bool,
}

/// Analyze every prototype in structural order with conservative closure captures.
#[must_use]
pub fn analyze_chunk_origins(chunk: &luad_core::model::Chunk) -> ChunkOriginAnalysis {
    let mut prototypes = Vec::new();
    let root_captures = root_capture_environment(&chunk.main_proto);
    analyze_proto_tree(
        &chunk.dialect,
        &chunk.main_proto,
        &root_captures,
        &mut prototypes,
    );
    ChunkOriginAnalysis { prototypes }
}

fn analyze_proto_tree(
    dialect: &str,
    proto: &Prototype,
    captures: &CaptureEnvironment,
    results: &mut Vec<OriginAnalysis>,
) {
    let instructions = crate::lift_proto_for_dialect(dialect, proto);
    let cfg = ControlFlowGraph::build(proto, &instructions);
    let dataflow = run_dataflow(proto, &instructions, &cfg, captures);
    let calls = if dataflow.exhausted {
        enumerate_calls_with_reason(proto, &instructions, OriginUnknownReason::AnalysisLimit)
    } else {
        collect_calls(proto, &instructions, &cfg, &dataflow.in_states, captures)
    };
    results.push(OriginAnalysis {
        proto_id: proto.id.clone(),
        calls,
    });

    let children = derive_child_captures(proto, &instructions, &cfg, &dataflow, captures);
    for (index, child) in proto.protos.iter().enumerate() {
        let environment = children
            .get(&index)
            .cloned()
            .unwrap_or_else(|| unknown_capture_environment(child));
        analyze_proto_tree(dialect, child, &environment, results);
    }
}

fn run_dataflow(
    proto: &Prototype,
    instructions: &[SemanticInstruction],
    cfg: &ControlFlowGraph,
    captures: &CaptureEnvironment,
) -> DataflowResult {
    let frame_size = usize::from(proto.maxstacksize);
    if frame_size > MAX_REGISTER_WINDOW {
        return DataflowResult {
            in_states: vec![vec![]; cfg.blocks.len()],
            exhausted: true,
        };
    }

    let mut entry =
        vec![FlowValue::Origin(unknown(OriginUnknownReason::MissingDefinition, [])); frame_size];
    for (index, slot) in entry
        .iter_mut()
        .enumerate()
        .take(usize::from(proto.numparams).min(frame_size))
    {
        *slot = FlowValue::Origin(expression(
            OriginExpressionKind::Parameter {
                owner: proto.path.clone(),
                index: index as u8,
            },
            [proto.id.clone()],
        ));
    }
    let bottom = vec![FlowValue::Bottom; frame_size];
    let mut in_states = vec![bottom.clone(); cfg.blocks.len()];
    let mut out_states = vec![bottom; cfg.blocks.len()];
    if let Some(entry_index) = cfg.blocks.iter().position(|block| block.is_entry) {
        in_states[entry_index] = entry;
    }

    let mut worklist: VecDeque<usize> = reverse_postorder(cfg).into();
    let mut queued: BTreeSet<usize> = worklist.iter().copied().collect();
    let mut steps = 0usize;
    let mut exhausted = false;
    while let Some(block_index) = worklist.pop_front() {
        queued.remove(&block_index);
        let block = &cfg.blocks[block_index];
        if !block.is_reachable {
            continue;
        }
        let incoming = if block.is_entry {
            in_states[block_index].clone()
        } else {
            meet_predecessors(block, &out_states, frame_size)
        };
        in_states[block_index] = incoming.clone();
        let mut state = incoming;
        for &pc in &block.instruction_pcs {
            steps = steps.saturating_add(1);
            if steps > MAX_TRANSFER_STEPS {
                exhausted = true;
                break;
            }
            if let Some(instruction) = instructions.get(pc) {
                transfer(instruction, &mut state, captures, frame_size);
            }
        }
        if exhausted {
            break;
        }
        if state != out_states[block_index] {
            out_states[block_index] = state;
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
        postorder: &mut Vec<usize>,
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
            visit(successor, cfg, seen, postorder);
        }
        postorder.push(index);
    }

    let mut seen = BTreeSet::new();
    let mut postorder = Vec::new();
    if let Some(entry) = cfg.blocks.iter().position(|block| block.is_entry) {
        visit(entry, cfg, &mut seen, &mut postorder);
    }
    postorder.reverse();
    postorder
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

fn meet_value(left: &FlowValue, right: &FlowValue) -> FlowValue {
    match (left, right) {
        (FlowValue::Bottom, value) | (value, FlowValue::Bottom) => value.clone(),
        (FlowValue::Origin(left), FlowValue::Origin(right)) => merge_equal(left, right)
            .map(FlowValue::Origin)
            .unwrap_or_else(|| {
                FlowValue::Origin(unknown(
                    OriginUnknownReason::ControlFlowConflict,
                    left.evidence.iter().chain(&right.evidence).cloned(),
                ))
            }),
    }
}

fn transfer(
    instruction: &SemanticInstruction,
    state: &mut RegisterState,
    captures: &CaptureEnvironment,
    frame_size: usize,
) {
    if is_closure_binding(instruction) {
        return;
    }
    if !is_known_lua51_mnemonic(&instruction.mnemonic) {
        invalidate_all(
            state,
            OriginUnknownReason::UnsupportedInstruction,
            [instruction.id.clone()],
        );
        return;
    }

    let before = state.clone();
    invalidate_writes(instruction, state, frame_size);
    match instruction.mnemonic.as_str() {
        "MOVE" => {
            if let (Some(destination), Some(source)) = (
                register_operand(instruction, 0),
                register_operand(instruction, 1),
            ) {
                set_register(
                    state,
                    destination,
                    add_evidence(get_register(&before, source), &instruction.id),
                );
            }
        }
        "LOADK" => {
            if let (Some(destination), Some((index, value))) = (
                register_operand(instruction, 0),
                constant_operand(instruction, 0),
            ) {
                let constant_id =
                    StableId::constant(proto_from_instruction(&instruction.id), index);
                set_register(
                    state,
                    destination,
                    FlowValue::Origin(literal(
                        Some(constant_id.clone()),
                        &value,
                        [constant_id, instruction.id.clone()],
                    )),
                );
            }
        }
        "LOADBOOL" => {
            if let (Some(destination), Some(value)) = (
                register_operand(instruction, 0),
                instruction
                    .operands
                    .iter()
                    .find_map(|operand| match operand {
                        TypedOperand::Flag { value } => Some(*value),
                        _ => None,
                    }),
            ) {
                set_register(
                    state,
                    destination,
                    FlowValue::Origin(expression(
                        OriginExpressionKind::Literal {
                            constant_id: None,
                            value: OriginLiteral::Boolean { value },
                        },
                        [instruction.id.clone()],
                    )),
                );
            }
        }
        "LOADNIL" => {
            for target in written_registers(instruction, frame_size) {
                set_register(
                    state,
                    target,
                    FlowValue::Origin(expression(
                        OriginExpressionKind::Literal {
                            constant_id: None,
                            value: OriginLiteral::Nil,
                        },
                        [instruction.id.clone()],
                    )),
                );
            }
        }
        "GETUPVAL" => {
            if let (Some(destination), Some((index, name))) = (
                register_operand(instruction, 0),
                upvalue_operand(instruction),
            ) {
                let value = captures.get(&index).cloned().unwrap_or_else(|| {
                    unknown(
                        OriginUnknownReason::AmbiguousCapture,
                        [instruction.id.clone()],
                    )
                });
                set_register(
                    state,
                    destination,
                    FlowValue::Origin(add_expression_evidence(
                        value,
                        [
                            StableId::upvalue(
                                proto_from_instruction(&instruction.id),
                                index as usize,
                            ),
                            instruction.id.clone(),
                        ],
                    )),
                );
                let _ = name;
            }
        }
        "GETGLOBAL" => {
            if let (Some(destination), Some((index, value))) = (
                register_operand(instruction, 0),
                constant_operand(instruction, 0),
            ) {
                if let Some(name) = string_literal(&value) {
                    let constant_id =
                        StableId::constant(proto_from_instruction(&instruction.id), index);
                    set_register(
                        state,
                        destination,
                        FlowValue::Origin(expression(
                            OriginExpressionKind::Global { name },
                            [constant_id, instruction.id.clone()],
                        )),
                    );
                }
            }
        }
        "GETTABLE" => transfer_gettable(instruction, &before, state, false),
        "SELF" => transfer_gettable(instruction, &before, state, true),
        "NEWTABLE" => {
            if let Some(destination) = register_operand(instruction, 0) {
                set_register(
                    state,
                    destination,
                    FlowValue::Origin(expression(
                        OriginExpressionKind::Table { entries: vec![] },
                        [instruction.id.clone()],
                    )),
                );
            }
        }
        "SETLIST" => transfer_setlist(instruction, &before, state),
        "SETTABLE" => invalidate_table_aliases(
            state,
            &before,
            register_operand(instruction, 0),
            instruction,
        ),
        "ADD" | "SUB" | "MUL" | "DIV" | "MOD" | "POW" => {
            transfer_binary(instruction, &before, state)
        }
        "UNM" | "NOT" | "LEN" => transfer_unary(instruction, &before, state),
        "CONCAT" => transfer_concat(instruction, &before, state),
        "CALL" => {
            invalidate_table_values(state, instruction);
            transfer_call_results(instruction, state, frame_size);
        }
        "VARARG" => transfer_vararg(instruction, state, frame_size),
        _ => {}
    }
}

fn transfer_gettable(
    instruction: &SemanticInstruction,
    before: &RegisterState,
    state: &mut RegisterState,
    is_self: bool,
) {
    let Some(destination) = register_operand(instruction, 0) else {
        return;
    };
    let Some(source) = register_operand(instruction, 1) else {
        return;
    };
    if is_self {
        set_register(
            state,
            destination.saturating_add(1),
            get_register(before, source),
        );
    }
    let Some((constant_index, constant)) = constant_operand(instruction, 0) else {
        set_register(
            state,
            destination,
            FlowValue::Origin(unknown(
                OriginUnknownReason::DynamicKey,
                [instruction.id.clone()],
            )),
        );
        return;
    };
    let Some(key) = origin_literal(&constant) else {
        set_register(
            state,
            destination,
            FlowValue::Origin(unknown(
                OriginUnknownReason::UnsupportedValue,
                [instruction.id.clone()],
            )),
        );
        return;
    };
    let base = origin_from_flow(get_register(before, source));
    let key_id = StableId::constant(proto_from_instruction(&instruction.id), constant_index);
    let result = bounded_expression(
        OriginExpressionKind::Field {
            base: Box::new(base),
            key,
            key_id: Some(key_id.clone()),
        },
        [key_id, instruction.id.clone()],
    );
    set_register(state, destination, FlowValue::Origin(result));
}

fn transfer_binary(
    instruction: &SemanticInstruction,
    before: &RegisterState,
    state: &mut RegisterState,
) {
    let Some(destination) = register_operand(instruction, 0) else {
        return;
    };
    let Some(left) = expression_operand(instruction, 1, before) else {
        return;
    };
    let Some(right) = expression_operand(instruction, 2, before) else {
        return;
    };
    let result = bounded_expression(
        OriginExpressionKind::Binary {
            operator: instruction.mnemonic.clone(),
            left: Box::new(left),
            right: Box::new(right),
        },
        [instruction.id.clone()],
    );
    set_register(state, destination, FlowValue::Origin(result));
}

fn transfer_unary(
    instruction: &SemanticInstruction,
    before: &RegisterState,
    state: &mut RegisterState,
) {
    let (Some(destination), Some(source)) = (
        register_operand(instruction, 0),
        register_operand(instruction, 1),
    ) else {
        return;
    };
    let result = bounded_expression(
        OriginExpressionKind::Unary {
            operator: instruction.mnemonic.clone(),
            operand: Box::new(origin_from_flow(get_register(before, source))),
        },
        [instruction.id.clone()],
    );
    set_register(state, destination, FlowValue::Origin(result));
}

fn transfer_concat(
    instruction: &SemanticInstruction,
    before: &RegisterState,
    state: &mut RegisterState,
) {
    let registers: Vec<_> = instruction
        .operands
        .iter()
        .filter_map(|operand| match operand {
            TypedOperand::Register { index } => Some(*index),
            _ => None,
        })
        .collect();
    let [destination, start, end] = registers.as_slice() else {
        return;
    };
    if start > end || usize::from(*end) >= before.len() {
        set_register(
            state,
            *destination,
            FlowValue::Origin(unknown(
                OriginUnknownReason::RegisterWindowLimit,
                [instruction.id.clone()],
            )),
        );
        return;
    }
    let parts = (*start..=*end)
        .map(|register| origin_from_flow(get_register(before, register)))
        .collect();
    let result = bounded_expression(
        OriginExpressionKind::Concat { parts },
        [instruction.id.clone()],
    );
    set_register(state, *destination, FlowValue::Origin(result));
}

fn transfer_setlist(
    instruction: &SemanticInstruction,
    before: &RegisterState,
    state: &mut RegisterState,
) {
    let Some(base) = register_operand(instruction, 0) else {
        return;
    };
    let counts = count_operands(instruction);
    let Some((count, variable)) = counts.first().copied() else {
        return;
    };
    if variable {
        set_register(
            state,
            base,
            FlowValue::Origin(unknown(
                OriginUnknownReason::OpenArgumentWindow,
                [instruction.id.clone()],
            )),
        );
        return;
    }
    let table = origin_from_flow(get_register(before, base));
    let mut table_evidence = table.evidence.clone();
    let mut entries = match table.kind {
        OriginExpressionKind::Table { entries } => entries,
        _ => {
            set_register(
                state,
                base,
                FlowValue::Origin(unknown(
                    OriginUnknownReason::UnsupportedValue,
                    [instruction.id.clone()],
                )),
            );
            return;
        }
    };
    for (index, value) in before.iter().enumerate() {
        if index == usize::from(base) {
            continue;
        }
        if let FlowValue::Origin(candidate) = value {
            let original = OriginExpression {
                kind: OriginExpressionKind::Table {
                    entries: entries.clone(),
                },
                evidence: table_evidence.clone(),
            };
            if same_shape(candidate, &original) {
                if let Some(slot) = state.get_mut(index) {
                    *slot = FlowValue::Origin(unknown(
                        OriginUnknownReason::UnsupportedValue,
                        [instruction.id.clone()],
                    ));
                }
            }
        }
    }
    for offset in 0..count {
        let Some(register) = base
            .checked_add(1)
            .and_then(|first| first.checked_add(offset as u8))
        else {
            set_register(
                state,
                base,
                FlowValue::Origin(unknown(
                    OriginUnknownReason::RegisterWindowLimit,
                    [instruction.id.clone()],
                )),
            );
            return;
        };
        entries.push(origin_from_flow(get_register(before, register)));
    }
    table_evidence.push(instruction.id.clone());
    set_register(
        state,
        base,
        FlowValue::Origin(bounded_expression(
            OriginExpressionKind::Table { entries },
            table_evidence,
        )),
    );
}

fn invalidate_table_aliases(
    state: &mut RegisterState,
    before: &RegisterState,
    base: Option<u8>,
    instruction: &SemanticInstruction,
) {
    let Some(base) = base else {
        return;
    };
    let base = origin_from_flow(get_register(before, base));
    for (slot, previous) in state.iter_mut().zip(before) {
        if let FlowValue::Origin(candidate) = previous {
            if same_shape(candidate, &base) && contains_table(candidate) {
                *slot = FlowValue::Origin(unknown(
                    OriginUnknownReason::UnsupportedValue,
                    [instruction.id.clone()],
                ));
            }
        }
    }
}

fn invalidate_table_values(state: &mut RegisterState, instruction: &SemanticInstruction) {
    for value in state {
        if matches!(value, FlowValue::Origin(expression) if contains_table(expression)) {
            *value = FlowValue::Origin(unknown(
                OriginUnknownReason::UnsupportedValue,
                [instruction.id.clone()],
            ));
        }
    }
}

fn transfer_call_results(
    instruction: &SemanticInstruction,
    state: &mut RegisterState,
    frame_size: usize,
) {
    let Some(base) = register_operand(instruction, 0) else {
        return;
    };
    let counts = count_operands(instruction);
    let Some((result_count, variable)) = counts.get(1).copied() else {
        return;
    };
    if variable {
        invalidate_from(
            state,
            base,
            frame_size,
            OriginUnknownReason::OpenResultWindow,
            [instruction.id.clone()],
        );
    } else if result_count > 1 {
        for result_index in 0..result_count - 1 {
            let Some(register) = base.checked_add(result_index as u8) else {
                break;
            };
            set_register(
                state,
                register,
                FlowValue::Origin(expression(
                    OriginExpressionKind::CallResult {
                        call_id: instruction.id.clone(),
                        result_index,
                    },
                    [instruction.id.clone()],
                )),
            );
        }
    }
}

fn transfer_vararg(
    instruction: &SemanticInstruction,
    state: &mut RegisterState,
    frame_size: usize,
) {
    let Some(base) = register_operand(instruction, 0) else {
        return;
    };
    let Some((count, variable)) = count_operands(instruction).first().copied() else {
        return;
    };
    if variable {
        invalidate_from(
            state,
            base,
            frame_size,
            OriginUnknownReason::OpenResultWindow,
            [instruction.id.clone()],
        );
    } else if count > 1 {
        for index in 0..count - 1 {
            if let Some(register) = base.checked_add(index as u8) {
                set_register(
                    state,
                    register,
                    FlowValue::Origin(unknown(
                        OriginUnknownReason::VarargValue,
                        [instruction.id.clone()],
                    )),
                );
            }
        }
    }
}

fn invalidate_writes(
    instruction: &SemanticInstruction,
    state: &mut RegisterState,
    frame_size: usize,
) {
    if instruction.mnemonic == "SETLIST" {
        return;
    }
    for write in &instruction.writes {
        match write {
            EffectTarget::Register { index } => set_register(
                state,
                *index,
                FlowValue::Origin(unknown(
                    OriginUnknownReason::Overwritten,
                    [instruction.id.clone()],
                )),
            ),
            EffectTarget::RegisterRange { start, end } => {
                for register in *start..=*end {
                    set_register(
                        state,
                        register,
                        FlowValue::Origin(unknown(
                            OriginUnknownReason::Overwritten,
                            [instruction.id.clone()],
                        )),
                    );
                }
            }
            EffectTarget::RegisterRangeToTop { start } => invalidate_from(
                state,
                *start,
                frame_size,
                OriginUnknownReason::OpenResultWindow,
                [instruction.id.clone()],
            ),
            _ => {}
        }
    }
}

fn collect_calls(
    proto: &Prototype,
    instructions: &[SemanticInstruction],
    cfg: &ControlFlowGraph,
    in_states: &[RegisterState],
    captures: &CaptureEnvironment,
) -> Vec<CallOriginFact> {
    let mut calls = Vec::new();
    let reachable_pcs: BTreeSet<_> = cfg
        .blocks
        .iter()
        .filter(|block| block.is_reachable)
        .flat_map(|block| block.instruction_pcs.iter().copied())
        .collect();
    for block in cfg.blocks.iter().filter(|block| block.is_reachable) {
        let mut state = in_states[block.index].clone();
        for &pc in &block.instruction_pcs {
            let Some(instruction) = instructions.get(pc) else {
                continue;
            };
            if is_call(instruction) {
                calls.push(call_fact(proto, instruction, &state, None));
            }
            transfer(
                instruction,
                &mut state,
                captures,
                usize::from(proto.maxstacksize),
            );
        }
    }
    for instruction in instructions
        .iter()
        .filter(|instruction| is_call(instruction))
    {
        if !reachable_pcs.contains(&instruction.pc) {
            calls.push(call_fact(
                proto,
                instruction,
                &[],
                Some(OriginUnknownReason::Unreachable),
            ));
        }
    }
    calls.sort_by_key(|call| call.pc);
    calls
}

fn enumerate_calls_with_reason(
    proto: &Prototype,
    instructions: &[SemanticInstruction],
    reason: OriginUnknownReason,
) -> Vec<CallOriginFact> {
    instructions
        .iter()
        .filter(|instruction| is_call(instruction))
        .map(|instruction| call_fact(proto, instruction, &[], Some(reason)))
        .collect()
}

fn call_fact(
    proto: &Prototype,
    instruction: &SemanticInstruction,
    state: &[FlowValue],
    forced_reason: Option<OriginUnknownReason>,
) -> CallOriginFact {
    let base = register_operand(instruction, 0).unwrap_or(0);
    let argument_count = count_operands(instruction).first().copied();
    let argument_window = match argument_count {
        Some((_, true)) => CallArgumentWindow::Open {
            reason: forced_reason.unwrap_or(OriginUnknownReason::OpenArgumentWindow),
        },
        Some((count, false)) => {
            let arguments = (0..count.saturating_sub(1))
                .map(|argument_index| {
                    let register = base
                        .checked_add(1)
                        .and_then(|first| first.checked_add(argument_index as u8))
                        .unwrap_or(u8::MAX);
                    let origin = forced_reason.map_or_else(
                        || origin_from_flow(get_register(state, register)),
                        |reason| unknown(reason, [instruction.id.clone()]),
                    );
                    FixedArgumentOrigin {
                        argument_index,
                        register,
                        origin,
                    }
                })
                .collect();
            CallArgumentWindow::Fixed { arguments }
        }
        None => CallArgumentWindow::Open {
            reason: forced_reason.unwrap_or(OriginUnknownReason::UnsupportedInstruction),
        },
    };
    CallOriginFact {
        call_id: instruction.id.clone(),
        proto_path: proto.path.clone(),
        pc: instruction.pc,
        call_kind: instruction.mnemonic.clone(),
        callee_register: base,
        argument_window,
    }
}

fn derive_child_captures(
    proto: &Prototype,
    instructions: &[SemanticInstruction],
    cfg: &ControlFlowGraph,
    dataflow: &DataflowResult,
    parent_captures: &CaptureEnvironment,
) -> BTreeMap<usize, CaptureEnvironment> {
    if dataflow.exhausted {
        return BTreeMap::new();
    }
    let mut environments: BTreeMap<usize, CaptureEnvironment> = BTreeMap::new();
    for closure in instructions
        .iter()
        .filter(|instruction| instruction.mnemonic == "CLOSURE")
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
            usize::from(proto.maxstacksize),
        );
        let destination = register_operand(closure, 0);
        let candidate = environments.entry(child_index).or_default();
        for slot in 0..child.upvalues.len() {
            let descriptor_pc = closure.pc + 1 + slot;
            let value = instructions
                .get(descriptor_pc)
                .map(|descriptor| {
                    capture_from_descriptor(
                        proto,
                        child,
                        slot as u8,
                        closure,
                        destination,
                        descriptor,
                        &state,
                        instructions,
                        cfg,
                        parent_captures,
                    )
                })
                .unwrap_or_else(|| {
                    unknown(
                        OriginUnknownReason::AmbiguousCapture,
                        [StableId::upvalue(child.path.clone(), slot)],
                    )
                });
            candidate
                .entry(slot as u8)
                .and_modify(|existing| {
                    *existing = merge_equal(existing, &value).unwrap_or_else(|| {
                        unknown(
                            OriginUnknownReason::AmbiguousCapture,
                            existing.evidence.iter().chain(&value.evidence).cloned(),
                        )
                    });
                })
                .or_insert(value);
        }
    }
    environments
}

#[allow(clippy::too_many_arguments)]
fn capture_from_descriptor(
    parent: &Prototype,
    child: &Prototype,
    slot: u8,
    closure: &SemanticInstruction,
    closure_destination: Option<u8>,
    descriptor: &SemanticInstruction,
    state: &RegisterState,
    parent_instructions: &[SemanticInstruction],
    parent_cfg: &ControlFlowGraph,
    parent_captures: &CaptureEnvironment,
) -> OriginExpression {
    let child_id = StableId::upvalue(child.path.clone(), slot as usize);
    if capture_slot_is_mutated(child, slot) || !is_closure_binding(descriptor) {
        return unknown(
            OriginUnknownReason::MutableCapture,
            [child_id, closure.id.clone(), descriptor.id.clone()],
        );
    }
    let value = match descriptor.reads.first() {
        Some(EffectTarget::Register { index }) => {
            if Some(*index) == closure_destination
                || local_capture_is_mutated(parent, parent_instructions, *index)
                || effect_may_be_written_after(
                    parent_instructions,
                    parent_cfg,
                    closure.pc,
                    &EffectTarget::Register { index: *index },
                )
            {
                unknown(OriginUnknownReason::MutableCapture, [])
            } else {
                origin_from_flow(get_register(state, *index))
            }
        }
        Some(EffectTarget::Upvalue { index, .. }) => {
            if capture_slot_is_mutated(parent, *index)
                || effect_may_be_written_after(
                    parent_instructions,
                    parent_cfg,
                    closure.pc,
                    &EffectTarget::Upvalue {
                        index: *index,
                        name: None,
                    },
                )
            {
                unknown(OriginUnknownReason::MutableCapture, [])
            } else {
                parent_captures
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| unknown(OriginUnknownReason::AmbiguousCapture, []))
            }
        }
        _ => unknown(OriginUnknownReason::AmbiguousCapture, []),
    };
    if contains_table(&value) {
        return unknown(
            OriginUnknownReason::MutableCapture,
            [child_id, closure.id.clone(), descriptor.id.clone()],
        );
    }
    add_expression_evidence(value, [child_id, closure.id.clone(), descriptor.id.clone()])
}

fn local_capture_is_mutated(
    parent: &Prototype,
    instructions: &[SemanticInstruction],
    register: u8,
) -> bool {
    instructions
        .iter()
        .filter(|instruction| instruction.mnemonic == "CLOSURE")
        .any(|closure| {
            let Some(child_index) = closure.operands.iter().find_map(|operand| match operand {
                TypedOperand::Prototype { index, .. } => Some(*index),
                _ => None,
            }) else {
                return false;
            };
            let Some(child) = parent.protos.get(child_index) else {
                return true;
            };
            (0..child.upvalues.len()).any(|slot| {
                instructions
                    .get(closure.pc + 1 + slot)
                    .is_some_and(|descriptor| {
                        is_closure_binding(descriptor)
                            && matches!(
                                descriptor.reads.first(),
                                Some(EffectTarget::Register { index }) if *index == register
                            )
                            && capture_slot_is_mutated(child, slot as u8)
                    })
            })
        })
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
        if let Some(instruction) = instructions.get(pc) {
            transfer(instruction, &mut state, captures, frame_size);
        }
    }
    state
}

fn root_capture_environment(proto: &Prototype) -> CaptureEnvironment {
    proto
        .upvalues
        .iter()
        .enumerate()
        .map(|(index, upvalue)| {
            let id = StableId::upvalue(proto.path.clone(), index);
            (
                index as u8,
                expression(
                    OriginExpressionKind::Upvalue {
                        owner: proto.path.clone(),
                        index: index as u8,
                        name: upvalue.name.as_ref().map(|name| name.display.clone()),
                    },
                    [id],
                ),
            )
        })
        .collect()
}

fn unknown_capture_environment(proto: &Prototype) -> CaptureEnvironment {
    proto
        .upvalues
        .iter()
        .enumerate()
        .map(|(index, _)| {
            (
                index as u8,
                unknown(
                    OriginUnknownReason::AmbiguousCapture,
                    [StableId::upvalue(proto.path.clone(), index)],
                ),
            )
        })
        .collect()
}

fn capture_slot_is_mutated(proto: &Prototype, slot: u8) -> bool {
    let instructions = luad_dialect_lua51::lift_proto_lua51(proto);
    instructions.iter().any(|instruction| {
        instruction
            .writes
            .iter()
            .any(|write| matches!(write, EffectTarget::Upvalue { index, .. } if *index == slot))
    }) || proto.protos.iter().any(|child| {
        child.upvalues.iter().any(|capture| {
            capture.instack == 0
                && capture.idx == slot
                && capture_slot_is_mutated(child, capture.index as u8)
        })
    })
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
    let reachable = reachable_blocks_after(cfg, origin_block.index);
    instructions.iter().any(|instruction| {
        if is_closure_binding(instruction) || !write_overlaps(&instruction.writes, target) {
            return false;
        }
        let Some(writer_block) = cfg
            .blocks
            .iter()
            .find(|block| block.instruction_pcs.contains(&instruction.pc))
        else {
            return true;
        };
        if writer_block.index == origin_block.index {
            instruction.pc > origin_pc || reachable.contains(&origin_block.index)
        } else {
            reachable.contains(&writer_block.index)
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

fn expression_operand(
    instruction: &SemanticInstruction,
    operand_index: usize,
    state: &[FlowValue],
) -> Option<OriginExpression> {
    match instruction.operands.get(operand_index)? {
        TypedOperand::Register { index } => Some(origin_from_flow(get_register(state, *index))),
        TypedOperand::Constant { index, value } => {
            let id = StableId::constant(proto_from_instruction(&instruction.id), *index);
            Some(literal(
                Some(id.clone()),
                value,
                [id, instruction.id.clone()],
            ))
        }
        _ => None,
    }
}

fn literal(
    constant_id: Option<StableId>,
    value: &ConstantValue,
    evidence: impl IntoIterator<Item = StableId>,
) -> OriginExpression {
    let evidence: Vec<_> = evidence.into_iter().collect();
    origin_literal(value).map_or_else(
        || {
            unknown(
                OriginUnknownReason::UnsupportedValue,
                evidence.iter().cloned(),
            )
        },
        |value| {
            expression(
                OriginExpressionKind::Literal { constant_id, value },
                evidence.iter().cloned(),
            )
        },
    )
}

fn origin_literal(value: &ConstantValue) -> Option<OriginLiteral> {
    match value {
        ConstantValue::Nil => Some(OriginLiteral::Nil),
        ConstantValue::Boolean(value) => Some(OriginLiteral::Boolean { value: *value }),
        ConstantValue::Integer { val, raw_hex } => Some(OriginLiteral::Integer {
            value: *val,
            raw_hex: raw_hex.clone(),
        }),
        ConstantValue::Float {
            raw_hex,
            is_nan,
            is_inf,
            ..
        } => Some(OriginLiteral::Float {
            raw_hex: raw_hex.clone(),
            is_nan: *is_nan,
            is_inf: *is_inf,
        }),
        ConstantValue::ShortString(value) | ConstantValue::LongString(value) => {
            Some(OriginLiteral::String {
                value: value.clone(),
            })
        }
    }
}

fn string_literal(value: &ConstantValue) -> Option<LuaString> {
    match value {
        ConstantValue::ShortString(value) | ConstantValue::LongString(value) => Some(value.clone()),
        _ => None,
    }
}

fn expression(
    kind: OriginExpressionKind,
    evidence: impl IntoIterator<Item = StableId>,
) -> OriginExpression {
    OriginExpression {
        kind,
        evidence: evidence
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    }
}

fn unknown(
    reason: OriginUnknownReason,
    evidence: impl IntoIterator<Item = StableId>,
) -> OriginExpression {
    expression(OriginExpressionKind::Unknown { reason }, evidence)
}

fn bounded_expression(
    kind: OriginExpressionKind,
    evidence: impl IntoIterator<Item = StableId>,
) -> OriginExpression {
    let candidate = expression(kind, evidence);
    if let Some(reason) = first_cutoff(&candidate) {
        return unknown(reason, candidate.evidence);
    }
    let (depth, nodes) = expression_size(&candidate);
    if depth > MAX_EXPRESSION_DEPTH {
        unknown(
            OriginUnknownReason::ExpressionDepthLimit,
            candidate.evidence,
        )
    } else if nodes > MAX_EXPRESSION_NODES {
        unknown(OriginUnknownReason::ExpressionNodeLimit, candidate.evidence)
    } else {
        candidate
    }
}

fn first_cutoff(expression: &OriginExpression) -> Option<OriginUnknownReason> {
    match &expression.kind {
        OriginExpressionKind::Unknown { reason }
            if matches!(
                reason,
                OriginUnknownReason::ExpressionDepthLimit
                    | OriginUnknownReason::ExpressionNodeLimit
                    | OriginUnknownReason::RegisterWindowLimit
                    | OriginUnknownReason::AnalysisLimit
            ) =>
        {
            Some(*reason)
        }
        OriginExpressionKind::Field { base, .. }
        | OriginExpressionKind::Unary { operand: base, .. } => first_cutoff(base),
        OriginExpressionKind::Binary { left, right, .. } => {
            first_cutoff(left).or_else(|| first_cutoff(right))
        }
        OriginExpressionKind::Concat { parts } | OriginExpressionKind::Table { entries: parts } => {
            parts.iter().find_map(first_cutoff)
        }
        _ => None,
    }
}

fn expression_size(expression: &OriginExpression) -> (usize, usize) {
    match &expression.kind {
        OriginExpressionKind::Field { base, .. }
        | OriginExpressionKind::Unary { operand: base, .. } => {
            let (depth, nodes) = expression_size(base);
            (depth.saturating_add(1), nodes.saturating_add(1))
        }
        OriginExpressionKind::Binary { left, right, .. } => {
            let (left_depth, left_nodes) = expression_size(left);
            let (right_depth, right_nodes) = expression_size(right);
            (
                left_depth.max(right_depth).saturating_add(1),
                left_nodes.saturating_add(right_nodes).saturating_add(1),
            )
        }
        OriginExpressionKind::Concat { parts } | OriginExpressionKind::Table { entries: parts } => {
            let mut depth = 0usize;
            let mut nodes = 1usize;
            for part in parts {
                let (part_depth, part_nodes) = expression_size(part);
                depth = depth.max(part_depth);
                nodes = nodes.saturating_add(part_nodes);
            }
            (depth.saturating_add(1), nodes)
        }
        _ => (1, 1),
    }
}

fn merge_equal(left: &OriginExpression, right: &OriginExpression) -> Option<OriginExpression> {
    if !same_shape(left, right) {
        return None;
    }
    let mut merged = left.clone();
    union_expression_evidence(&mut merged, right);
    Some(merged)
}

fn same_shape(left: &OriginExpression, right: &OriginExpression) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    clear_evidence(&mut left);
    clear_evidence(&mut right);
    left == right
}

fn contains_table(expression: &OriginExpression) -> bool {
    match &expression.kind {
        OriginExpressionKind::Table { .. } => true,
        OriginExpressionKind::Field { base, .. }
        | OriginExpressionKind::Unary { operand: base, .. } => contains_table(base),
        OriginExpressionKind::Binary { left, right, .. } => {
            contains_table(left) || contains_table(right)
        }
        OriginExpressionKind::Concat { parts } => parts.iter().any(contains_table),
        _ => false,
    }
}

fn clear_evidence(expression: &mut OriginExpression) {
    expression.evidence.clear();
    match &mut expression.kind {
        OriginExpressionKind::Field { base, .. }
        | OriginExpressionKind::Unary { operand: base, .. } => clear_evidence(base),
        OriginExpressionKind::Binary { left, right, .. } => {
            clear_evidence(left);
            clear_evidence(right);
        }
        OriginExpressionKind::Concat { parts } | OriginExpressionKind::Table { entries: parts } => {
            for part in parts {
                clear_evidence(part);
            }
        }
        _ => {}
    }
}

fn union_expression_evidence(left: &mut OriginExpression, right: &OriginExpression) {
    left.evidence = left
        .evidence
        .iter()
        .chain(&right.evidence)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    match (&mut left.kind, &right.kind) {
        (
            OriginExpressionKind::Field { base: left, .. },
            OriginExpressionKind::Field { base: right, .. },
        )
        | (
            OriginExpressionKind::Unary { operand: left, .. },
            OriginExpressionKind::Unary { operand: right, .. },
        ) => union_expression_evidence(left, right),
        (
            OriginExpressionKind::Binary {
                left: left_left,
                right: left_right,
                ..
            },
            OriginExpressionKind::Binary {
                left: right_left,
                right: right_right,
                ..
            },
        ) => {
            union_expression_evidence(left_left, right_left);
            union_expression_evidence(left_right, right_right);
        }
        (
            OriginExpressionKind::Concat { parts: left },
            OriginExpressionKind::Concat { parts: right },
        )
        | (
            OriginExpressionKind::Table { entries: left },
            OriginExpressionKind::Table { entries: right },
        ) => {
            for (left, right) in left.iter_mut().zip(right) {
                union_expression_evidence(left, right);
            }
        }
        _ => {}
    }
}

fn add_expression_evidence(
    mut expression: OriginExpression,
    evidence: impl IntoIterator<Item = StableId>,
) -> OriginExpression {
    expression.evidence = expression
        .evidence
        .into_iter()
        .chain(evidence)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    expression
}

fn add_evidence(value: FlowValue, evidence: &StableId) -> FlowValue {
    match value {
        FlowValue::Origin(expression) => {
            FlowValue::Origin(add_expression_evidence(expression, [evidence.clone()]))
        }
        FlowValue::Bottom => FlowValue::Bottom,
    }
}

fn origin_from_flow(value: FlowValue) -> OriginExpression {
    match value {
        FlowValue::Origin(expression) => expression,
        FlowValue::Bottom => unknown(OriginUnknownReason::MissingDefinition, []),
    }
}

fn get_register(state: &[FlowValue], index: u8) -> FlowValue {
    state
        .get(usize::from(index))
        .cloned()
        .unwrap_or_else(|| FlowValue::Origin(unknown(OriginUnknownReason::RegisterWindowLimit, [])))
}

fn set_register(state: &mut RegisterState, index: u8, value: FlowValue) {
    if let Some(slot) = state.get_mut(usize::from(index)) {
        *slot = value;
    }
}

fn invalidate_from(
    state: &mut RegisterState,
    start: u8,
    frame_size: usize,
    reason: OriginUnknownReason,
    evidence: impl IntoIterator<Item = StableId>,
) {
    let evidence: Vec<_> = evidence.into_iter().collect();
    for slot in state.iter_mut().take(frame_size).skip(usize::from(start)) {
        *slot = FlowValue::Origin(unknown(reason, evidence.iter().cloned()));
    }
}

fn invalidate_all(
    state: &mut RegisterState,
    reason: OriginUnknownReason,
    evidence: impl IntoIterator<Item = StableId>,
) {
    let evidence: Vec<_> = evidence.into_iter().collect();
    for slot in state {
        *slot = FlowValue::Origin(unknown(reason, evidence.iter().cloned()));
    }
}

fn written_registers(instruction: &SemanticInstruction, frame_size: usize) -> Vec<u8> {
    let mut registers = BTreeSet::new();
    for write in &instruction.writes {
        match write {
            EffectTarget::Register { index } => {
                registers.insert(*index);
            }
            EffectTarget::RegisterRange { start, end } => {
                registers.extend(*start..=*end);
            }
            EffectTarget::RegisterRangeToTop { start } => {
                registers.extend(
                    (usize::from(*start)..frame_size.min(usize::from(u8::MAX) + 1))
                        .map(|register| register as u8),
                );
            }
            _ => {}
        }
    }
    registers.into_iter().collect()
}

fn count_operands(instruction: &SemanticInstruction) -> Vec<(usize, bool)> {
    instruction
        .operands
        .iter()
        .filter_map(|operand| match operand {
            TypedOperand::Count { value, is_variable } => Some((*value, *is_variable)),
            _ => None,
        })
        .collect()
}

fn register_operand(instruction: &SemanticInstruction, ordinal: usize) -> Option<u8> {
    instruction
        .operands
        .iter()
        .filter_map(|operand| match operand {
            TypedOperand::Register { index } => Some(*index),
            _ => None,
        })
        .nth(ordinal)
}

fn constant_operand(
    instruction: &SemanticInstruction,
    ordinal: usize,
) -> Option<(usize, ConstantValue)> {
    instruction
        .operands
        .iter()
        .filter_map(|operand| match operand {
            TypedOperand::Constant { index, value } => Some((*index, value.clone())),
            _ => None,
        })
        .nth(ordinal)
}

fn upvalue_operand(instruction: &SemanticInstruction) -> Option<(u8, Option<String>)> {
    instruction
        .operands
        .iter()
        .find_map(|operand| match operand {
            TypedOperand::Upvalue { index, name } => Some((*index, name.clone())),
            _ => None,
        })
}

fn proto_from_instruction(id: &StableId) -> ProtoPath {
    match id {
        StableId::Instruction { proto, .. } => proto.clone(),
        _ => ProtoPath::root(),
    }
}

fn is_call(instruction: &SemanticInstruction) -> bool {
    matches!(instruction.mnemonic.as_str(), "CALL" | "TAILCALL")
}

fn is_closure_binding(instruction: &SemanticInstruction) -> bool {
    instruction.implicit_effects.iter().any(|effect| {
        matches!(
            effect,
            ImplicitEffect::CompanionPair { companion_role, .. }
                if companion_role == "closure_binding"
        )
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_join_unions_nested_evidence() {
        let left = bounded_expression(
            OriginExpressionKind::Unary {
                operator: "LEN".into(),
                operand: Box::new(expression(
                    OriginExpressionKind::Parameter {
                        owner: ProtoPath::root(),
                        index: 0,
                    },
                    [StableId::instruction(ProtoPath::root(), 1)],
                )),
            },
            [StableId::instruction(ProtoPath::root(), 2)],
        );
        let right = bounded_expression(
            OriginExpressionKind::Unary {
                operator: "LEN".into(),
                operand: Box::new(expression(
                    OriginExpressionKind::Parameter {
                        owner: ProtoPath::root(),
                        index: 0,
                    },
                    [StableId::instruction(ProtoPath::root(), 3)],
                )),
            },
            [StableId::instruction(ProtoPath::root(), 4)],
        );
        let merged = merge_equal(&left, &right).expect("same expression must merge");
        assert_eq!(merged.evidence.len(), 2);
        let OriginExpressionKind::Unary { operand, .. } = merged.kind else {
            panic!("expected unary expression")
        };
        assert_eq!(operand.evidence.len(), 2);
    }

    #[test]
    fn conflicting_join_is_explicit() {
        let parameter = FlowValue::Origin(expression(
            OriginExpressionKind::Parameter {
                owner: ProtoPath::root(),
                index: 0,
            },
            [],
        ));
        let literal = FlowValue::Origin(expression(
            OriginExpressionKind::Literal {
                constant_id: None,
                value: OriginLiteral::Nil,
            },
            [],
        ));
        assert!(matches!(
            meet_value(&parameter, &literal),
            FlowValue::Origin(OriginExpression {
                kind: OriginExpressionKind::Unknown {
                    reason: OriginUnknownReason::ControlFlowConflict
                },
                ..
            })
        ));
    }

    #[test]
    fn cutoff_propagates_instead_of_growing_a_cycle() {
        let cutoff = unknown(OriginUnknownReason::ExpressionDepthLimit, []);
        let wrapped = bounded_expression(
            OriginExpressionKind::Unary {
                operator: "LEN".into(),
                operand: Box::new(cutoff),
            },
            [],
        );
        assert!(matches!(
            wrapped.kind,
            OriginExpressionKind::Unknown {
                reason: OriginUnknownReason::ExpressionDepthLimit
            }
        ));
    }
}
