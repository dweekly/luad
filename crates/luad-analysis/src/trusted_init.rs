//! Opt-in `trusted-init` admission for Lua 5.1 modules the strict convention refuses.
//!
//! The strict convention admits only a declarative root. This admission states, rather
//! than proves, that the rest of the root is harmless. Under the `trusted-init`
//! assumption, code run during module initialization does not replace, remove or alias
//! any module's exported functions, or change a module's environment. That covers the
//! root's own statements, same-file functions, and anything reached through values the
//! analysis does not identify. Every answer that relies on an admission here carries the
//! `trusted-init` label.
//!
//! Only cheap refusals that are directly visible in the root's bytecode are kept:
//! - no single literal `module(...)` declaration that runs on every path;
//! - a second `module` load;
//! - a direct `setfenv` or `getfenv` global used as a call target, including through a
//!   register copy.
//!
//! Each name's root stores decide its export: one unconditional closure store after the
//! declaration is an export, and anything else makes that one label dynamic.

use std::collections::{BTreeMap, BTreeSet};

use luad_core::model::{Chunk, ConstantValue};
use luad_core::{EffectTarget, ProtoPath, StableId};
use luad_dialect_lua51::{Opcode51 as Op, RawInstruction51};

use crate::callees::{analyze_root_global_stores, GlobalStoreValue};
use crate::cfg::ControlFlowGraph;

/// A module admitted under `trusted-init`.
pub(crate) struct TrustedModule {
    pub segments: Vec<String>,
    pub declaration_evidence: Vec<StableId>,
    /// `(export name, defining prototype, evidence)` in root order.
    pub exports: Vec<(String, ProtoPath, Vec<StableId>)>,
    /// Dynamic label prefixes with their evidence.
    pub marks: BTreeMap<Vec<String>, BTreeSet<StableId>>,
}

pub(crate) enum TrustedOutcome {
    Admitted(TrustedModule),
    /// The module's namespace cannot be named; the whole corpus degrades.
    Refused(Vec<StableId>),
    Limited,
}

/// What a register visibly holds, for the declaration and environment checks only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Other,
    Module,
    /// The global `setfenv` or `getfenv`.
    Environment,
    Package,
    Seeall,
    /// A string loaded by `LOADK` at this PC.
    Literal(usize),
}

fn string_bytes(value: &ConstantValue) -> Option<&[u8]> {
    match value {
        ConstantValue::ShortString(s) | ConstantValue::LongString(s) => Some(&s.raw_bytes),
        _ => None,
    }
}

fn written_registers(target: &EffectTarget, frame: usize) -> std::ops::Range<usize> {
    match target {
        EffectTarget::Register { index } => *index as usize..*index as usize + 1,
        EffectTarget::RegisterRange { start, end } => *start as usize..*end as usize + 1,
        EffectTarget::RegisterRangeToTop { start } => *start as usize..frame.max(*start as usize),
        _ => 0..0,
    }
}

fn dominates(cfg: &ControlFlowGraph, dominator: usize, block: usize) -> bool {
    let mut current = Some(block);
    let mut steps = 0;
    while let Some(b) = current {
        if b == dominator {
            return true;
        }
        steps += 1;
        if steps > cfg.blocks.len() {
            return false;
        }
        current = cfg.blocks[b].immediate_dominator.filter(|&d| d != b);
    }
    false
}

/// Which blocks dominate every reachable exit, computed once per block on demand.
struct ExitDominance<'a> {
    cfg: &'a ControlFlowGraph,
    exits: Vec<usize>,
    known: BTreeMap<usize, bool>,
}

impl<'a> ExitDominance<'a> {
    fn new(cfg: &'a ControlFlowGraph) -> Self {
        let exits = cfg
            .blocks
            .iter()
            .filter(|b| b.is_reachable && b.is_exit)
            .map(|b| b.index)
            .collect();
        Self {
            cfg,
            exits,
            known: BTreeMap::new(),
        }
    }

    fn dominates_exits(&mut self, block: usize) -> bool {
        if let Some(&known) = self.known.get(&block) {
            return known;
        }
        let answer = self.cfg.blocks[block].is_reachable
            && !self.exits.is_empty()
            && self
                .exits
                .iter()
                .all(|&exit| dominates(self.cfg, block, exit));
        self.known.insert(block, answer);
        answer
    }
}

fn root_pc(id: &StableId) -> Option<usize> {
    match id {
        StableId::Instruction { proto, pc } if proto == &ProtoPath::root() => Some(*pc),
        _ => None,
    }
}

/// Re-examine a root the strict rule refused. The caller has already checked the chunk
/// is Lua 5.1 and loads `module`. Work is bounded by `MAX_MODULE_INIT_WORDS` root
/// instructions: one linear pass, the shared root store analysis, and one exit-dominance
/// answer per block (each a walk up the dominator tree from every exit). Nested
/// prototypes are never visited.
pub(crate) fn admit_trusted_module(chunk: &Chunk) -> TrustedOutcome {
    let p = &chunk.main_proto;
    let refused = |pcs: &mut dyn Iterator<Item = usize>| {
        let mut evidence: Vec<StableId> = pcs
            .filter_map(|pc| p.instructions.get(pc).map(|w| w.id.clone()))
            .collect();
        if evidence.is_empty() {
            evidence.push(p.id.clone());
        }
        TrustedOutcome::Refused(evidence)
    };
    if crate::validate_for_analysis(chunk).is_err() {
        return refused(&mut std::iter::empty());
    }
    if p.instructions.len() > super::linking::MAX_MODULE_INIT_WORDS {
        return TrustedOutcome::Limited;
    }
    let constant = |index: usize| p.constants.get(index).map(|c| &c.value);
    let instructions = crate::lift_proto_for_dialect(&chunk.dialect, p);
    let cfg = ControlFlowGraph::build(p, &instructions);
    if cfg.blocks.is_empty() {
        return refused(&mut std::iter::empty());
    }
    let frame = (p.maxstacksize as usize).clamp(1, 256);

    let mut block_of = BTreeMap::new();
    for block in &cfg.blocks {
        for &pc in &block.instruction_pcs {
            block_of.insert(pc, block.index);
        }
    }

    // One linear pass in PC order. It is not path-sensitive: it only has to find the
    // declaration and the directly visible environment calls.
    let mut registers = vec![Token::Other; frame];
    let mut module_loads = Vec::new();
    let mut declarations = Vec::new();
    let mut option_calls = Vec::new();
    let mut refusals = Vec::new();
    let mut constant_bytes = 0usize;
    for &pc in block_of.keys() {
        let instruction = &instructions[pc];
        let raw = RawInstruction51::decode(instruction.raw_word);
        let a = raw.a as usize;
        let key = match raw.opcode {
            Some(Op::LoadK | Op::GetGlobal | Op::SetGlobal) => Some(raw.bx as usize),
            Some(Op::GetTable | Op::SelfOp) if raw.c >= 256 => Some((raw.c - 256) as usize),
            _ => None,
        };
        if let Some(value) = key.and_then(constant) {
            constant_bytes = constant_bytes.saturating_add(match value {
                ConstantValue::ShortString(s) | ConstantValue::LongString(s) => {
                    s.raw_bytes.len().saturating_add(s.display.len())
                }
                ConstantValue::Float { raw_hex, .. } | ConstantValue::Integer { raw_hex, .. } => {
                    raw_hex.len()
                }
                _ => 1,
            });
            if constant_bytes > super::linking::MAX_MODULE_INIT_CONSTANT_BYTES {
                return TrustedOutcome::Limited;
            }
        }
        let read = |r: usize| registers.get(r).copied().unwrap_or(Token::Other);
        let produced = match raw.opcode {
            Some(Op::GetGlobal) => Some(match constant(raw.bx as usize).and_then(string_bytes) {
                Some(b"module") => {
                    module_loads.push(pc);
                    Token::Module
                }
                Some(b"setfenv" | b"getfenv") => Token::Environment,
                Some(b"package") => Token::Package,
                _ => Token::Other,
            }),
            Some(Op::LoadK) => Some(match constant(raw.bx as usize).and_then(string_bytes) {
                Some(_) => Token::Literal(pc),
                None => Token::Other,
            }),
            Some(Op::Move) => Some(read(raw.b as usize)),
            Some(Op::GetTable) => Some(
                match (
                    read(raw.b as usize),
                    (raw.c >= 256)
                        .then(|| constant((raw.c - 256) as usize))
                        .flatten()
                        .and_then(string_bytes),
                ) {
                    (Token::Package, Some(b"seeall")) => Token::Seeall,
                    _ => Token::Other,
                },
            ),
            Some(Op::Call | Op::TailCall) => {
                match read(a) {
                    Token::Module => {
                        let literal = match read(a + 1) {
                            Token::Literal(load) => Some(load),
                            _ => None,
                        };
                        match (raw.opcode == Some(Op::Call) && raw.c == 1, literal) {
                            (true, Some(load)) if raw.b >= 2 => {
                                declarations.push((pc, load));
                                let seeall_only =
                                    raw.b == 2 || (raw.b == 3 && read(a + 2) == Token::Seeall);
                                if !seeall_only {
                                    option_calls.push(pc);
                                }
                            }
                            _ => refusals.push(pc),
                        }
                    }
                    Token::Environment => refusals.push(pc),
                    _ => {}
                }
                None
            }
            _ => None,
        };
        // A callee's frame overlaps every register from the call slot up.
        if matches!(raw.opcode, Some(Op::Call | Op::TailCall)) {
            for slot in registers.iter_mut().skip(a) {
                *slot = Token::Other;
            }
        }
        for target in &instruction.writes {
            for register in written_registers(target, frame) {
                if let Some(slot) = registers.get_mut(register) {
                    *slot = Token::Other;
                }
            }
        }
        if let (Some(token), Some(slot)) = (produced, registers.get_mut(a)) {
            *slot = token;
        }
    }
    if module_loads.len() != 1 {
        return refused(&mut module_loads.into_iter());
    }
    if !refusals.is_empty() {
        return refused(&mut refusals.into_iter());
    }
    let [(call_pc, load_pc)] = declarations.as_slice() else {
        return refused(&mut declarations.iter().map(|(call, _)| *call));
    };
    let (call_pc, load_pc) = (*call_pc, *load_pc);
    let declaration_block = block_of[&call_pc];
    let mut exit_dominance = ExitDominance::new(&cfg);
    if !exit_dominance.dominates_exits(declaration_block) {
        return refused(&mut std::iter::once(call_pc));
    }
    let raw_load = RawInstruction51::decode(p.instructions[load_pc].raw_word);
    let Some(name) = constant(raw_load.bx as usize)
        .and_then(string_bytes)
        .and_then(|b| std::str::from_utf8(b).ok())
    else {
        return refused(&mut std::iter::once(load_pc));
    };
    if name.as_bytes().contains(&0) || !super::linking::admitted_selector(name.as_bytes()) {
        return refused(&mut std::iter::once(load_pc));
    }
    let parts: Vec<_> = name.split('.').take(32).collect();
    if parts.len() >= 32 {
        return TrustedOutcome::Limited;
    }
    if parts.iter().any(|s| s.is_empty()) {
        return refused(&mut std::iter::once(load_pc));
    }
    let module: Vec<String> = parts.into_iter().map(str::to_owned).collect();
    let in_module = |name: &str| {
        let mut label = module.clone();
        label.push(name.to_string());
        label
    };

    let mut marks: BTreeMap<Vec<String>, BTreeSet<StableId>> = BTreeMap::new();
    let mut add_mark = |label: Vec<String>, pc: usize| {
        marks
            .entry(label)
            .or_default()
            .insert(p.instructions[pc].id.clone());
    };
    // Options receive the module table and may change its metatable.
    for pc in option_calls {
        add_mark(module.clone(), pc);
    }

    let Ok(stores) = analyze_root_global_stores(chunk) else {
        return TrustedOutcome::Limited;
    };
    let mut store_counts: BTreeMap<&[u8], usize> = BTreeMap::new();
    for store in &stores {
        *store_counts.entry(&store.name_raw).or_default() += 1;
    }
    let declared = |pc: usize, block: usize| {
        if block == declaration_block {
            pc > call_pc
        } else {
            dominates(&cfg, declaration_block, block)
        }
    };
    let mut exports = Vec::new();
    for store in &stores {
        let Some(pc) = root_pc(&store.store_id) else {
            continue;
        };
        // Labels with unadmitted segments resolve dynamic at every call site.
        let Ok(name) = std::str::from_utf8(&store.name_raw) else {
            continue;
        };
        if !super::linking::admitted_selector(name.as_bytes()) {
            continue;
        }
        let Some(&block) = block_of.get(&pc) else {
            continue;
        };
        if !declared(pc, block) {
            add_mark(vec![name.to_string()], pc);
            add_mark(in_module(name), pc);
            continue;
        }
        // The root store analysis is path-insensitive, so a closure value is trusted
        // only when everything it rests on lies in the store's own block.
        let in_block = |evidence: &[StableId]| {
            evidence
                .iter()
                .all(|id| root_pc(id).is_some_and(|e| e <= pc && block_of.get(&e) == Some(&block)))
        };
        let settled =
            store_counts[store.name_raw.as_slice()] == 1 && exit_dominance.dominates_exits(block);
        match &store.value {
            GlobalStoreValue::Closure {
                prototype,
                evidence,
            } if settled && in_block(evidence) => {
                exports.push((name.to_string(), prototype.clone(), evidence.clone()));
            }
            // Any other value, even a known non-function, may replace a namespace that
            // labels below `M.name` rely on, so it is never treated as proved absence.
            _ => add_mark(in_module(name), pc),
        }
    }

    TrustedOutcome::Admitted(TrustedModule {
        segments: module,
        declaration_evidence: vec![
            p.instructions[module_loads[0]].id.clone(),
            p.instructions[load_pc].id.clone(),
            p.instructions[call_pc].id.clone(),
        ],
        exports,
        marks,
    })
}
