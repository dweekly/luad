//! Control-flow graph construction, basic block partitioning, and immediate dominator computation.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use luad_core::id::StableId;
use luad_core::ir::SemanticInstruction;
use luad_core::model::Prototype;

/// Classification of control-flow edges.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum CfgEdgeKind {
    /// Normal straight-line execution into subsequent basic block.
    Fallthrough,
    /// Edge taken when a conditional test evaluates to true.
    ConditionalTrue,
    /// Edge taken when a conditional test evaluates to false.
    ConditionalFalse,
    /// Direct unconditional jump.
    UnconditionalJump,
    /// Backward loop branch edge.
    LoopBack,
    /// Skipped single instruction outcome.
    ConditionalSkip,
    /// Function call return continuation.
    ReturnContinuation,
}

/// A directed edge in the control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CfgEdge {
    /// Source basic block index.
    pub from_block: usize,
    /// Destination basic block index.
    pub to_block: usize,
    /// Edge classification.
    pub kind: CfgEdgeKind,
}

/// A basic block of contiguous, non-branching instructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BasicBlock {
    /// Stable block identifier (e.g. `proto:0:block:3`).
    pub id: StableId,
    /// 0-indexed block index within prototype.
    pub index: usize,
    /// Starting program counter (inclusive).
    pub start_pc: usize,
    /// Ending program counter (inclusive).
    pub end_pc: usize,
    /// Sequence of instruction PCs contained in this block.
    pub instruction_pcs: Vec<usize>,
    /// Predecessor block indices.
    pub predecessors: Vec<usize>,
    /// Outgoing control-flow edges.
    pub successors: Vec<CfgEdge>,
    /// Whether this block is the function entry point.
    pub is_entry: bool,
    /// Whether this block contains a function return or exit.
    pub is_exit: bool,
    /// Whether this block is reachable from the entry point.
    pub is_reachable: bool,
    /// Immediate dominator block index (if reachable and computed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immediate_dominator: Option<usize>,
}

/// Control-flow graph for a prototype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ControlFlowGraph {
    /// Target prototype stable ID.
    pub proto_id: StableId,
    /// Sequence of all basic blocks.
    pub blocks: Vec<BasicBlock>,
    /// Total instruction count.
    pub instruction_count: usize,
}

impl ControlFlowGraph {
    /// Build a control-flow graph from lifted semantic instructions of a prototype.
    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn build(proto: &Prototype, instructions: &[SemanticInstruction]) -> Self {
        if instructions.is_empty() {
            return Self {
                proto_id: proto.id.clone(),
                blocks: vec![],
                instruction_count: 0,
            };
        }

        let num_insts = instructions.len();

        // 1. Identify block leaders (entry PCs of basic blocks)
        let mut leaders = BTreeSet::new();
        leaders.insert(0); // PC 0 is always a leader

        for (pc, inst) in instructions.iter().enumerate() {
            // If instruction branches or jumps, target is a leader and fallthrough PC is a leader
            if let Some(target_pc) = inst.jump_target {
                if target_pc < num_insts {
                    leaders.insert(target_pc);
                }
                if pc + 1 < num_insts {
                    leaders.insert(pc + 1);
                }
            }

            // If instruction conditionally skips (e.g. TEST, LFALSESKIP)
            for effect in &inst.implicit_effects {
                if let luad_core::ImplicitEffect::ConditionalSkip { skip_target_pc } = effect {
                    if *skip_target_pc < num_insts {
                        leaders.insert(*skip_target_pc);
                    }
                    if pc + 1 < num_insts {
                        leaders.insert(pc + 1);
                    }
                }
            }

            // Return instructions terminate blocks
            if inst.mnemonic.starts_with("RETURN") && pc + 1 < num_insts {
                leaders.insert(pc + 1);
            }
        }

        let leader_vec: Vec<usize> = leaders.into_iter().collect();
        let mut pc_to_block = BTreeMap::new();
        let mut blocks = Vec::with_capacity(leader_vec.len());

        // 2. Partition into contiguous BasicBlocks
        for (b_idx, &start_pc) in leader_vec.iter().enumerate() {
            let end_pc = if b_idx + 1 < leader_vec.len() {
                leader_vec[b_idx + 1] - 1
            } else {
                num_insts - 1
            };

            let mut pcs = Vec::new();
            for pc in start_pc..=end_pc {
                pcs.push(pc);
                pc_to_block.insert(pc, b_idx);
            }

            let last_inst = &instructions[end_pc];
            let is_exit = last_inst.mnemonic.starts_with("RETURN");

            blocks.push(BasicBlock {
                id: StableId::block(proto.path.clone(), b_idx),
                index: b_idx,
                start_pc,
                end_pc,
                instruction_pcs: pcs,
                predecessors: Vec::new(),
                successors: Vec::new(),
                is_entry: b_idx == 0,
                is_exit,
                is_reachable: false,
                immediate_dominator: None,
            });
        }

        // 3. Connect control-flow edges
        for b_idx in 0..blocks.len() {
            let end_pc = blocks[b_idx].end_pc;
            let last_inst = &instructions[end_pc];

            // A. Jump instruction
            if let Some(target_pc) = last_inst.jump_target {
                if let Some(&dest_b_idx) = pc_to_block.get(&target_pc) {
                    let edge_kind = if target_pc <= end_pc {
                        CfgEdgeKind::LoopBack
                    } else if last_inst.mnemonic == "JMP" {
                        CfgEdgeKind::UnconditionalJump
                    } else {
                        CfgEdgeKind::ConditionalTrue
                    };

                    blocks[b_idx].successors.push(CfgEdge {
                        from_block: b_idx,
                        to_block: dest_b_idx,
                        kind: edge_kind,
                    });
                }
            }

            // B. Conditional skip instructions
            for effect in &last_inst.implicit_effects {
                if let luad_core::ImplicitEffect::ConditionalSkip { skip_target_pc } = effect {
                    if let Some(&skip_b_idx) = pc_to_block.get(skip_target_pc) {
                        blocks[b_idx].successors.push(CfgEdge {
                            from_block: b_idx,
                            to_block: skip_b_idx,
                            kind: CfgEdgeKind::ConditionalSkip,
                        });
                    }
                }
            }

            // C. Fallthrough to next block (unless unconditional jump or return)
            if !last_inst.mnemonic.starts_with("RETURN") && last_inst.mnemonic != "JMP" {
                let next_pc = end_pc + 1;
                if let Some(&next_b_idx) = pc_to_block.get(&next_pc) {
                    if next_b_idx != b_idx
                        && !blocks[b_idx]
                            .successors
                            .iter()
                            .any(|e| e.to_block == next_b_idx)
                    {
                        blocks[b_idx].successors.push(CfgEdge {
                            from_block: b_idx,
                            to_block: next_b_idx,
                            kind: CfgEdgeKind::Fallthrough,
                        });
                    }
                }
            }
        }

        // 4. Fill predecessors from successors
        let mut preds_map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for block in &blocks {
            for edge in &block.successors {
                preds_map
                    .entry(edge.to_block)
                    .or_default()
                    .push(block.index);
            }
        }
        for block in &mut blocks {
            if let Some(preds) = preds_map.get(&block.index) {
                block.predecessors = preds.clone();
            }
        }

        // 5. Compute reachability via BFS from entry block (0)
        let mut queue = VecDeque::new();
        let mut visited = BTreeSet::new();
        queue.push_back(0);
        visited.insert(0);

        while let Some(curr) = queue.pop_front() {
            blocks[curr].is_reachable = true;
            for edge in &blocks[curr].successors {
                if visited.insert(edge.to_block) {
                    queue.push_back(edge.to_block);
                }
            }
        }

        // 6. Compute Immediate Dominators for reachable blocks
        compute_immediate_dominators(&mut blocks);

        Self {
            proto_id: proto.id.clone(),
            blocks,
            instruction_count: num_insts,
        }
    }

    /// Render graph in Graphviz DOT format.
    #[must_use]
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str(&format!("digraph \"{}\" {{\n", self.proto_id));
        dot.push_str("  node [shape=box, fontname=\"Courier\", style=\"rounded,filled\", fillcolor=\"#f8f9fa\"];\n");
        dot.push_str("  edge [fontname=\"Helvetica\", fontsize=10];\n\n");

        for block in &self.blocks {
            let fill = if !block.is_reachable {
                "#ffebee" // light red for unreachable
            } else if block.is_entry {
                "#e8f5e9" // light green for entry
            } else if block.is_exit {
                "#ede7f6" // light purple for exit
            } else {
                "#f8f9fa"
            };

            let label = format!(
                "Block {} (PC {}..{})\\n{} instructions",
                block.index,
                block.start_pc,
                block.end_pc,
                block.instruction_pcs.len()
            );

            dot.push_str(&format!(
                "  b{} [label=\"{}\", fillcolor=\"{}\"];\n",
                block.index, label, fill
            ));

            for edge in &block.successors {
                let (color, style) = match edge.kind {
                    CfgEdgeKind::Fallthrough => ("#9e9e9e", "solid"),
                    CfgEdgeKind::ConditionalTrue => ("#2e7d32", "bold"),
                    CfgEdgeKind::ConditionalFalse => ("#c62828", "bold"),
                    CfgEdgeKind::UnconditionalJump => ("#1565c0", "solid"),
                    CfgEdgeKind::LoopBack => ("#e65100", "dashed"),
                    CfgEdgeKind::ConditionalSkip => ("#6a1b9a", "dotted"),
                    CfgEdgeKind::ReturnContinuation => ("#424242", "dotted"),
                };

                dot.push_str(&format!(
                    "  b{} -> b{} [label=\"{:?}\", color=\"{}\", style=\"{}\"];\n",
                    block.index, edge.to_block, edge.kind, color, style
                ));
            }
        }

        dot.push_str("}\n");
        dot
    }

    /// Compute dominance frontiers for all reachable basic blocks.
    #[must_use]
    pub fn dominance_frontiers(&self) -> BTreeMap<usize, BTreeSet<usize>> {
        let mut df: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for b in &self.blocks {
            if b.is_reachable {
                df.insert(b.index, BTreeSet::new());
            }
        }

        for b in &self.blocks {
            if !b.is_reachable {
                continue;
            }
            if b.predecessors.len() >= 2 {
                for &p in &b.predecessors {
                    let mut runner = p;
                    while let Some(runner_block) = self.blocks.get(runner) {
                        if !runner_block.is_reachable {
                            break;
                        }
                        if Some(runner) == b.immediate_dominator {
                            break;
                        }
                        if let Some(entry) = df.get_mut(&runner) {
                            entry.insert(b.index);
                        }
                        if let Some(idom) = runner_block.immediate_dominator {
                            if idom == runner {
                                break;
                            }
                            runner = idom;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        df
    }
}


/// Compute immediate dominators (idom) using standard iterative dataflow algorithm.
fn compute_immediate_dominators(blocks: &mut [BasicBlock]) {
    let reachable_blocks: Vec<usize> = blocks
        .iter()
        .filter(|b| b.is_reachable)
        .map(|b| b.index)
        .collect();

    if reachable_blocks.is_empty() {
        return;
    }

    let all_reachable_set: BTreeSet<usize> = reachable_blocks.iter().copied().collect();
    let mut doms: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();

    // Entry block dominates only itself
    let mut entry_dom = BTreeSet::new();
    entry_dom.insert(0);
    doms.insert(0, entry_dom);

    // Initial state: every other reachable block is dominated by all reachable blocks
    for &b_idx in &reachable_blocks {
        if b_idx != 0 {
            doms.insert(b_idx, all_reachable_set.clone());
        }
    }

    // Iterative intersection
    let mut changed = true;
    while changed {
        changed = false;
        for &b_idx in &reachable_blocks {
            if b_idx == 0 {
                continue;
            }

            let preds = &blocks[b_idx].predecessors;
            let reachable_preds: Vec<usize> = preds
                .iter()
                .copied()
                .filter(|p| doms.contains_key(p))
                .collect();

            if reachable_preds.is_empty() {
                continue;
            }

            let mut new_dom = doms[&reachable_preds[0]].clone();
            for &p in &reachable_preds[1..] {
                new_dom = new_dom.intersection(&doms[&p]).copied().collect();
            }
            new_dom.insert(b_idx);

            if doms.get(&b_idx) != Some(&new_dom) {
                doms.insert(b_idx, new_dom);
                changed = true;
            }
        }
    }

    // Compute immediate dominator (strict dominator with largest dom set)
    for &b_idx in &reachable_blocks {
        if b_idx == 0 {
            continue;
        }

        if let Some(block_doms) = doms.get(&b_idx) {
            let strict_doms: Vec<usize> =
                block_doms.iter().copied().filter(|&d| d != b_idx).collect();

            // The immediate dominator idom(n) is the unique strict dominator d of n that does not dominate any other strict dominator of n
            let mut idom = None;
            for &candidate in &strict_doms {
                let candidate_doms = &doms[&candidate];
                let is_closest = strict_doms
                    .iter()
                    .all(|&other| other == candidate || !candidate_doms.contains(&other));
                if is_closest {
                    idom = Some(candidate);
                    break;
                }
            }

            blocks[b_idx].immediate_dominator = idom;
        }
    }
}
