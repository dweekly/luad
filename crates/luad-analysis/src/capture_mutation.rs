//! Shared postorder capture-mutation analysis and deterministic budget tracking.

use std::collections::{BTreeMap, BTreeSet};

use luad_core::ir::EffectTarget;
use luad_core::model::{Chunk, Prototype};
use luad_core::ProtoPath;

/// Identification of a shared variable cell in an owning prototype.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SharedCell {
    /// Local register in the owning prototype.
    Local(u8),
    /// Upvalue slot in the owning prototype.
    Upvalue(u8),
}

/// Whole-tree capture mutation summary for a Lua 5.1 chunk.
#[derive(Debug, Clone, Default)]
pub struct CaptureMutationSummary {
    /// Set of shared cells that are mutated by any closure or instruction in the prototype tree.
    pub mutated_cells: BTreeSet<(ProtoPath, SharedCell)>,
    /// Map from (prototype path, upvalue slot) to its canonical root shared cell (owner path, cell).
    pub upvalue_to_cell: BTreeMap<(ProtoPath, u8), (ProtoPath, SharedCell)>,
    /// Whether analysis budget was exhausted during summary construction.
    pub exhausted: bool,
}

impl CaptureMutationSummary {
    /// Build a bounded capture-mutation summary for the entire prototype tree of a chunk.
    pub fn build(chunk: &Chunk, budget: usize) -> Self {
        if !chunk.dialect.starts_with("lua5.1") {
            return Self::default();
        }

        let mut summary = Self::default();
        let mut remaining_budget = budget;

        // 1. Map upvalues to their canonical root shared cells top-down.
        map_prototype_upvalues(
            &chunk.main_proto,
            &ProtoPath::root(),
            &mut summary,
            &mut remaining_budget,
        );
        if summary.exhausted {
            return summary;
        }

        // 2. Postorder traversal of prototype tree to collect directly mutated upvalues and propagate to cells.
        collect_mutations_postorder(
            &chunk.dialect,
            &chunk.main_proto,
            &ProtoPath::root(),
            &mut summary,
            &mut remaining_budget,
        );

        summary
    }

    /// Check whether a child prototype's upvalue slot is mutable anywhere in the chunk.
    pub fn is_child_slot_mutated(&self, child_path: &ProtoPath, slot: u8) -> bool {
        if self.exhausted {
            return true;
        }
        if let Some(cell) = self.upvalue_to_cell.get(&(child_path.clone(), slot)) {
            self.mutated_cells.contains(cell)
        } else {
            false
        }
    }

    /// Check whether a prototype's local register is captured and mutated by any closure.
    pub fn is_local_register_mutated(&self, owner_path: &ProtoPath, register: u8) -> bool {
        if self.exhausted {
            return true;
        }
        self.mutated_cells
            .contains(&(owner_path.clone(), SharedCell::Local(register)))
    }

    /// Check whether a prototype's upvalue slot is mutated by any closure.
    pub fn is_upvalue_slot_mutated(&self, owner_path: &ProtoPath, slot: u8) -> bool {
        if self.exhausted {
            return true;
        }
        if let Some(cell) = self.upvalue_to_cell.get(&(owner_path.clone(), slot)) {
            self.mutated_cells.contains(cell)
        } else {
            self.mutated_cells
                .contains(&(owner_path.clone(), SharedCell::Upvalue(slot)))
        }
    }
}

fn map_prototype_upvalues(
    proto: &Prototype,
    path: &ProtoPath,
    summary: &mut CaptureMutationSummary,
    remaining_budget: &mut usize,
) {
    if path.depth() == 0 {
        for slot in 0..proto.upvalues.len() {
            summary.upvalue_to_cell.insert(
                (path.clone(), slot as u8),
                (path.clone(), SharedCell::Upvalue(slot as u8)),
            );
        }
    }

    for (child_idx, child) in proto.protos.iter().enumerate() {
        let child_path = path.child(child_idx);
        let nups = child.upvalues.len();
        for slot in 0..nups {
            if *remaining_budget == 0 {
                summary.exhausted = true;
                return;
            }
            *remaining_budget -= 1;

            let upval = &child.upvalues[slot];
            if upval.instack == 1 {
                summary.upvalue_to_cell.insert(
                    (child_path.clone(), slot as u8),
                    (path.clone(), SharedCell::Local(upval.idx)),
                );
            } else {
                let parent_upval_slot = upval.idx;
                let canonical_cell = summary
                    .upvalue_to_cell
                    .get(&(path.clone(), parent_upval_slot))
                    .cloned()
                    .unwrap_or_else(|| (path.clone(), SharedCell::Upvalue(parent_upval_slot)));
                summary
                    .upvalue_to_cell
                    .insert((child_path.clone(), slot as u8), canonical_cell);
            }
        }

        map_prototype_upvalues(child, &child_path, summary, remaining_budget);
        if summary.exhausted {
            return;
        }
    }
}

fn collect_mutations_postorder(
    dialect: &str,
    proto: &Prototype,
    path: &ProtoPath,
    summary: &mut CaptureMutationSummary,
    remaining_budget: &mut usize,
) {
    for (child_idx, child) in proto.protos.iter().enumerate() {
        let child_path = path.child(child_idx);
        collect_mutations_postorder(dialect, child, &child_path, summary, remaining_budget);
        if summary.exhausted {
            return;
        }
    }

    if *remaining_budget == 0 {
        summary.exhausted = true;
        return;
    }
    *remaining_budget -= 1;

    let instructions = crate::lift_proto_for_dialect(dialect, proto);
    for inst in &instructions {
        for write in &inst.writes {
            if let EffectTarget::Upvalue { index, .. } = write {
                let canonical_cell = summary
                    .upvalue_to_cell
                    .get(&(path.clone(), *index))
                    .cloned()
                    .unwrap_or_else(|| (path.clone(), SharedCell::Upvalue(*index)));
                summary.mutated_cells.insert(canonical_cell);
            }
        }
    }
}
