//! Shared postorder capture-mutation analysis and deterministic budget tracking.

use std::collections::{BTreeMap, BTreeSet};

use luad_core::ir::EffectTarget;
use luad_core::model::{Chunk, Prototype};
use luad_core::ProtoPath;
use luad_dialect_lua51::{discover_roles_lua51, Lua51PhysicalRole, Opcode51, RawInstruction51};

type CanonicalCell = (ProtoPath, SharedCell);

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
    /// Map from a prototype upvalue slot to every canonical shared cell that can feed it.
    pub upvalue_to_cells: BTreeMap<(ProtoPath, u8), BTreeSet<CanonicalCell>>,
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
        if let Some(cells) = self.upvalue_to_cells.get(&(child_path.clone(), slot)) {
            cells.iter().any(|cell| self.mutated_cells.contains(cell))
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
        if let Some(cells) = self.upvalue_to_cells.get(&(owner_path.clone(), slot)) {
            cells.iter().any(|cell| self.mutated_cells.contains(cell))
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
            summary.upvalue_to_cells.insert(
                (path.clone(), slot as u8),
                [(path.clone(), SharedCell::Upvalue(slot as u8))]
                    .into_iter()
                    .collect(),
            );
        }
    }

    let role_map = discover_roles_lua51(proto);
    for (pc, instruction) in proto.instructions.iter().enumerate() {
        if !role_map.is_executable(pc) {
            continue;
        }
        let raw = RawInstruction51::decode(instruction.raw_word);
        if raw.opcode != Some(Opcode51::Closure) {
            continue;
        }
        let child_idx = raw.bx as usize;
        let Some(child) = proto.protos.get(child_idx) else {
            continue;
        };
        let child_path = path.child(child_idx);
        for slot in 0..child.upvalues.len() {
            if *remaining_budget == 0 {
                summary.exhausted = true;
                return;
            }
            *remaining_budget -= 1;

            let desc_pc = pc + 1 + slot;
            if !matches!(
                role_map.get(desc_pc),
                Lua51PhysicalRole::ClosureBinding {
                    owner_pc,
                    upvalue_index,
                } if owner_pc == pc && upvalue_index == slot
            ) {
                continue;
            }
            let Some(descriptor) = proto.instructions.get(desc_pc) else {
                continue;
            };
            let desc_raw = RawInstruction51::decode(descriptor.raw_word);
            let cells: BTreeSet<CanonicalCell> = match desc_raw.opcode {
                Some(Opcode51::Move) => [(path.clone(), SharedCell::Local(desc_raw.b as u8))]
                    .into_iter()
                    .collect(),
                Some(Opcode51::GetUpval) => summary
                    .upvalue_to_cells
                    .get(&(path.clone(), desc_raw.b as u8))
                    .cloned()
                    .unwrap_or_else(|| {
                        [(path.clone(), SharedCell::Upvalue(desc_raw.b as u8))]
                            .into_iter()
                            .collect()
                    }),
                _ => BTreeSet::new(),
            };
            summary
                .upvalue_to_cells
                .entry((child_path.clone(), slot as u8))
                .or_default()
                .extend(cells);
        }
    }

    for (child_idx, child) in proto.protos.iter().enumerate() {
        let child_path = path.child(child_idx);
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
                let canonical_cells = summary
                    .upvalue_to_cells
                    .get(&(path.clone(), *index))
                    .cloned()
                    .unwrap_or_else(|| {
                        [(path.clone(), SharedCell::Upvalue(*index))]
                            .into_iter()
                            .collect()
                    });
                summary.mutated_cells.extend(canonical_cells);
            }
        }
    }
}
