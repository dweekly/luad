//! Central authority for Lua 5.1 physical instruction roles.

use crate::opcodes::{Opcode51, RawInstruction51};
use luad_core::model::{InstructionWord, Prototype};

/// Physical role of an instruction word in a Lua 5.1 prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lua51PhysicalRole {
    /// Standard executable instruction.
    Instruction,
    /// Upvalue binding descriptor following a CLOSURE instruction.
    ClosureBinding {
        owner_pc: usize,
        upvalue_index: usize,
    },
    /// Extra list-batch argument following a SETLIST instruction with C == 0.
    SetlistExtra { owner_pc: usize },
}

impl Lua51PhysicalRole {
    /// Name of the role for disasm, explain, and export serialization.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::ClosureBinding { .. } => "closure_binding",
            Self::SetlistExtra { .. } => "setlist_extra",
        }
    }

    /// Owner PC if this word is a companion word.
    pub fn companion_pc(&self) -> Option<usize> {
        match *self {
            Self::Instruction => None,
            Self::ClosureBinding { owner_pc, .. } => Some(owner_pc),
            Self::SetlistExtra { owner_pc } => Some(owner_pc),
        }
    }

    /// Whether this word is an executable instruction.
    pub fn is_executable(&self) -> bool {
        matches!(self, Self::Instruction)
    }
}

/// Truncated companion range defect discovered during physical role resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lua51RoleFault {
    /// CLOSURE lacks required follow-up upvalue binding descriptors.
    TruncatedClosure {
        owner_pc: usize,
        declared: usize,
        available: usize,
    },
    /// SETLIST with C == 0 lacks required follow-up list-batch extra word.
    TruncatedSetlist { owner_pc: usize },
}

/// Result of physical role discovery across a prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lua51RoleMap {
    /// Resolved physical role for every instruction index in the prototype.
    pub roles: Vec<Lua51PhysicalRole>,
    /// Truncated companion range defects discovered during scanning.
    pub faults: Vec<Lua51RoleFault>,
}

impl Lua51RoleMap {
    /// Get the physical role for the given PC.
    pub fn get(&self, pc: usize) -> Lua51PhysicalRole {
        self.roles
            .get(pc)
            .copied()
            .unwrap_or(Lua51PhysicalRole::Instruction)
    }

    /// Whether the word at the given PC is an executable instruction.
    pub fn is_executable(&self, pc: usize) -> bool {
        self.get(pc).is_executable()
    }

    /// Companion owner PC for the given PC if it is a companion word.
    pub fn companion_pc(&self, pc: usize) -> Option<usize> {
        self.get(pc).companion_pc()
    }
}

/// Discover physical roles for all instruction words in a Lua 5.1 prototype.
///
/// Performs a single ascending PC pass with first-unclaimed-owner precedence.
/// Claimed companion words are never reconsidered as owners.
pub fn discover_roles_lua51(proto: &Prototype) -> Lua51RoleMap {
    discover_roles_from_parts_lua51(&proto.instructions, &proto.protos)
}

/// Discover physical roles from the code vector and child prototype table.
///
/// This form is available while a prototype is being assembled by the parser.
pub(crate) fn discover_roles_from_parts_lua51(
    instructions: &[InstructionWord],
    child_protos: &[Prototype],
) -> Lua51RoleMap {
    let num_insts = instructions.len();
    let mut roles = vec![Lua51PhysicalRole::Instruction; num_insts];
    let mut faults = Vec::new();

    for pc in 0..num_insts {
        if roles[pc] != Lua51PhysicalRole::Instruction {
            continue;
        }

        let raw = RawInstruction51::decode(instructions[pc].raw_word);
        match raw.opcode {
            Some(Opcode51::Closure) => {
                let child_bx = raw.bx as usize;
                if let Some(child) = child_protos.get(child_bx) {
                    let nups = child.upvalues.len();
                    for (upvalue_index, offset) in (1..=nups).enumerate() {
                        let desc_pc = pc + offset;
                        if desc_pc < num_insts {
                            roles[desc_pc] = Lua51PhysicalRole::ClosureBinding {
                                owner_pc: pc,
                                upvalue_index,
                            };
                        }
                    }
                    if pc + nups >= num_insts {
                        faults.push(Lua51RoleFault::TruncatedClosure {
                            owner_pc: pc,
                            declared: nups,
                            available: num_insts.saturating_sub(pc + 1),
                        });
                    }
                }
            }
            Some(Opcode51::SetList) if raw.c == 0 => {
                let extra_pc = pc + 1;
                if extra_pc < num_insts {
                    roles[extra_pc] = Lua51PhysicalRole::SetlistExtra { owner_pc: pc };
                } else {
                    faults.push(Lua51RoleFault::TruncatedSetlist { owner_pc: pc });
                }
            }
            _ => {}
        }
    }

    Lua51RoleMap { roles, faults }
}
