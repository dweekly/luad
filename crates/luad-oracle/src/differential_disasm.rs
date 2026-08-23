//! Unified three-way differential disassembly comparator for Lua 5.4.8.
//!
//! Compares official `luac -l -l` oracle listings, independent reference decoder facts,
//! and production `DisassembledPrototype` / live CLI JSON records across complete recursive prototype hierarchies.

#![forbid(unsafe_code)]

use luad_core::disasm::{DisassembledPrototype, OperandKind, ResolvedFact};
use luad_core::id::StableId;
use luad_core::model::Prototype;

use crate::independent_lua54_oracle::{IndependentInstruction54, IndependentOpcode54};
use crate::listing_parser::{DumpLineInfo, LuacProtoDump};

/// Typed error returned when three-way disassembly comparison fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisasmComparisonError {
    InstructionCountMismatch {
        proto_id: String,
        luac_count: usize,
        independent_count: usize,
        production_count: usize,
    },
    MnemonicMismatch {
        pc: usize,
        luac_mnemonic: String,
        independent_mnemonic: String,
        production_mnemonic: String,
    },
    PhysicalFieldMismatch {
        pc: usize,
        field_name: String,
        independent_val: i64,
        production_val: i64,
    },
    OperandDisplayMismatch {
        pc: usize,
        expected_raw: String,
        actual_display: String,
    },
    JumpTargetMismatch {
        pc: usize,
        expected_target: usize,
        actual_target: usize,
    },
    MissingJumpTarget {
        pc: usize,
        expected_target: usize,
    },
    LineMismatch {
        pc: usize,
        expected_line: usize,
        actual_line: usize,
    },
    MissingSourceLine {
        pc: usize,
        expected_line: usize,
    },
    UnexpectedSourceLine {
        pc: usize,
        actual_line: usize,
    },
    RoleMismatch {
        pc: usize,
        expected: String,
        actual: String,
    },
    CompanionMismatch {
        pc: usize,
        detail: String,
    },
    MissingResolvedFact {
        pc: usize,
        operand_name: String,
        fact_type: String,
    },
    ConstantResolutionMismatch {
        pc: usize,
        detail: String,
    },
    PrototypeResolutionMismatch {
        pc: usize,
        detail: String,
    },
    UpvalueResolutionMismatch {
        pc: usize,
        detail: String,
    },
    MissingPrototype {
        proto_id: String,
        detail: String,
    },
    JsonMismatch {
        pc: usize,
        detail: String,
    },
}

/// Recursively verify differential agreement for a complete prototype tree against official dump and CLI JSON.
pub fn compare_chunk_tree_three_way(
    root_proto: &Prototype,
    luac_dump: &LuacProtoDumpList,
    cli_json: &DisassembledPrototype,
) -> Result<(), DisasmComparisonError> {
    let mut func_idx = 0;
    compare_proto_node_recursive(root_proto, luac_dump.functions, &mut func_idx, cli_json)?;

    if func_idx != luac_dump.functions.len() {
        return Err(DisasmComparisonError::MissingPrototype {
            proto_id: root_proto.id.to_string(),
            detail: format!(
                "Official dump contains {} prototypes but chunk hierarchy only traversed {}",
                luac_dump.functions.len(),
                func_idx
            ),
        });
    }

    Ok(())
}

/// Wrapper for the vector of dumped functions from `LuacDump`.
pub struct LuacProtoDumpList<'a> {
    pub functions: &'a [LuacProtoDump],
}

fn compare_proto_node_recursive(
    proto: &Prototype,
    luac_funcs: &[LuacProtoDump],
    func_idx: &mut usize,
    cli_json_proto: &DisassembledPrototype,
) -> Result<(), DisasmComparisonError> {
    if *func_idx >= luac_funcs.len() {
        return Err(DisasmComparisonError::MissingPrototype {
            proto_id: proto.id.to_string(),
            detail: format!(
                "Missing counterpart in official dump at index {func_idx} for prototype {}",
                proto.id
            ),
        });
    }

    let luac_proto = &luac_funcs[*func_idx];
    *func_idx += 1;

    let indep_insts: Vec<IndependentInstruction54> = proto
        .instructions
        .iter()
        .map(|i| IndependentInstruction54::decode(i.raw_word))
        .collect();

    let prod_proto = luad_dialect_lua54::disassemble_proto_lua54(proto);

    compare_proto_three_way(
        proto,
        luac_proto,
        &indep_insts,
        &prod_proto,
        Some(cli_json_proto),
    )?;

    if proto.protos.len() != cli_json_proto.child_protos.len() {
        return Err(DisasmComparisonError::MissingPrototype {
            proto_id: proto.id.to_string(),
            detail: format!(
                "Prototype {} has {} child prototypes in chunk, but CLI JSON reports {}",
                proto.id,
                proto.protos.len(),
                cli_json_proto.child_protos.len()
            ),
        });
    }

    for (i, child_proto) in proto.protos.iter().enumerate() {
        let child_cli_json = &cli_json_proto.child_protos[i];
        compare_proto_node_recursive(child_proto, luac_funcs, func_idx, child_cli_json)?;
    }

    Ok(())
}

/// Compare disassembly three-way across official luac dump, independent decoder, and production record for one prototype.
#[allow(clippy::needless_range_loop)]
pub fn compare_proto_three_way(
    owning_proto: &Prototype,
    luac_proto: &LuacProtoDump,
    indep_insts: &[IndependentInstruction54],
    prod_proto: &DisassembledPrototype,
    cli_json_proto: Option<&DisassembledPrototype>,
) -> Result<(), DisasmComparisonError> {
    let luac_count = luac_proto.instructions.len();
    let indep_count = indep_insts.len();
    let prod_count = prod_proto.instructions.len();

    if luac_count != indep_count || luac_count != prod_count {
        return Err(DisasmComparisonError::InstructionCountMismatch {
            proto_id: prod_proto.id.to_string(),
            luac_count,
            independent_count: indep_count,
            production_count: prod_count,
        });
    }

    for pc in 0..luac_count {
        let luac_inst = &luac_proto.instructions[pc];
        let indep_inst = &indep_insts[pc];
        let prod_inst = &prod_proto.instructions[pc];

        let indep_mnemonic = indep_inst
            .opcode
            .map(|op| op.name().to_string())
            .unwrap_or_else(|| format!("UNKNOWN_0x{:02x}", indep_inst.raw_word & 0x7F));

        // 1. Mnemonic agreement
        if luac_inst.mnemonic != indep_mnemonic || luac_inst.mnemonic != prod_inst.mnemonic {
            return Err(DisasmComparisonError::MnemonicMismatch {
                pc,
                luac_mnemonic: luac_inst.mnemonic.clone(),
                independent_mnemonic: indep_mnemonic,
                production_mnemonic: prod_inst.mnemonic.clone(),
            });
        }

        // 2. Physical field agreement with independent decoder
        let enc = &prod_inst.encoded_operands;
        if indep_inst.a != enc.a {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "A".to_string(),
                independent_val: indep_inst.a as i64,
                production_val: enc.a as i64,
            });
        }
        if indep_inst.b != enc.b {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "B".to_string(),
                independent_val: indep_inst.b as i64,
                production_val: enc.b as i64,
            });
        }
        if indep_inst.c != enc.c {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "C".to_string(),
                independent_val: indep_inst.c as i64,
                production_val: enc.c as i64,
            });
        }
        if indep_inst.k != enc.k {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "k".to_string(),
                independent_val: indep_inst.k as i64,
                production_val: enc.k as i64,
            });
        }
        if indep_inst.sb != enc.sb {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "sB".to_string(),
                independent_val: indep_inst.sb as i64,
                production_val: enc.sb as i64,
            });
        }
        if indep_inst.sc != enc.sc {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "sC".to_string(),
                independent_val: indep_inst.sc as i64,
                production_val: enc.sc as i64,
            });
        }
        if indep_inst.bx != enc.bx {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "Bx".to_string(),
                independent_val: indep_inst.bx as i64,
                production_val: enc.bx as i64,
            });
        }
        if indep_inst.sbx != enc.sbx {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "sBx".to_string(),
                independent_val: indep_inst.sbx as i64,
                production_val: enc.sbx as i64,
            });
        }
        if indep_inst.ax != enc.ax {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "Ax".to_string(),
                independent_val: indep_inst.ax as i64,
                production_val: enc.ax as i64,
            });
        }
        if indep_inst.sj != enc.sj {
            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                pc,
                field_name: "sJ".to_string(),
                independent_val: indep_inst.sj as i64,
                production_val: enc.sj as i64,
            });
        }

        // 3. Typed signed operand value check
        if let Some(op) = indep_inst.opcode {
            match op {
                IndependentOpcode54::Addi
                | IndependentOpcode54::Shri
                | IndependentOpcode54::Shli => {
                    let sc_op = prod_inst.operands.iter().find(|o| o.name == "sC");
                    match sc_op.map(|o| &o.kind) {
                        Some(OperandKind::ImmediateSigned { value })
                            if *value == indep_inst.sc as i64 => {}
                        _ => {
                            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                                pc,
                                field_name: "sC_operand".to_string(),
                                independent_val: indep_inst.sc as i64,
                                production_val: sc_op
                                    .and_then(|o| match o.kind {
                                        OperandKind::ImmediateSigned { value } => Some(value),
                                        _ => None,
                                    })
                                    .unwrap_or(-999999),
                            });
                        }
                    }
                }
                IndependentOpcode54::Loadi | IndependentOpcode54::Loadf => {
                    let sbx_op = prod_inst.operands.iter().find(|o| o.name == "sBx");
                    match sbx_op.map(|o| &o.kind) {
                        Some(OperandKind::ImmediateSigned { value })
                            if *value == indep_inst.sbx as i64 => {}
                        _ => {
                            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                                pc,
                                field_name: "sBx_operand".to_string(),
                                independent_val: indep_inst.sbx as i64,
                                production_val: sbx_op
                                    .and_then(|o| match o.kind {
                                        OperandKind::ImmediateSigned { value } => Some(value),
                                        _ => None,
                                    })
                                    .unwrap_or(-999999),
                            });
                        }
                    }
                }
                IndependentOpcode54::Eqi
                | IndependentOpcode54::Lti
                | IndependentOpcode54::Lei
                | IndependentOpcode54::Gti
                | IndependentOpcode54::Gei
                | IndependentOpcode54::Mmbini => {
                    let sb_op = prod_inst.operands.iter().find(|o| o.name == "sB");
                    match sb_op.map(|o| &o.kind) {
                        Some(OperandKind::ImmediateSigned { value })
                            if *value == indep_inst.sb as i64 => {}
                        _ => {
                            return Err(DisasmComparisonError::PhysicalFieldMismatch {
                                pc,
                                field_name: "sB_operand".to_string(),
                                independent_val: indep_inst.sb as i64,
                                production_val: sb_op
                                    .and_then(|o| match o.kind {
                                        OperandKind::ImmediateSigned { value } => Some(value),
                                        _ => None,
                                    })
                                    .unwrap_or(-999999),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        // 4. Branch and jump targets
        if let Some(op) = indep_inst.opcode {
            let expected_target = match op {
                IndependentOpcode54::Jmp => Some((pc as i32 + 1 + indep_inst.sj) as usize),
                IndependentOpcode54::Forloop | IndependentOpcode54::Tforloop => {
                    Some((pc as i32 + 1 - indep_inst.bx as i32) as usize)
                }
                IndependentOpcode54::Forprep | IndependentOpcode54::Tforprep => {
                    Some((pc as i32 + 1 + indep_inst.bx as i32 + 1) as usize)
                }
                _ => None,
            };

            if let Some(exp_target) = expected_target {
                match prod_inst.jump_target {
                    Some(act_target) if act_target == exp_target => (),
                    Some(act_target) => {
                        return Err(DisasmComparisonError::JumpTargetMismatch {
                            pc,
                            expected_target: exp_target,
                            actual_target: act_target,
                        });
                    }
                    None => {
                        return Err(DisasmComparisonError::MissingJumpTarget {
                            pc,
                            expected_target: exp_target,
                        });
                    }
                }
            }
        }

        // 5. Source lines
        match luac_inst.line_info {
            DumpLineInfo::Known(l) => match prod_inst.line {
                Some(prod_line) if prod_line == l => (),
                Some(prod_line) => {
                    return Err(DisasmComparisonError::LineMismatch {
                        pc,
                        expected_line: l,
                        actual_line: prod_line,
                    });
                }
                None => {
                    return Err(DisasmComparisonError::MissingSourceLine {
                        pc,
                        expected_line: l,
                    });
                }
            },
            DumpLineInfo::Stripped => {
                if let Some(prod_line) = prod_inst.line {
                    return Err(DisasmComparisonError::UnexpectedSourceLine {
                        pc,
                        actual_line: prod_line,
                    });
                }
            }
        }

        // 6. Formatted operand display agreement with luac -l -l
        let prod_ops_str = prod_inst
            .operands
            .iter()
            .map(|o| o.display.as_str())
            .collect::<Vec<_>>()
            .join(" ");

        if luac_inst.operands_raw != prod_ops_str {
            return Err(DisasmComparisonError::OperandDisplayMismatch {
                pc,
                expected_raw: luac_inst.operands_raw.clone(),
                actual_display: prod_ops_str,
            });
        }

        // 7. Role and Companion Verification
        if let Some(op) = indep_inst.opcode {
            match op {
                IndependentOpcode54::Mmbin
                | IndependentOpcode54::Mmbini
                | IndependentOpcode54::Mmbink => {
                    if prod_inst.role != "companion" {
                        return Err(DisasmComparisonError::RoleMismatch {
                            pc,
                            expected: "companion".to_string(),
                            actual: prod_inst.role.clone(),
                        });
                    }
                    if pc > 0 && prod_inst.companion_pc != Some(pc - 1) {
                        return Err(DisasmComparisonError::CompanionMismatch {
                            pc,
                            detail: format!(
                                "Metamethod companion at PC {pc} must link back to PC {}",
                                pc - 1
                            ),
                        });
                    }
                }
                IndependentOpcode54::Extraarg => {
                    if prod_inst.role != "extra_argument" {
                        return Err(DisasmComparisonError::RoleMismatch {
                            pc,
                            expected: "extra_argument".to_string(),
                            actual: prod_inst.role.clone(),
                        });
                    }
                    if pc > 0 && prod_inst.companion_pc != Some(pc - 1) {
                        return Err(DisasmComparisonError::CompanionMismatch {
                            pc,
                            detail: format!(
                                "EXTRAARG at PC {pc} must link back to companion instruction at PC {}",
                                pc - 1
                            ),
                        });
                    }
                }
                _ => {
                    if prod_inst.role != "instruction" {
                        return Err(DisasmComparisonError::RoleMismatch {
                            pc,
                            expected: "instruction".to_string(),
                            actual: prod_inst.role.clone(),
                        });
                    }
                }
            }
        }

        // 8. Mandatory Resolution Verification for Applicable Operands
        if let Some(op) = indep_inst.opcode {
            match op {
                IndependentOpcode54::Loadk => {
                    let bx = indep_inst.bx as usize;
                    let exp_id = match &owning_proto.id {
                        StableId::Proto(p) => StableId::Constant {
                            proto: p.clone(),
                            index: bx,
                        },
                        other => other.clone(),
                    };
                    let exp_val = owning_proto.constants.get(bx).map(|c| &c.value);
                    let op_bx = prod_inst.operands.iter().find(|o| o.name == "Bx");
                    match op_bx.and_then(|o| o.resolved.as_ref()) {
                        Some(ResolvedFact::Constant {
                            index,
                            id,
                            value,
                            formatted_preview,
                        }) if (*index != bx
                            || *id != exp_id
                            || Some(value) != exp_val
                            || formatted_preview.is_empty()) =>
                        {
                            return Err(DisasmComparisonError::ConstantResolutionMismatch {
                                pc,
                                detail: format!("LOADK Bx resolution mismatch: index={index}, id={id}, preview={formatted_preview}"),
                            });
                        }
                        None => {
                            return Err(DisasmComparisonError::MissingResolvedFact {
                                pc,
                                operand_name: "Bx".to_string(),
                                fact_type: "Constant".to_string(),
                            });
                        }
                        _ => {}
                    }
                }
                IndependentOpcode54::Gettabup => {
                    // Upvalue B
                    let b = indep_inst.b as usize;
                    let op_b = prod_inst.operands.iter().find(|o| o.name == "B");
                    match op_b.and_then(|o| o.resolved.as_ref()) {
                        Some(ResolvedFact::Upvalue { index, .. }) if *index as usize == b => {}
                        None => {
                            return Err(DisasmComparisonError::MissingResolvedFact {
                                pc,
                                operand_name: "B".to_string(),
                                fact_type: "Upvalue".to_string(),
                            });
                        }
                        _ => {}
                    }
                    // Constant C
                    let c = indep_inst.c as usize;
                    let exp_id = match &owning_proto.id {
                        StableId::Proto(p) => StableId::Constant {
                            proto: p.clone(),
                            index: c,
                        },
                        other => other.clone(),
                    };
                    let exp_val = owning_proto
                        .constants
                        .get(c)
                        .map(|const_item| &const_item.value);
                    let op_c = prod_inst.operands.iter().find(|o| o.name == "C");
                    match op_c.and_then(|o| o.resolved.as_ref()) {
                        Some(ResolvedFact::Constant {
                            index,
                            id,
                            value,
                            formatted_preview,
                        }) if (*index != c
                            || *id != exp_id
                            || Some(value) != exp_val
                            || formatted_preview.is_empty()) =>
                        {
                            return Err(DisasmComparisonError::ConstantResolutionMismatch {
                                pc,
                                detail: format!("GETTABUP C resolution mismatch: index={index}, id={id}, preview={formatted_preview}"),
                            });
                        }
                        None => {
                            return Err(DisasmComparisonError::MissingResolvedFact {
                                pc,
                                operand_name: "C".to_string(),
                                fact_type: "Constant".to_string(),
                            });
                        }
                        _ => {}
                    }
                }
                IndependentOpcode54::Closure => {
                    let bx = indep_inst.bx as usize;
                    let exp_child = owning_proto.protos.get(bx);
                    let op_bx = prod_inst.operands.iter().find(|o| o.name == "Bx");
                    match op_bx.and_then(|o| o.resolved.as_ref()) {
                        Some(ResolvedFact::Prototype { index, id })
                            if (*index != bx || exp_child.map(|c| &c.id) != Some(id)) =>
                        {
                            return Err(DisasmComparisonError::PrototypeResolutionMismatch {
                                pc,
                                detail: format!(
                                    "CLOSURE Bx resolution mismatch: index={index}, id={id}"
                                ),
                            });
                        }
                        None => {
                            return Err(DisasmComparisonError::MissingResolvedFact {
                                pc,
                                operand_name: "Bx".to_string(),
                                fact_type: "Prototype".to_string(),
                            });
                        }
                        _ => {}
                    }
                }

                _ => {}
            }
        }

        // 9. CLI JSON agreement if provided
        if let Some(json_proto) = cli_json_proto {
            let json_inst = &json_proto.instructions[pc];
            if json_inst != prod_inst {
                return Err(DisasmComparisonError::JsonMismatch {
                    pc,
                    detail: format!(
                        "JSON instruction at PC {pc} did not match production instruction: JSON={json_inst:?}, PROD={prod_inst:?}"
                    ),
                });
            }
        }
    }

    Ok(())
}
