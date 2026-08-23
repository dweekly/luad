//! Structural and semantic comparison engine for two Lua bytecode chunks.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use luad_core::id::ProtoPath;
use luad_core::model::{Chunk, Prototype};

/// Difference in an instruction slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InstructionDiff {
    /// Program counter.
    pub pc: usize,
    /// Representation in first (old) chunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    /// Representation in second (new) chunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
}

/// Differences identified within a matching prototype path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProtoDiff {
    /// Prototype path.
    pub path: ProtoPath,
    /// Header/parameter changes.
    pub header_diffs: Vec<String>,
    /// Constant changes.
    pub constant_diffs: Vec<String>,
    /// Upvalue changes.
    pub upvalue_diffs: Vec<String>,
    /// Instruction changes.
    pub instruction_diffs: Vec<InstructionDiff>,
}

/// Complete structural and semantic chunk difference report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChunkDiff {
    /// Old chunk SHA-256.
    pub old_sha256: String,
    /// New chunk SHA-256.
    pub new_sha256: String,
    /// Differences in chunk header fields.
    pub header_diffs: Vec<String>,
    /// Differences across prototypes.
    pub proto_diffs: Vec<ProtoDiff>,
    /// Whether both chunks are structurally and semantically equivalent.
    pub is_identical: bool,
}

/// Compare two chunks structurally and semantically.
#[must_use]
pub fn diff_chunks(
    old_chunk: &Chunk,
    new_chunk: &Chunk,
    semantic: bool,
    ignore_debug: bool,
) -> ChunkDiff {
    let mut header_diffs = Vec::new();

    if old_chunk.dialect != new_chunk.dialect {
        header_diffs.push(format!(
            "Dialect changed: {} -> {}",
            old_chunk.dialect, new_chunk.dialect
        ));
    }
    if old_chunk.header.version != new_chunk.header.version {
        header_diffs.push(format!(
            "Version byte changed: 0x{:02x} -> 0x{:02x}",
            old_chunk.header.version, new_chunk.header.version
        ));
    }

    let mut proto_diffs = Vec::new();
    diff_prototype(
        &old_chunk.dialect,
        &old_chunk.main_proto,
        &new_chunk.dialect,
        &new_chunk.main_proto,
        semantic,
        ignore_debug,
        &mut proto_diffs,
    );

    let is_identical = header_diffs.is_empty()
        && proto_diffs.iter().all(|p| {
            p.header_diffs.is_empty()
                && p.constant_diffs.is_empty()
                && p.upvalue_diffs.is_empty()
                && p.instruction_diffs.is_empty()
        });

    ChunkDiff {
        old_sha256: old_chunk.sha256.clone(),
        new_sha256: new_chunk.sha256.clone(),
        header_diffs,
        proto_diffs,
        is_identical,
    }
}

fn diff_prototype(
    old_dialect: &str,
    old_p: &Prototype,
    new_dialect: &str,
    new_p: &Prototype,
    semantic: bool,
    ignore_debug: bool,
    diffs: &mut Vec<ProtoDiff>,
) {
    let mut header_diffs = Vec::new();
    let mut constant_diffs = Vec::new();
    let mut upvalue_diffs = Vec::new();
    let mut instruction_diffs = Vec::new();

    if !ignore_debug {
        let old_src = old_p.source_name.as_ref().map(|s| s.display.as_str());
        let new_src = new_p.source_name.as_ref().map(|s| s.display.as_str());
        if old_src != new_src {
            header_diffs.push(format!(
                "Source name changed: {:?} -> {:?}",
                old_src, new_src
            ));
        }
        if old_p.line_info.len() != new_p.line_info.len() {
            header_diffs.push(format!(
                "Debug line info count changed: {} -> {}",
                old_p.line_info.len(),
                new_p.line_info.len()
            ));
        }
        if old_p.loc_vars.len() != new_p.loc_vars.len() {
            header_diffs.push(format!(
                "Local variable count changed: {} -> {}",
                old_p.loc_vars.len(),
                new_p.loc_vars.len()
            ));
        }
    }

    if old_p.numparams != new_p.numparams {
        header_diffs.push(format!(
            "Parameter count changed: {} -> {}",
            old_p.numparams, new_p.numparams
        ));
    }
    if old_p.maxstacksize != new_p.maxstacksize {
        header_diffs.push(format!(
            "Max stack size changed: {} -> {}",
            old_p.maxstacksize, new_p.maxstacksize
        ));
    }

    // Compare constants
    if old_p.constants.len() != new_p.constants.len() {
        constant_diffs.push(format!(
            "Constant count changed: {} -> {}",
            old_p.constants.len(),
            new_p.constants.len()
        ));
    }

    // Compare upvalues
    if old_p.upvalues.len() != new_p.upvalues.len() {
        upvalue_diffs.push(format!(
            "Upvalue count changed: {} -> {}",
            old_p.upvalues.len(),
            new_p.upvalues.len()
        ));
    }

    // Compare instructions
    if old_dialect != new_dialect && !semantic {
        header_diffs.push(format!(
            "Cross-dialect physical instruction diff ({old_dialect} vs {new_dialect}) is incompatible/uncertain; use --semantic for IR effect comparison"
        ));
    } else {
        let max_insts = old_p.instructions.len().max(new_p.instructions.len());
        let old_lifted = if semantic {
            Some(crate::lift_proto_for_dialect(old_dialect, old_p))
        } else {
            None
        };
        let new_lifted = if semantic {
            Some(crate::lift_proto_for_dialect(new_dialect, new_p))
        } else {
            None
        };

        for pc in 0..max_insts {
            let old_desc = if let Some(lifted) = &old_lifted {
                lifted
                    .get(pc)
                    .map(|i| format!("{:<10} {}", i.mnemonic, i.explanation))
            } else {
                old_p
                    .instructions
                    .get(pc)
                    .map(|i| format!("0x{:08x}", i.raw_word))
            };

            let new_desc = if let Some(lifted) = &new_lifted {
                lifted
                    .get(pc)
                    .map(|i| format!("{:<10} {}", i.mnemonic, i.explanation))
            } else {
                new_p
                    .instructions
                    .get(pc)
                    .map(|i| format!("0x{:08x}", i.raw_word))
            };

            if old_desc != new_desc {
                instruction_diffs.push(InstructionDiff {
                    pc,
                    old: old_desc,
                    new: new_desc,
                });
            }
        }
    }

    let has_any_diff = !header_diffs.is_empty()
        || !constant_diffs.is_empty()
        || !upvalue_diffs.is_empty()
        || !instruction_diffs.is_empty();

    if has_any_diff {
        diffs.push(ProtoDiff {
            path: old_p.path.clone(),
            header_diffs,
            constant_diffs,
            upvalue_diffs,
            instruction_diffs,
        });
    }

    // Child prototypes
    let min_protos = old_p.protos.len().min(new_p.protos.len());
    for i in 0..min_protos {
        diff_prototype(
            old_dialect,
            &old_p.protos[i],
            new_dialect,
            &new_p.protos[i],
            semantic,
            ignore_debug,
            diffs,
        );
    }
}
