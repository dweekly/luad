//! Versioned subtree-content identities for fully decoded Lua 5.1 prototypes.

use luad_core::disasm::{
    DisassembledInstruction, DisassembledPrototype, OperandKind, ResolvedFact,
};
use luad_core::model::{Chunk, ConstantValue, Prototype};
use luad_core::StableId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOTYPE_IDENTITY_SCHEME_V1: &str = "luad-prototype-v1";
const DOMAIN_V1: &[u8] = b"luad-prototype-v1\0";

pub const PROTOTYPE_IDENTITY_SCHEME_V2: &str = "luad-prototype-v2";
const DOMAIN_V2: &[u8] = b"luad-prototype-v2\0";

const TAG_RECORD_PROTOTYPE: u8 = 0x01;
const TAG_RECORD_INSTRUCTION: u8 = 0x02;
const TAG_RECORD_OPERAND: u8 = 0x03;
const TAG_RECORD_CHILD_DIGEST: u8 = 0x04;

const TAG_CONST_NIL: u8 = 0x10;
const TAG_CONST_BOOL: u8 = 0x11;
const TAG_CONST_INT: u8 = 0x12;
const TAG_CONST_FLOAT: u8 = 0x13;
const TAG_CONST_SHORT_STRING: u8 = 0x14;
const TAG_CONST_LONG_STRING: u8 = 0x15;

const TAG_OPERAND_REGISTER: u8 = 0x20;
const TAG_OPERAND_IMMEDIATE_UNSIGNED: u8 = 0x21;
const TAG_OPERAND_IMMEDIATE_SIGNED: u8 = 0x22;
const TAG_OPERAND_FLAG: u8 = 0x23;
const TAG_OPERAND_RAW: u8 = 0x24;

const TAG_RESOLUTION_NONE: u8 = 0x30;
const TAG_RESOLUTION_CONSTANT: u8 = 0x31;
const TAG_RESOLUTION_UPVALUE: u8 = 0x32;
const TAG_RESOLUTION_LOCAL: u8 = 0x33;
const TAG_RESOLUTION_PROTOTYPE: u8 = 0x34;
const TAG_RESOLUTION_JUMP_TARGET: u8 = 0x35;
const TAG_RESOLUTION_METAMETHOD: u8 = 0x36;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PrototypeIdentityFact {
    pub proto_id: StableId,
    pub scheme: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChunkPrototypeIdentityAnalysis {
    pub prototypes: Vec<PrototypeIdentityFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrototypeIdentityError {
    #[error("prototype identity is defined only for Lua 5.1 chunks, not '{0}'")]
    UnsupportedDialect(String),
    #[error("prototype and disassembly child counts differ at {proto_id}")]
    ChildCountMismatch { proto_id: StableId },
    #[error("constant {constant_index} in {proto_id} has invalid raw hex: {message}")]
    InvalidConstantEncoding {
        proto_id: StableId,
        constant_index: usize,
        message: String,
    },
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn tagged(&mut self, tag: u8) {
        self.bytes.push(tag);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    fn raw_digest(&mut self, value: &[u8; 32]) {
        self.bytes.extend_from_slice(value);
    }
}

struct TreeIdentity {
    raw_digest: [u8; 32],
    facts: Vec<PrototypeIdentityFact>,
}

/// Compute one v1 subtree-content identity for every prototype in structural order.
pub fn analyze_chunk_prototype_identities_v1(
    chunk: &Chunk,
) -> Result<ChunkPrototypeIdentityAnalysis, PrototypeIdentityError> {
    if !matches!(
        chunk.dialect.as_str(),
        "lua5.1" | "lua5.1-stock32" | "lua5.1-lnum32"
    ) {
        return Err(PrototypeIdentityError::UnsupportedDialect(
            chunk.dialect.clone(),
        ));
    }

    let disassembly = luad_dialect_lua51::disassemble_proto_lua51_v1(&chunk.main_proto);
    let tree = encode_tree(
        &chunk.main_proto,
        &disassembly,
        PROTOTYPE_IDENTITY_SCHEME_V1,
        DOMAIN_V1,
    )?;
    Ok(ChunkPrototypeIdentityAnalysis {
        prototypes: tree.facts,
    })
}

/// Compute one v2 subtree-content identity for every prototype in structural order.
pub fn analyze_chunk_prototype_identities(
    chunk: &Chunk,
) -> Result<ChunkPrototypeIdentityAnalysis, PrototypeIdentityError> {
    if !matches!(
        chunk.dialect.as_str(),
        "lua5.1" | "lua5.1-stock32" | "lua5.1-lnum32"
    ) {
        return Err(PrototypeIdentityError::UnsupportedDialect(
            chunk.dialect.clone(),
        ));
    }

    let disassembly = luad_dialect_lua51::disassemble_proto_lua51(&chunk.main_proto);
    let tree = encode_tree(
        &chunk.main_proto,
        &disassembly,
        PROTOTYPE_IDENTITY_SCHEME_V2,
        DOMAIN_V2,
    )?;
    Ok(ChunkPrototypeIdentityAnalysis {
        prototypes: tree.facts,
    })
}

fn encode_tree(
    proto: &Prototype,
    disassembly: &DisassembledPrototype,
    scheme: &str,
    domain: &[u8],
) -> Result<TreeIdentity, PrototypeIdentityError> {
    if proto.protos.len() != disassembly.child_protos.len() {
        return Err(PrototypeIdentityError::ChildCountMismatch {
            proto_id: proto.id.clone(),
        });
    }

    let children = proto
        .protos
        .iter()
        .zip(&disassembly.child_protos)
        .map(|(child, child_disassembly)| encode_tree(child, child_disassembly, scheme, domain))
        .collect::<Result<Vec<_>, _>>()?;

    let mut encoder = Encoder::default();
    encoder.bytes.extend_from_slice(domain);
    encoder.tagged(TAG_RECORD_PROTOTYPE);
    encoder.bytes(b"lua5.1");
    encoder.u8(proto.numparams);
    encoder.u8(proto.is_vararg);
    encoder.u8(proto.maxstacksize);

    encoder.u64(disassembly.instructions.len() as u64);
    for instruction in &disassembly.instructions {
        encode_instruction(&mut encoder, instruction);
    }

    encoder.u64(proto.constants.len() as u64);
    for constant in &proto.constants {
        encode_constant(&mut encoder, &proto.id, constant.index, &constant.value)?;
    }

    encoder.u64(proto.upvalues.len() as u64);
    encoder.u64(children.len() as u64);
    for child in &children {
        encoder.tagged(TAG_RECORD_CHILD_DIGEST);
        encoder.raw_digest(&child.raw_digest);
    }

    let raw_digest: [u8; 32] = Sha256::digest(&encoder.bytes).into();
    let fact = PrototypeIdentityFact {
        proto_id: proto.id.clone(),
        scheme: scheme.to_string(),
        digest: format!("sha256:{}", hex::encode(raw_digest)),
    };
    let mut facts = Vec::with_capacity(
        1 + children
            .iter()
            .map(|child| child.facts.len())
            .sum::<usize>(),
    );
    facts.push(fact);
    for child in children {
        facts.extend(child.facts);
    }

    Ok(TreeIdentity { raw_digest, facts })
}

fn encode_instruction(encoder: &mut Encoder, instruction: &DisassembledInstruction) {
    encoder.tagged(TAG_RECORD_INSTRUCTION);
    encoder.bytes(instruction.role.as_bytes());
    encoder.bytes(instruction.mnemonic.as_bytes());
    encoder.u64(instruction.operands.len() as u64);
    for operand in &instruction.operands {
        encoder.tagged(TAG_RECORD_OPERAND);
        match operand.kind {
            OperandKind::Register { index } => {
                encoder.tagged(TAG_OPERAND_REGISTER);
                encoder.u8(index);
            }
            OperandKind::ImmediateUnsigned { value } => {
                encoder.tagged(TAG_OPERAND_IMMEDIATE_UNSIGNED);
                encoder.u64(value);
            }
            OperandKind::ImmediateSigned { value } => {
                encoder.tagged(TAG_OPERAND_IMMEDIATE_SIGNED);
                encoder.i64(value);
            }
            OperandKind::Flag { value } => {
                encoder.tagged(TAG_OPERAND_FLAG);
                encoder.u8(value);
            }
            OperandKind::Raw { value } => {
                encoder.tagged(TAG_OPERAND_RAW);
                encoder.u64(value);
            }
        }
        match &operand.resolved {
            None => encoder.tagged(TAG_RESOLUTION_NONE),
            Some(ResolvedFact::Constant { index, .. }) => {
                encoder.tagged(TAG_RESOLUTION_CONSTANT);
                encoder.u64(*index as u64);
            }
            Some(ResolvedFact::Upvalue { index, .. }) => {
                encoder.tagged(TAG_RESOLUTION_UPVALUE);
                encoder.u8(*index);
            }
            Some(ResolvedFact::Local { index, .. }) => {
                encoder.tagged(TAG_RESOLUTION_LOCAL);
                encoder.u64(*index as u64);
            }
            Some(ResolvedFact::Prototype { index, .. }) => {
                encoder.tagged(TAG_RESOLUTION_PROTOTYPE);
                encoder.u64(*index as u64);
            }
            Some(ResolvedFact::JumpTarget { target_pc, .. }) => {
                encoder.tagged(TAG_RESOLUTION_JUMP_TARGET);
                encoder.u64(*target_pc as u64);
            }
            Some(ResolvedFact::Metamethod { name }) => {
                encoder.tagged(TAG_RESOLUTION_METAMETHOD);
                encoder.bytes(name.as_bytes());
            }
        }
    }
}

fn encode_constant(
    encoder: &mut Encoder,
    proto_id: &StableId,
    constant_index: usize,
    value: &ConstantValue,
) -> Result<(), PrototypeIdentityError> {
    match value {
        ConstantValue::Nil => encoder.tagged(TAG_CONST_NIL),
        ConstantValue::Boolean(value) => {
            encoder.tagged(TAG_CONST_BOOL);
            encoder.u8(u8::from(*value));
        }
        ConstantValue::Integer { raw_hex, .. } => {
            encoder.tagged(TAG_CONST_INT);
            encoder.bytes(&decode_constant_hex(proto_id, constant_index, raw_hex)?);
        }
        ConstantValue::Float { raw_hex, .. } => {
            encoder.tagged(TAG_CONST_FLOAT);
            encoder.bytes(&decode_constant_hex(proto_id, constant_index, raw_hex)?);
        }
        ConstantValue::ShortString(value) => {
            encoder.tagged(TAG_CONST_SHORT_STRING);
            encoder.bytes(&value.raw_bytes);
        }
        ConstantValue::LongString(value) => {
            encoder.tagged(TAG_CONST_LONG_STRING);
            encoder.bytes(&value.raw_bytes);
        }
    }
    Ok(())
}

fn decode_constant_hex(
    proto_id: &StableId,
    constant_index: usize,
    raw_hex: &str,
) -> Result<Vec<u8>, PrototypeIdentityError> {
    hex::decode(raw_hex).map_err(|error| PrototypeIdentityError::InvalidConstantEncoding {
        proto_id: proto_id.clone(),
        constant_index,
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use luad_core::model::Prototype;
    use luad_core::{ProtoPath, SourceLocation, StableId};
    use sha2::{Digest, Sha256};

    use super::{
        encode_tree, DOMAIN_V1, DOMAIN_V2, PROTOTYPE_IDENTITY_SCHEME_V1,
        PROTOTYPE_IDENTITY_SCHEME_V2,
    };

    #[test]
    fn empty_prototype_matches_normative_preimage_vector() {
        let path = ProtoPath::root();
        let prototype = Prototype {
            id: StableId::proto(path.clone()),
            path,
            source_name: None,
            line_defined: 0,
            last_line_defined: 0,
            numparams: 0,
            is_vararg: 0,
            maxstacksize: 2,
            instructions: vec![],
            constants: vec![],
            upvalues: vec![],
            protos: vec![],
            line_info: vec![],
            abs_line_info: vec![],
            loc_vars: vec![],
            upvalue_names: vec![],
            source: SourceLocation::new(0, &[]),
        };
        let disassembly = luad_core::DisassembledPrototype {
            id: prototype.id.clone(),
            source_name: None,
            line_defined: 0,
            last_line_defined: 0,
            numparams: 0,
            is_vararg: false,
            maxstacksize: 2,
            instructions: vec![],
            diagnostics: vec![],
            child_protos: vec![],
        };
        let normative_preimage = hex::decode(concat!(
            "6c7561642d70726f746f747970652d763100",
            "01",
            "0000000000000006",
            "6c7561352e31",
            "000002",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
        ))
        .expect("normative hex vector");
        assert_eq!(normative_preimage.len(), 68);
        assert_eq!(
            hex::encode(Sha256::digest(&normative_preimage)),
            "b5568c02c95499f55261b286ab13e7f86b2beab5b113ee15c7d0d47dbecfea50"
        );

        let identity = encode_tree(
            &prototype,
            &disassembly,
            PROTOTYPE_IDENTITY_SCHEME_V1,
            DOMAIN_V1,
        )
        .expect("identity");
        assert_eq!(
            identity.facts[0].digest,
            "sha256:b5568c02c95499f55261b286ab13e7f86b2beab5b113ee15c7d0d47dbecfea50"
        );
    }

    #[test]
    fn empty_prototype_matches_normative_v2_preimage_vector() {
        let path = ProtoPath::root();
        let prototype = Prototype {
            id: StableId::proto(path.clone()),
            path,
            source_name: None,
            line_defined: 0,
            last_line_defined: 0,
            numparams: 0,
            is_vararg: 0,
            maxstacksize: 2,
            instructions: vec![],
            constants: vec![],
            upvalues: vec![],
            protos: vec![],
            line_info: vec![],
            abs_line_info: vec![],
            loc_vars: vec![],
            upvalue_names: vec![],
            source: SourceLocation::new(0, &[]),
        };
        let disassembly = luad_core::DisassembledPrototype {
            id: prototype.id.clone(),
            source_name: None,
            line_defined: 0,
            last_line_defined: 0,
            numparams: 0,
            is_vararg: false,
            maxstacksize: 2,
            instructions: vec![],
            diagnostics: vec![],
            child_protos: vec![],
        };
        let normative_preimage = hex::decode(concat!(
            "6c7561642d70726f746f747970652d763200",
            "01",
            "0000000000000006",
            "6c7561352e31",
            "000002",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
        ))
        .expect("normative hex vector");
        assert_eq!(normative_preimage.len(), 68);
        assert_eq!(
            hex::encode(Sha256::digest(&normative_preimage)),
            "a4f418350f217b5477b6dc79e956e7b7b8ba248466fd720955d8324c0f0b0573"
        );

        let identity = encode_tree(
            &prototype,
            &disassembly,
            PROTOTYPE_IDENTITY_SCHEME_V2,
            DOMAIN_V2,
        )
        .expect("identity");
        assert_eq!(
            identity.facts[0].digest,
            "sha256:a4f418350f217b5477b6dc79e956e7b7b8ba248466fd720955d8324c0f0b0573"
        );
    }
}
