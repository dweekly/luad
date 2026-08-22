//! Lua 5.2 opcode definitions and bitfield decoder.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const BITRK_52: u32 = 1 << 8; // 256

/// All 40 official Lua 5.2 opcodes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum Opcode52 {
    Move = 0,
    LoadK = 1,
    LoadKx = 2,
    LoadBool = 3,
    LoadNil = 4,
    GetUpval = 5,
    GetTabUp = 6,
    GetTable = 7,
    SetTabUp = 8,
    SetUpval = 9,
    SetTable = 10,
    NewTable = 11,
    SelfOp = 12,
    Add = 13,
    Sub = 14,
    Mul = 15,
    Div = 16,
    Mod = 17,
    Pow = 18,
    Unm = 19,
    Not = 20,
    Len = 21,
    Concat = 22,
    Jmp = 23,
    Eq = 24,
    Lt = 25,
    Le = 26,
    Test = 27,
    TestSet = 28,
    Call = 29,
    TailCall = 30,
    Return = 31,
    ForLoop = 32,
    ForPrep = 33,
    TForCall = 34,
    TForLoop = 35,
    SetList = 36,
    Closure = 37,
    VarArg = 38,
    ExtraArg = 39,
}

impl Opcode52 {
    /// Safe construction of Lua 5.2 opcode without unsafe code.
    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Move),
            1 => Some(Self::LoadK),
            2 => Some(Self::LoadKx),
            3 => Some(Self::LoadBool),
            4 => Some(Self::LoadNil),
            5 => Some(Self::GetUpval),
            6 => Some(Self::GetTabUp),
            7 => Some(Self::GetTable),
            8 => Some(Self::SetTabUp),
            9 => Some(Self::SetUpval),
            10 => Some(Self::SetTable),
            11 => Some(Self::NewTable),
            12 => Some(Self::SelfOp),
            13 => Some(Self::Add),
            14 => Some(Self::Sub),
            15 => Some(Self::Mul),
            16 => Some(Self::Div),
            17 => Some(Self::Mod),
            18 => Some(Self::Pow),
            19 => Some(Self::Unm),
            20 => Some(Self::Not),
            21 => Some(Self::Len),
            22 => Some(Self::Concat),
            23 => Some(Self::Jmp),
            24 => Some(Self::Eq),
            25 => Some(Self::Lt),
            26 => Some(Self::Le),
            27 => Some(Self::Test),
            28 => Some(Self::TestSet),
            29 => Some(Self::Call),
            30 => Some(Self::TailCall),
            31 => Some(Self::Return),
            32 => Some(Self::ForLoop),
            33 => Some(Self::ForPrep),
            34 => Some(Self::TForCall),
            35 => Some(Self::TForLoop),
            36 => Some(Self::SetList),
            37 => Some(Self::Closure),
            38 => Some(Self::VarArg),
            39 => Some(Self::ExtraArg),
            _ => None,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::LoadK => "LOADK",
            Self::LoadKx => "LOADKX",
            Self::LoadBool => "LOADBOOL",
            Self::LoadNil => "LOADNIL",
            Self::GetUpval => "GETUPVAL",
            Self::GetTabUp => "GETTABUP",
            Self::GetTable => "GETTABLE",
            Self::SetTabUp => "SETTABUP",
            Self::SetUpval => "SETUPVAL",
            Self::SetTable => "SETTABLE",
            Self::NewTable => "NEWTABLE",
            Self::SelfOp => "SELF",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Unm => "UNM",
            Self::Not => "NOT",
            Self::Len => "LEN",
            Self::Concat => "CONCAT",
            Self::Jmp => "JMP",
            Self::Eq => "EQ",
            Self::Lt => "LT",
            Self::Le => "LE",
            Self::Test => "TEST",
            Self::TestSet => "TESTSET",
            Self::Call => "CALL",
            Self::TailCall => "TAILCALL",
            Self::Return => "RETURN",
            Self::ForLoop => "FORLOOP",
            Self::ForPrep => "FORPREP",
            Self::TForCall => "TFORCALL",
            Self::TForLoop => "TFORLOOP",
            Self::SetList => "SETLIST",
            Self::Closure => "CLOSURE",
            Self::VarArg => "VARARG",
            Self::ExtraArg => "EXTRAARG",
        }
    }

    #[must_use]
    pub fn mode(self) -> OpMode52 {
        match self {
            Self::Move
            | Self::LoadBool
            | Self::LoadNil
            | Self::GetUpval
            | Self::GetTabUp
            | Self::GetTable
            | Self::SetTabUp
            | Self::SetUpval
            | Self::SetTable
            | Self::NewTable
            | Self::SelfOp
            | Self::Add
            | Self::Sub
            | Self::Mul
            | Self::Div
            | Self::Mod
            | Self::Pow
            | Self::Unm
            | Self::Not
            | Self::Len
            | Self::Concat
            | Self::Eq
            | Self::Lt
            | Self::Le
            | Self::Test
            | Self::TestSet
            | Self::Call
            | Self::TailCall
            | Self::Return
            | Self::TForCall
            | Self::SetList
            | Self::VarArg => OpMode52::IABC,
            Self::LoadK | Self::Closure => OpMode52::IABx,
            Self::Jmp | Self::ForLoop | Self::ForPrep | Self::TForLoop => OpMode52::IAsBx,
            Self::LoadKx | Self::ExtraArg => OpMode52::IAx,
        }
    }
}

/// Lua 5.2 instruction format modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OpMode52 {
    IABC,
    IABx,
    IAsBx,
    IAx,
}

/// Decoded raw bitfields from a 32-bit Lua 5.2 instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawInstruction52 {
    pub raw: u32,
    pub opcode_num: u8,
    pub opcode: Option<Opcode52>,
    pub a: u8,
    pub b: u16,
    pub c: u16,
    pub bx: u32,
    pub sbx: i32,
    pub ax: u32,
}

impl RawInstruction52 {
    pub const OFFSET_SBX: i32 = 131071;

    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let opcode_num = (raw & 0x3f) as u8;
        let opcode = Opcode52::from_u8(opcode_num);
        let a = ((raw >> 6) & 0xff) as u8;
        let c = ((raw >> 14) & 0x1ff) as u16;
        let b = ((raw >> 23) & 0x1ff) as u16;
        let bx = (raw >> 14) & 0x3ffff;
        let sbx = (bx as i32) - Self::OFFSET_SBX;
        let ax = (raw >> 6) & 0x3ffffff;

        Self {
            raw,
            opcode_num,
            opcode,
            a,
            b,
            c,
            bx,
            sbx,
            ax,
        }
    }

    #[must_use]
    pub fn encode_iabc(opcode: Opcode52, a: u8, b: u16, c: u16) -> u32 {
        ((opcode as u32) & 0x3F)
            | (((a as u32) & 0xFF) << 6)
            | (((c as u32) & 0x1FF) << 14)
            | (((b as u32) & 0x1FF) << 23)
    }

    #[must_use]
    pub fn encode_iabx(opcode: Opcode52, a: u8, bx: u32) -> u32 {
        ((opcode as u32) & 0x3F) | (((a as u32) & 0xFF) << 6) | ((bx & 0x3FFFF) << 14)
    }

    #[must_use]
    pub fn encode_iasbx(opcode: Opcode52, a: u8, sbx: i32) -> u32 {
        let bx = (sbx + Self::OFFSET_SBX) as u32;
        Self::encode_iabx(opcode, a, bx)
    }

    #[must_use]
    pub fn encode_iax(opcode: Opcode52, ax: u32) -> u32 {
        ((opcode as u32) & 0x3F) | ((ax & 0x3FFFFFF) << 6)
    }

    #[must_use]
    pub fn encode(self) -> Option<u32> {
        let op = self.opcode?;
        let word = match op.mode() {
            OpMode52::IABC => Self::encode_iabc(op, self.a, self.b, self.c),
            OpMode52::IABx => Self::encode_iabx(op, self.a, self.bx),
            OpMode52::IAsBx => Self::encode_iasbx(op, self.a, self.sbx),
            OpMode52::IAx => Self::encode_iax(op, self.ax),
        };
        Some(word)
    }

    #[must_use]
    pub fn is_b_k(&self) -> bool {
        (self.b as u32 & BITRK_52) != 0
    }

    #[must_use]
    pub fn is_c_k(&self) -> bool {
        (self.c as u32 & BITRK_52) != 0
    }

    #[must_use]
    pub fn b_index_k(&self) -> usize {
        (self.b as u32 & !BITRK_52) as usize
    }

    #[must_use]
    pub fn c_index_k(&self) -> usize {
        (self.c as u32 & !BITRK_52) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_40_opcodes_from_u8() {
        for op in 0..=39 {
            let opcode = Opcode52::from_u8(op);
            assert!(opcode.is_some(), "Opcode {op} must be recognized");
            assert_eq!(opcode.unwrap() as u8, op);
        }
        assert!(Opcode52::from_u8(40).is_none());
    }

    #[test]
    fn test_round_trip_property_all_opmodes() {
        for op in [Opcode52::Move, Opcode52::Add, Opcode52::Eq] {
            let word = RawInstruction52::encode_iabc(op, 42, 100, 200);
            let decoded = RawInstruction52::decode(word);
            assert_eq!(decoded.opcode, Some(op));
            assert_eq!(decoded.encode(), Some(word));
        }

        let word_bx = RawInstruction52::encode_iabx(Opcode52::LoadK, 5, 12345);
        let dec_bx = RawInstruction52::decode(word_bx);
        assert_eq!(dec_bx.opcode, Some(Opcode52::LoadK));
        assert_eq!(dec_bx.bx, 12345);
        assert_eq!(dec_bx.encode(), Some(word_bx));

        let word_sbx = RawInstruction52::encode_iasbx(Opcode52::Jmp, 0, -500);
        let dec_sbx = RawInstruction52::decode(word_sbx);
        assert_eq!(dec_sbx.opcode, Some(Opcode52::Jmp));
        assert_eq!(dec_sbx.sbx, -500);
        assert_eq!(dec_sbx.encode(), Some(word_sbx));

        let word_ax = RawInstruction52::encode_iax(Opcode52::ExtraArg, 654321);
        let dec_ax = RawInstruction52::decode(word_ax);
        assert_eq!(dec_ax.opcode, Some(Opcode52::ExtraArg));
        assert_eq!(dec_ax.ax, 654321);
        assert_eq!(dec_ax.encode(), Some(word_ax));
    }
}
