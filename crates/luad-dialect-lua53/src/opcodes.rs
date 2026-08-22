//! Lua 5.3 opcode definitions and raw instruction decoder.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const BITRK_53: u32 = 1 << 8; // 256

/// All 47 official Lua 5.3 opcodes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum Opcode53 {
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
    Mod = 16,
    Pow = 17,
    Div = 18,
    IDiv = 19,
    BAnd = 20,
    BOr = 21,
    BXor = 22,
    Shl = 23,
    Shr = 24,
    Unm = 25,
    BNot = 26,
    Not = 27,
    Len = 28,
    Concat = 29,
    Jmp = 30,
    Eq = 31,
    Lt = 32,
    Le = 33,
    Test = 34,
    TestSet = 35,
    Call = 36,
    TailCall = 37,
    Return = 38,
    ForLoop = 39,
    ForPrep = 40,
    TForCall = 41,
    TForLoop = 42,
    SetList = 43,
    Closure = 44,
    VarArg = 45,
    ExtraArg = 46,
}

impl Opcode53 {
    /// Safe construction of Lua 5.3 opcode without unsafe code.
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
            16 => Some(Self::Mod),
            17 => Some(Self::Pow),
            18 => Some(Self::Div),
            19 => Some(Self::IDiv),
            20 => Some(Self::BAnd),
            21 => Some(Self::BOr),
            22 => Some(Self::BXor),
            23 => Some(Self::Shl),
            24 => Some(Self::Shr),
            25 => Some(Self::Unm),
            26 => Some(Self::BNot),
            27 => Some(Self::Not),
            28 => Some(Self::Len),
            29 => Some(Self::Concat),
            30 => Some(Self::Jmp),
            31 => Some(Self::Eq),
            32 => Some(Self::Lt),
            33 => Some(Self::Le),
            34 => Some(Self::Test),
            35 => Some(Self::TestSet),
            36 => Some(Self::Call),
            37 => Some(Self::TailCall),
            38 => Some(Self::Return),
            39 => Some(Self::ForLoop),
            40 => Some(Self::ForPrep),
            41 => Some(Self::TForCall),
            42 => Some(Self::TForLoop),
            43 => Some(Self::SetList),
            44 => Some(Self::Closure),
            45 => Some(Self::VarArg),
            46 => Some(Self::ExtraArg),
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
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Div => "DIV",
            Self::IDiv => "IDIV",
            Self::BAnd => "BAND",
            Self::BOr => "BOR",
            Self::BXor => "BXOR",
            Self::Shl => "SHL",
            Self::Shr => "SHR",
            Self::Unm => "UNM",
            Self::BNot => "BNOT",
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
    pub fn mode(self) -> OpMode53 {
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
            | Self::Mod
            | Self::Pow
            | Self::Div
            | Self::IDiv
            | Self::BAnd
            | Self::BOr
            | Self::BXor
            | Self::Shl
            | Self::Shr
            | Self::Unm
            | Self::BNot
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
            | Self::VarArg => OpMode53::IABC,
            Self::LoadK | Self::Closure => OpMode53::IABx,
            Self::Jmp | Self::ForLoop | Self::ForPrep | Self::TForLoop => OpMode53::IAsBx,
            Self::LoadKx | Self::ExtraArg => OpMode53::IAx,
        }
    }
}

/// Lua 5.3 instruction format modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OpMode53 {
    IABC,
    IABx,
    IAsBx,
    IAx,
}

/// Decoded raw bitfields from a 32-bit Lua 5.3 instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawInstruction53 {
    pub raw: u32,
    pub opcode_num: u8,
    pub opcode: Option<Opcode53>,
    pub a: u8,
    pub b: u16,
    pub c: u16,
    pub bx: u32,
    pub sbx: i32,
    pub ax: u32,
}

impl RawInstruction53 {
    pub const OFFSET_SBX: i32 = 131071;

    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let opcode_num = (raw & 0x3f) as u8;
        let opcode = Opcode53::from_u8(opcode_num);
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
    pub fn encode_iabc(opcode: Opcode53, a: u8, b: u16, c: u16) -> u32 {
        ((opcode as u32) & 0x3F)
            | (((a as u32) & 0xFF) << 6)
            | (((c as u32) & 0x1FF) << 14)
            | (((b as u32) & 0x1FF) << 23)
    }

    #[must_use]
    pub fn encode_iabx(opcode: Opcode53, a: u8, bx: u32) -> u32 {
        ((opcode as u32) & 0x3F) | (((a as u32) & 0xFF) << 6) | ((bx & 0x3FFFF) << 14)
    }

    #[must_use]
    pub fn encode_iasbx(opcode: Opcode53, a: u8, sbx: i32) -> u32 {
        let bx = (sbx + Self::OFFSET_SBX) as u32;
        Self::encode_iabx(opcode, a, bx)
    }

    #[must_use]
    pub fn encode_iax(opcode: Opcode53, ax: u32) -> u32 {
        ((opcode as u32) & 0x3F) | ((ax & 0x3FFFFFF) << 6)
    }

    #[must_use]
    pub fn encode(self) -> Option<u32> {
        let op = self.opcode?;
        let word = match op.mode() {
            OpMode53::IABC => Self::encode_iabc(op, self.a, self.b, self.c),
            OpMode53::IABx => Self::encode_iabx(op, self.a, self.bx),
            OpMode53::IAsBx => Self::encode_iasbx(op, self.a, self.sbx),
            OpMode53::IAx => Self::encode_iax(op, self.ax),
        };
        Some(word)
    }

    #[must_use]
    pub fn is_b_k(&self) -> bool {
        (self.b as u32 & BITRK_53) != 0
    }

    #[must_use]
    pub fn is_c_k(&self) -> bool {
        (self.c as u32 & BITRK_53) != 0
    }

    #[must_use]
    pub fn b_index_k(&self) -> usize {
        (self.b as u32 & !BITRK_53) as usize
    }

    #[must_use]
    pub fn c_index_k(&self) -> usize {
        (self.c as u32 & !BITRK_53) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_47_opcodes_from_u8() {
        for op in 0..=46 {
            let opcode = Opcode53::from_u8(op);
            assert!(opcode.is_some(), "Opcode {op} must be recognized");
            assert_eq!(opcode.unwrap() as u8, op);
        }
        assert!(Opcode53::from_u8(47).is_none());
    }

    #[test]
    fn test_round_trip_property_all_opmodes() {
        for op in [Opcode53::Move, Opcode53::Add, Opcode53::Eq] {
            let word = RawInstruction53::encode_iabc(op, 42, 100, 200);
            let decoded = RawInstruction53::decode(word);
            assert_eq!(decoded.opcode, Some(op));
            assert_eq!(decoded.encode(), Some(word));
        }

        let word_bx = RawInstruction53::encode_iabx(Opcode53::LoadK, 5, 12345);
        let dec_bx = RawInstruction53::decode(word_bx);
        assert_eq!(dec_bx.opcode, Some(Opcode53::LoadK));
        assert_eq!(dec_bx.bx, 12345);
        assert_eq!(dec_bx.encode(), Some(word_bx));

        let word_sbx = RawInstruction53::encode_iasbx(Opcode53::Jmp, 0, -500);
        let dec_sbx = RawInstruction53::decode(word_sbx);
        assert_eq!(dec_sbx.opcode, Some(Opcode53::Jmp));
        assert_eq!(dec_sbx.sbx, -500);
        assert_eq!(dec_sbx.encode(), Some(word_sbx));

        let word_ax = RawInstruction53::encode_iax(Opcode53::ExtraArg, 654321);
        let dec_ax = RawInstruction53::decode(word_ax);
        assert_eq!(dec_ax.opcode, Some(Opcode53::ExtraArg));
        assert_eq!(dec_ax.ax, 654321);
        assert_eq!(dec_ax.encode(), Some(word_ax));
    }
}
