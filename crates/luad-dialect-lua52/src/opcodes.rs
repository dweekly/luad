//! Lua 5.2 opcode definitions and bitfield decoder.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const BITRK_52: u32 = 1 << 8; // 256

/// All 40 official Lua 5.2 opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        if val <= 39 {
            Some(unsafe { std::mem::transmute::<u8, Opcode52>(val) })
        } else {
            None
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpMode52 {
    IABC,
    IABx,
    IAsBx,
    IAx,
}

/// Decoded raw bitfields from a 32-bit Lua 5.2 instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawInstruction52 {
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
    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let opcode_num = (raw & 0x3f) as u8;
        let opcode = Opcode52::from_u8(opcode_num);
        let a = ((raw >> 6) & 0xff) as u8;
        let c = ((raw >> 14) & 0x1ff) as u16;
        let b = ((raw >> 23) & 0x1ff) as u16;
        let bx = (raw >> 14) & 0x3ffff;
        let sbx = (bx as i32) - 131071;
        let ax = (raw >> 6) & 0x3ffffff;

        Self {
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
