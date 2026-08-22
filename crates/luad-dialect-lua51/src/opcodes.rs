//! Lua 5.1 opcode definitions and bitfield decoder.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const BITRK_51: u32 = 1 << 8; // 256

/// All 38 official Lua 5.1 opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[repr(u8)]
pub enum Opcode51 {
    Move = 0,
    LoadK = 1,
    LoadBool = 2,
    LoadNil = 3,
    GetUpval = 4,
    GetGlobal = 5,
    GetTable = 6,
    SetGlobal = 7,
    SetUpval = 8,
    SetTable = 9,
    NewTable = 10,
    SelfOp = 11,
    Add = 12,
    Sub = 13,
    Mul = 14,
    Div = 15,
    Mod = 16,
    Pow = 17,
    Unm = 18,
    Not = 19,
    Len = 20,
    Concat = 21,
    Jmp = 22,
    Eq = 23,
    Lt = 24,
    Le = 25,
    Test = 26,
    TestSet = 27,
    Call = 28,
    TailCall = 29,
    Return = 30,
    ForLoop = 31,
    ForPrep = 32,
    TForLoop = 33,
    SetList = 34,
    Close = 35,
    Closure = 36,
    VarArg = 37,
}

impl Opcode51 {
    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        if val <= 37 {
            Some(unsafe { std::mem::transmute::<u8, Opcode51>(val) })
        } else {
            None
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::LoadK => "LOADK",
            Self::LoadBool => "LOADBOOL",
            Self::LoadNil => "LOADNIL",
            Self::GetUpval => "GETUPVAL",
            Self::GetGlobal => "GETGLOBAL",
            Self::GetTable => "GETTABLE",
            Self::SetGlobal => "SETGLOBAL",
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
            Self::TForLoop => "TFORLOOP",
            Self::SetList => "SETLIST",
            Self::Close => "CLOSE",
            Self::Closure => "CLOSURE",
            Self::VarArg => "VARARG",
        }
    }

    #[must_use]
    pub fn mode(self) -> OpMode51 {
        match self {
            Self::Move
            | Self::LoadBool
            | Self::LoadNil
            | Self::GetUpval
            | Self::GetTable
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
            | Self::TForLoop
            | Self::SetList
            | Self::Close
            | Self::VarArg => OpMode51::IABC,
            Self::LoadK | Self::GetGlobal | Self::SetGlobal | Self::Closure => OpMode51::IABx,
            Self::Jmp | Self::ForLoop | Self::ForPrep => OpMode51::IAsBx,
        }
    }
}

/// Lua 5.1 instruction format modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpMode51 {
    IABC,
    IABx,
    IAsBx,
}

/// Decoded raw bitfields from a 32-bit Lua 5.1 instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawInstruction51 {
    pub opcode_num: u8,
    pub opcode: Option<Opcode51>,
    pub a: u8,
    pub b: u16,
    pub c: u16,
    pub bx: u32,
    pub sbx: i32,
}

impl RawInstruction51 {
    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let opcode_num = (raw & 0x3f) as u8;
        let opcode = Opcode51::from_u8(opcode_num);
        let a = ((raw >> 6) & 0xff) as u8;
        let c = ((raw >> 14) & 0x1ff) as u16;
        let b = ((raw >> 23) & 0x1ff) as u16;
        let bx = (raw >> 14) & 0x3ffff;
        let sbx = (bx as i32) - 131071;

        Self {
            opcode_num,
            opcode,
            a,
            b,
            c,
            bx,
            sbx,
        }
    }

    #[must_use]
    pub fn is_b_k(&self) -> bool {
        (self.b as u32 & BITRK_51) != 0
    }

    #[must_use]
    pub fn is_c_k(&self) -> bool {
        (self.c as u32 & BITRK_51) != 0
    }

    #[must_use]
    pub fn b_index_k(&self) -> usize {
        (self.b as u32 & !BITRK_51) as usize
    }

    #[must_use]
    pub fn c_index_k(&self) -> usize {
        (self.c as u32 & !BITRK_51) as usize
    }
}
