//! Lua 5.3 opcode definitions and raw instruction decoder.

use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

pub const BITRK_53: u32 = 1 << 8; // 256

/// All 47 official Lua 5.3 opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        if val <= 46 {
            Some(unsafe { std::mem::transmute(val) })
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
            Self::Move | Self::LoadBool | Self::LoadNil | Self::GetUpval | Self::GetTabUp
            | Self::GetTable | Self::SetTabUp | Self::SetUpval | Self::SetTable | Self::NewTable
            | Self::SelfOp | Self::Add | Self::Sub | Self::Mul | Self::Mod | Self::Pow
            | Self::Div | Self::IDiv | Self::BAnd | Self::BOr | Self::BXor | Self::Shl
            | Self::Shr | Self::Unm | Self::BNot | Self::Not | Self::Len | Self::Concat
            | Self::Eq | Self::Lt | Self::Le | Self::Test | Self::TestSet | Self::Call
            | Self::TailCall | Self::Return | Self::TForCall | Self::SetList | Self::VarArg => {
                OpMode53::IABC
            }
            Self::LoadK | Self::Closure => OpMode53::IABx,
            Self::Jmp | Self::ForLoop | Self::ForPrep | Self::TForLoop => OpMode53::IAsBx,
            Self::LoadKx | Self::ExtraArg => OpMode53::IAx,
        }
    }
}

/// Lua 5.3 instruction format modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpMode53 {
    IABC,
    IABx,
    IAsBx,
    IAx,
}

/// Decoded raw bitfields from a 32-bit Lua 5.3 instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawInstruction53 {
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
    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let opcode_num = (raw & 0x3f) as u8;
        let opcode = Opcode53::from_u8(opcode_num);
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
